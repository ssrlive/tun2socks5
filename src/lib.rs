use crate::{
    args::ProxyType,
    directions::{IncomingDataEvent, IncomingDirection, OutgoingDirection},
    http::HttpManager,
    session_info::{IpProtocol, SessionInfo},
};
use proxy_handler::{ConnectionManager, ProxyHandler};
use socks::SocksProxyManager;
use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    sync::Arc,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::{
        mpsc::{self, Receiver, Sender},
        Mutex,
    },
};
use tproxy_config::is_private_ip;
use udp_stream::UdpStream;
pub use {
    args::Args,
    error::{Error, Result},
};

mod args;
mod directions;
mod dns;
mod error;
mod http;
mod proxy_handler;
mod session_info;
mod socks;

const DNS_PORT: u16 = 53;

static TASK_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
use std::sync::atomic::Ordering::Relaxed;

pub async fn main_entry(device: tun::AsyncDevice, args: Args, mut quit: Receiver<()>) -> crate::Result<()> {
    let server_addr = args.proxy.addr;
    let key = args.proxy.credentials.clone();

    use socks5_impl::protocol::Version::{V4, V5};
    let mgr = match args.proxy.proxy_type {
        ProxyType::Socks5 => Arc::new(SocksProxyManager::new(server_addr, V5, key)) as Arc<dyn ConnectionManager>,
        ProxyType::Socks4 => Arc::new(SocksProxyManager::new(server_addr, V4, key)) as Arc<dyn ConnectionManager>,
        ProxyType::Http => Arc::new(HttpManager::new(server_addr, key)) as Arc<dyn ConnectionManager>,
    };

    use futures::{SinkExt, StreamExt};

    let (stack, mut tcp_listener, udp_socket) = ::lwip::NetStack::new()?;
    let (mut stack_sink, mut stack_stream) = stack.split();

    // tun device is assumed implementing `Stream` and `Sink`
    let framed = device.into_framed();
    let (mut tun_sink, mut tun_stream) = framed.split();

    // Reads packet from stack and sends to TUN.
    tokio::spawn(async move {
        while let Some(pkt) = stack_stream.next().await {
            if let Ok(pkt) = pkt {
                tun_sink.send(tun::TunPacket::new(pkt)).await.unwrap();
            }
        }
    });

    // Reads packet from TUN and sends to stack.
    tokio::spawn(async move {
        while let Some(pkt) = tun_stream.next().await {
            if let Ok(pkt) = pkt {
                stack_sink.send(pkt.into_bytes().into()).await.unwrap();
            }
        }
    });

    // Extracts TCP connections from stack and sends them to the dispatcher.
    let mgr1: Arc<dyn ConnectionManager> = mgr.clone();
    tokio::spawn(async move {
        while let Some((stream, local_addr, remote_addr)) = tcp_listener.next().await {
            tokio::spawn(handle_inbound_stream(stream, local_addr, remote_addr, mgr1.clone(), server_addr));
        }
    });

    // Receive and send UDP packets between netstack and NAT manager. The NAT
    // manager would maintain UDP sessions and send them to the dispatcher.
    tokio::spawn(async move {
        if let Err(err) = handle_inbound_datagram(udp_socket, args, mgr).await {
            log::error!("UDP error \"{}\"", err);
        }
    });

    _ = quit.recv().await;
    log::info!("");
    log::info!("Ctrl-C recieved, exiting...");

    Ok(())
}

async fn handle_inbound_stream(
    tcp_stack: lwip::TcpStream,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    mgr: Arc<dyn ConnectionManager>,
    server_addr: SocketAddr,
) -> crate::Result<()> {
    log::trace!("Session count {}", TASK_COUNT.fetch_add(1, Relaxed) + 1);
    let info = SessionInfo::new(local_addr, remote_addr, IpProtocol::Tcp);
    let proxy_handler = mgr.new_proxy_handler(info, false).await?;
    if let Err(err) = handle_tcp_session(tcp_stack, server_addr, proxy_handler).await {
        log::error!("{} error \"{}\"", info, err);
    }
    log::trace!("Session count {}", TASK_COUNT.fetch_sub(1, Relaxed) - 1);
    Ok(())
}

async fn handle_inbound_datagram(udp_socket: Box<lwip::UdpSocket>, args: Args, mgr: Arc<dyn ConnectionManager>) -> crate::Result<()> {
    let server_addr = args.proxy.addr;
    let (udp_tx, mut udp_rx) = udp_socket.split();
    let udp_tx = Arc::new(udp_tx);

    let udp_sessions = Arc::new(Mutex::new(HashMap::<SessionInfo, Sender<Vec<u8>>>::new()));
    let udp_sessions_clone = udp_sessions.clone();

    let (session_dead_tx, mut session_dead_rx) = mpsc::channel::<SessionInfo>(1024);
    let session_dead_tx = Arc::new(session_dead_tx);
    tokio::spawn(async move {
        while let Some(session) = session_dead_rx.recv().await {
            udp_sessions_clone.lock().await.remove(&session);
        }
    });

    while let Ok((incoming_pkt, src_addr, dst_addr)) = udp_rx.recv_from().await {
        let mut info = SessionInfo::new(src_addr, dst_addr, IpProtocol::Udp);
        if info.dst.port() == DNS_PORT && is_private_ip(info.dst.ip()) {
            info.dst.set_ip(args.dns_addr);
        }

        let mut udp_sessions = udp_sessions.lock().await;
        if let Some(session_data_sender) = udp_sessions.get(&info) {
            session_data_sender.send(incoming_pkt).await.ok();
            continue;
        }

        let (session_data_sender, session_data_receiver) = mpsc::channel::<Vec<u8>>(1024);
        udp_sessions.insert(info, session_data_sender);

        let udp_tx = udp_tx.clone();
        let session_dead_tx = session_dead_tx.clone();
        let mgr = mgr.clone();
        let ipv6 = args.ipv6_enabled;
        tokio::spawn(async move {
            log::trace!("Session count {}", TASK_COUNT.fetch_add(1, Relaxed) + 1);
            let first_pkt = incoming_pkt;

            if info.dst.port() == DNS_PORT && args.dns == args::ArgDns::OverTcp {
                let proxy_handler = mgr.new_proxy_handler(info, false).await?;
                if let Err(err) = dns_over_tcp_session(first_pkt, session_data_receiver, udp_tx, server_addr, proxy_handler, ipv6).await {
                    log::error!("{} error \"{}\"", info, err);
                }
            } else {
                let proxy_handler = mgr.new_proxy_handler(info, true).await?;
                if let Err(err) = udp_generic_session(first_pkt, session_data_receiver, udp_tx, server_addr, proxy_handler, ipv6).await {
                    log::error!("{} error \"{}\"", info, err);
                }
            }

            if let Err(err) = session_dead_tx.send(info).await {
                log::error!("{} error \"{}\"", info, err);
            }
            log::trace!("Session count {}", TASK_COUNT.fetch_sub(1, Relaxed) - 1);
            Ok::<(), crate::Error>(())
        });
    }
    Ok(())
}

async fn handle_tcp_session(
    tcp_stack: lwip::TcpStream,
    server_addr: SocketAddr,
    proxy_handler: Arc<Mutex<dyn ProxyHandler>>,
) -> crate::Result<()> {
    let mut server = TcpStream::connect(server_addr).await?;

    let session_info = proxy_handler.lock().await.get_session_info();
    log::info!("Beginning {}", session_info);

    let _ = handle_proxy_session(&mut server, proxy_handler).await?;

    let (mut t_rx, mut t_tx) = tokio::io::split(tcp_stack);
    let (mut s_rx, mut s_tx) = tokio::io::split(server);

    let result = tokio::join! {
         tokio::io::copy(&mut t_rx, &mut s_tx),
         tokio::io::copy(&mut s_rx, &mut t_tx),
    };
    let result = match result {
        (Ok(t), Ok(s)) => Ok((t, s)),
        (Err(e), _) | (_, Err(e)) => Err(e),
    };

    log::info!("Ending {} with {:?}", session_info, result);

    Ok(())
}

async fn udp_generic_session(
    first_pkt: Vec<u8>,
    mut session_data_receiver: Receiver<Vec<u8>>,
    udp_tx: Arc<lwip::UdpSendHalf>,
    server_addr: SocketAddr,
    proxy_handler: Arc<Mutex<dyn ProxyHandler>>,
    ipv6_enabled: bool,
) -> crate::Result<()> {
    use socks5_impl::protocol::{StreamOperation, UdpHeader};
    let mut server = TcpStream::connect(server_addr).await?;
    let session_info = proxy_handler.lock().await.get_session_info();
    log::info!("Beginning {}", session_info);

    let udp_addr = handle_proxy_session(&mut server, proxy_handler).await?;
    let udp_addr = udp_addr.ok_or("udp associate failed")?;

    let mut udp_server = UdpStream::connect(udp_addr).await?;

    async fn write_to_udp_server(udp_server: &mut UdpStream, data: &[u8], session_info: SessionInfo) -> crate::Result<()> {
        // Add SOCKS5 UDP header to the incoming data
        let mut s5_udp_data = Vec::<u8>::new();
        UdpHeader::new(0, session_info.dst.into()).write_to_stream(&mut s5_udp_data)?;
        s5_udp_data.extend_from_slice(data);

        udp_server.write_all(&s5_udp_data).await?;
        Ok(())
    }

    write_to_udp_server(&mut udp_server, &first_pkt, session_info).await?;

    // Set your desired timeout duration
    let timeout_duration = std::time::Duration::from_secs(5);

    let mut buf2 = [0_u8; 4096];
    loop {
        let timeout = tokio::time::Instant::now() + timeout_duration;
        tokio::select! {
            buf1 = session_data_receiver.recv() => {
                let buf1 = buf1.ok_or("")?;
                if buf1.is_empty() {
                    break;
                }
                write_to_udp_server(&mut udp_server, &buf1, session_info).await?;
            }
            len = udp_server.read(&mut buf2) => {
                let len = len?;
                if len == 0 {
                    break;
                }
                let buf2 = &buf2[..len];

                // Remove SOCKS5 UDP header from the server data
                let header = UdpHeader::retrieve_from_stream(&mut &buf2[..])?;
                let data = &buf2[header.len()..];

                let buf = if session_info.dst.port() == DNS_PORT {
                    let mut message = dns::parse_data_to_dns_message(data, false)?;
                    if !ipv6_enabled {
                        dns::remove_ipv6_entries(&mut message);
                    }
                    message.to_vec()?
                } else {
                    data.to_vec()
                };

                // udp_tx.send_to(&buf, &session_info.dst, &session_info.src)?;
                udp_tx.send_to(&buf, &session_info.src, &session_info.dst)?;
            }
            _ = tokio::time::sleep_until(timeout) => {
                log::trace!("{} timeout", session_info);
                break;
            }
        }
    }

    log::info!("Ending {}", session_info);

    Ok(())
}

async fn dns_over_tcp_session(
    first_pkt: Vec<u8>,
    mut session_data_receiver: Receiver<Vec<u8>>,
    udp_tx: Arc<lwip::UdpSendHalf>,
    server_addr: SocketAddr,
    proxy_handler: Arc<Mutex<dyn ProxyHandler>>,
    ipv6_enabled: bool,
) -> crate::Result<()> {
    let mut server = TcpStream::connect(server_addr).await?;

    let session_info = proxy_handler.lock().await.get_session_info();
    log::info!("Beginning {}", session_info);

    let _ = handle_proxy_session(&mut server, proxy_handler).await?;

    async fn write_to_server(server: &mut TcpStream, data: &[u8]) -> crate::Result<()> {
        _ = dns::parse_data_to_dns_message(data, false)?;

        // Insert the DNS message length in front of the payload
        let len = u16::try_from(data.len())?;
        let mut buf = Vec::with_capacity(std::mem::size_of::<u16>() + usize::from(len));
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(data);

        server.write_all(&buf).await?;
        Ok(())
    }

    write_to_server(&mut server, &first_pkt).await?;

    let mut buf2 = [0_u8; 4096];
    loop {
        tokio::select! {
            buf1 = session_data_receiver.recv() => {
                let buf1 = buf1.ok_or("")?;
                if buf1.is_empty() {
                    break;
                }

                write_to_server(&mut server, &buf1).await?;
            }
            len = server.read(&mut buf2) => {
                let len = len?;
                if len == 0 {
                    break;
                }
                let mut buf = buf2[..len].to_vec();

                let mut to_send: VecDeque<Vec<u8>> = VecDeque::new();
                loop {
                    if buf.len() < 2 {
                        break;
                    }
                    let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
                    if buf.len() < len + 2 {
                        break;
                    }

                    // remove the length field
                    let data = buf[2..len + 2].to_vec();

                    let mut message = dns::parse_data_to_dns_message(&data, false)?;

                    let name = dns::extract_domain_from_dns_message(&message)?;
                    let ip = dns::extract_ipaddr_from_dns_message(&message);
                    log::trace!("DNS over TCP query result: {} -> {:?}", name, ip);

                    if !ipv6_enabled {
                        dns::remove_ipv6_entries(&mut message);
                    }

                    to_send.push_back(message.to_vec()?);
                    if len + 2 == buf.len() {
                        break;
                    }
                    buf = buf[len + 2..].to_vec();
                }

                while let Some(packet) = to_send.pop_front() {
                    // udp_tx.send_to(&packet, &session_info.dst, &session_info.src)?;
                    udp_tx.send_to(&packet, &session_info.src, &session_info.dst)?;
                }
            }
        }
    }

    log::info!("Ending {}", session_info);

    Ok(())
}

async fn handle_proxy_session(server: &mut TcpStream, proxy_handler: Arc<Mutex<dyn ProxyHandler>>) -> crate::Result<Option<SocketAddr>> {
    let mut launched = false;
    let mut proxy_handler = proxy_handler.lock().await;
    let dir = OutgoingDirection::ToServer;

    loop {
        if proxy_handler.connection_established() {
            break;
        }

        if !launched {
            let data = proxy_handler.peek_data(dir).buffer;
            let len = data.len();
            if len == 0 {
                return Err("proxy_handler launched went wrong".into());
            }
            server.write_all(data).await?;
            proxy_handler.consume_data(dir, len);

            launched = true;
        }

        let mut buf = [0_u8; 4096];
        let len = server.read(&mut buf).await?;
        if len == 0 {
            return Err("server closed accidentially".into());
        }
        let event = IncomingDataEvent {
            direction: IncomingDirection::FromServer,
            buffer: &buf[..len],
        };
        proxy_handler.push_data(event).await?;

        let data = proxy_handler.peek_data(dir).buffer;
        let len = data.len();
        if len > 0 {
            server.write_all(data).await?;
            proxy_handler.consume_data(dir, len);
        }
    }
    Ok(proxy_handler.get_udp_associate())
}
