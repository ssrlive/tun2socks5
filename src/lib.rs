use crate::{
    args::ProxyType,
    directions::{IncomingDataEvent, IncomingDirection, OutgoingDirection},
    session_info::{IpProtocol, SessionInfo},
};
pub use args::Args;
pub use error::{Error, Result};
use ipstack::stream::{IpStackStream, IpStackTcpStream, IpStackUdpStream};
use proxy_handler::{ConnectionManager, ProxyHandler};
pub use route_config::{config_restore, config_settings, DEFAULT_GATEWAY, TUN_DNS, TUN_GATEWAY, TUN_IPV4, TUN_NETMASK};
use socks::SocksProxyManager;
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::Mutex,
};
use udp_stream::UdpStream;

mod args;
mod directions;
mod dns;
mod error;
mod proxy_handler;
mod route_config;
mod session_info;
mod socks;

const DNS_PORT: u16 = 53;

static TASK_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
use std::sync::atomic::Ordering::Relaxed;

pub async fn main_entry<D>(device: D, mtu: u16, packet_info: bool, args: Args) -> crate::Result<()>
where
    D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let server_addr = args.proxy.addr;
    let key = args.proxy.credentials.clone();
    let dns_addr = args.dns_addr;
    let ipv6_enabled = args.ipv6_enabled;

    use socks5_impl::protocol::Version::{V4, V5};
    let mgr = match args.proxy.proxy_type {
        ProxyType::Socks5 => Arc::new(SocksProxyManager::new(server_addr, V5, key)) as Arc<dyn ConnectionManager>,
        ProxyType::Socks4 => Arc::new(SocksProxyManager::new(server_addr, V4, key)) as Arc<dyn ConnectionManager>,
        ProxyType::Http => {
            unimplemented!("http proxy is not implemented yet")
        }
    };

    let mut ip_stack = ipstack::IpStack::new(device, mtu, packet_info);

    loop {
        match ip_stack.accept().await? {
            IpStackStream::Tcp(tcp) => {
                log::trace!("Session count {}", TASK_COUNT.fetch_add(1, Relaxed) + 1);
                let info = SessionInfo::new(tcp.local_addr(), tcp.peer_addr(), IpProtocol::Tcp);
                let proxy_handler = mgr.new_proxy_handler(info, false)?;
                tokio::spawn(async move {
                    if let Err(err) = handle_tcp_connection(tcp, server_addr, proxy_handler).await {
                        log::error!("{} error \"{}\"", info, err);
                    }
                    log::trace!("Session count {}", TASK_COUNT.fetch_sub(1, Relaxed) - 1);
                });
            }
            IpStackStream::Udp(udp) => {
                log::trace!("Session count {}", TASK_COUNT.fetch_add(1, Relaxed) + 1);
                let mut info = SessionInfo::new(udp.local_addr(), udp.peer_addr(), IpProtocol::Udp);
                if info.dst.port() == DNS_PORT && dns::addr_is_private(&info.dst) {
                    info.dst.set_ip(dns_addr);
                }
                let proxy_handler = mgr.new_proxy_handler(info, true)?;
                tokio::spawn(async move {
                    if let Err(err) = handle_udp_associate_connection(udp, server_addr, proxy_handler, ipv6_enabled).await {
                        log::error!("{} error \"{}\"", info, err);
                    }
                    log::trace!("Session count {}", TASK_COUNT.fetch_sub(1, Relaxed) - 1);
                });
            }
        };
    }
}

async fn handle_tcp_connection(
    tcp_stack: IpStackTcpStream,
    server_addr: SocketAddr,
    proxy_handler: Arc<Mutex<dyn ProxyHandler>>,
) -> crate::Result<()> {
    let mut server = TcpStream::connect(server_addr).await?;

    let session_info = proxy_handler.lock().await.get_connection_info();
    log::info!("Beginning {}", session_info);

    let _ = handle_proxy_connection(&mut server, proxy_handler).await?;

    let (mut t_rx, mut t_tx) = tokio::io::split(tcp_stack);
    let (mut s_rx, mut s_tx) = tokio::io::split(server);

    let result = tokio::join! {
         tokio::io::copy(&mut t_rx, &mut s_tx) ,
         tokio::io::copy(&mut s_rx, &mut t_tx),
    };
    let result = match result {
        (Ok(t), Ok(s)) => Ok((t, s)),
        (Err(e), _) | (_, Err(e)) => Err(e),
    };

    log::info!("Ending {} with {:?}", session_info, result);

    Ok(())
}

async fn handle_udp_associate_connection(
    mut udp_stack: IpStackUdpStream,
    server_addr: SocketAddr,
    proxy_handler: Arc<Mutex<dyn ProxyHandler>>,
    ipv6_enabled: bool,
) -> crate::Result<()> {
    use socks5_impl::protocol::{StreamOperation, UdpHeader};
    let mut server = TcpStream::connect(server_addr).await?;
    let session_info = proxy_handler.lock().await.get_connection_info();
    log::info!("Beginning {}", session_info);

    let udp_addr = handle_proxy_connection(&mut server, proxy_handler).await?;
    let udp_addr = udp_addr.ok_or("udp associate failed")?;

    let mut udp_server = UdpStream::connect(udp_addr).await?;

    let mut buf1 = [0_u8; 4096];
    let mut buf2 = [0_u8; 4096];
    loop {
        tokio::select! {
            len = udp_stack.read(&mut buf1) => {
                let len = len?;
                if len == 0 {
                    break;
                }
                let buf1 = &buf1[..len];

                // Add SOCKS5 UDP header to the incoming data
                let mut s5_udp_data = Vec::<u8>::new();
                UdpHeader::new(0, session_info.dst.into()).write_to_stream(&mut s5_udp_data)?;
                s5_udp_data.extend_from_slice(buf1);

                udp_server.write_all(&s5_udp_data).await?;
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

                udp_stack.write_all(&buf).await?;
            }
        }
    }

    log::info!("Ending {}", session_info);

    Ok(())
}

async fn handle_proxy_connection(server: &mut TcpStream, proxy_handler: Arc<Mutex<dyn ProxyHandler>>) -> crate::Result<Option<SocketAddr>> {
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
        proxy_handler.push_data(event)?;

        let data = proxy_handler.peek_data(dir).buffer;
        let len = data.len();
        if len > 0 {
            server.write_all(data).await?;
            proxy_handler.consume_data(dir, len);
        }
    }
    Ok(proxy_handler.get_udp_associate())
}
