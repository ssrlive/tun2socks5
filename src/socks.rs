use crate::{
    directions::{IncomingDataEvent, IncomingDirection, OutgoingDataEvent, OutgoingDirection},
    error::{Error, Result},
    proxy_handler::{ConnectionManager, ProxyHandler},
    session_info::SessionInfo,
};
use socks5_impl::protocol::{self, handshake, password_method, Address, AuthMethod, StreamOperation, UserKey, Version};
use std::{collections::VecDeque, net::SocketAddr, sync::Arc};
use tokio::sync::Mutex;

#[derive(Eq, PartialEq, Debug)]
enum SocksState {
    ClientHello,
    ServerHello,
    SendAuthData,
    ReceiveAuthResponse,
    SendRequest,
    ReceiveResponse,
    Established,
}

struct SocksProxyImpl {
    info: SessionInfo,
    state: SocksState,
    client_inbuf: VecDeque<u8>,
    server_inbuf: VecDeque<u8>,
    client_outbuf: VecDeque<u8>,
    server_outbuf: VecDeque<u8>,
    version: Version,
    credentials: Option<UserKey>,
    command: protocol::Command,
    udp_associate: Option<SocketAddr>,
}

impl SocksProxyImpl {
    fn new(info: SessionInfo, credentials: Option<UserKey>, version: Version, command: protocol::Command) -> Result<Self> {
        let mut result = Self {
            info,
            state: SocksState::ClientHello,
            client_inbuf: VecDeque::default(),
            server_inbuf: VecDeque::default(),
            client_outbuf: VecDeque::default(),
            server_outbuf: VecDeque::default(),
            version,
            credentials,
            command,
            udp_associate: None,
        };
        result.send_client_hello()?;
        Ok(result)
    }

    fn send_client_hello_socks4(&mut self) -> Result<(), Error> {
        let credentials = &self.credentials;
        self.server_outbuf.extend(&[self.version as u8, protocol::Command::Connect.into()]);
        self.server_outbuf.extend(self.info.dst.port().to_be_bytes());
        let mut ip_vec = Vec::<u8>::new();
        let name_vec = Vec::<u8>::new();
        match &self.info.dst {
            SocketAddr::V4(addr) => {
                ip_vec.extend(addr.ip().octets().as_ref());
            }
            SocketAddr::V6(_) => {
                return Err("SOCKS4 does not support IPv6".into());
            }
        }
        self.server_outbuf.extend(ip_vec);
        if let Some(credentials) = credentials {
            self.server_outbuf.extend(credentials.username.as_bytes());
            if !credentials.password.is_empty() {
                self.server_outbuf.push_back(b':');
                self.server_outbuf.extend(credentials.password.as_bytes());
            }
        }
        self.server_outbuf.push_back(0);
        self.server_outbuf.extend(name_vec);
        Ok(())
    }

    fn send_client_hello_socks5(&mut self) -> Result<(), Error> {
        let credentials = &self.credentials;
        let mut methods = vec![AuthMethod::NoAuth, AuthMethod::from(4_u8), AuthMethod::from(100_u8)];
        if credentials.is_some() {
            methods.push(AuthMethod::UserPass);
        }
        handshake::Request::new(methods).write_to_stream(&mut self.server_outbuf)?;
        Ok(())
    }

    fn send_client_hello(&mut self) -> Result<(), Error> {
        match self.version {
            Version::V4 => {
                self.send_client_hello_socks4()?;
            }
            Version::V5 => {
                self.send_client_hello_socks5()?;
            }
        }
        self.state = SocksState::ServerHello;
        Ok(())
    }

    fn receive_server_hello_socks4(&mut self) -> std::io::Result<()> {
        if self.server_inbuf.len() < 8 {
            return Ok(());
        }

        if self.server_inbuf[1] != 0x5a {
            return Err(crate::Error::from("SOCKS4 server replied with an unexpected reply code.").into());
        }

        self.server_inbuf.drain(0..8);

        self.state = SocksState::Established;
        self.state_change()
    }

    fn receive_server_hello_socks5(&mut self) -> std::io::Result<()> {
        let response = handshake::Response::retrieve_from_stream(&mut self.server_inbuf.clone());
        if let Err(e) = response {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                log::trace!("receive_server_hello_socks5 needs more data \"{}\"...", e);
                return Ok(());
            } else {
                return Err(e);
            }
        }
        let respones = response?;
        self.server_inbuf.drain(0..respones.len());
        let auth_method = respones.method;

        if auth_method != AuthMethod::NoAuth && self.credentials.is_none()
            || (auth_method != AuthMethod::NoAuth && auth_method != AuthMethod::UserPass) && self.credentials.is_some()
        {
            return Err(crate::Error::from("SOCKS5 server requires an unsupported authentication method.").into());
        }

        self.state = if auth_method == AuthMethod::UserPass {
            SocksState::SendAuthData
        } else {
            SocksState::SendRequest
        };
        self.state_change()
    }

    fn receive_server_hello(&mut self) -> std::io::Result<()> {
        match self.version {
            Version::V4 => self.receive_server_hello_socks4(),
            Version::V5 => self.receive_server_hello_socks5(),
        }
    }

    fn send_auth_data(&mut self) -> std::io::Result<()> {
        let tmp = UserKey::default();
        let credentials = self.credentials.as_ref().unwrap_or(&tmp);
        let request = password_method::Request::new(&credentials.username, &credentials.password);
        request.write_to_stream(&mut self.server_outbuf)?;
        self.state = SocksState::ReceiveAuthResponse;
        self.state_change()
    }

    fn receive_auth_data(&mut self) -> std::io::Result<()> {
        use password_method::Response;
        let response = Response::retrieve_from_stream(&mut self.server_inbuf.clone());
        if let Err(e) = response {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                log::trace!("receive_auth_data needs more data \"{}\"...", e);
                return Ok(());
            } else {
                return Err(e);
            }
        }
        let response = response?;
        self.server_inbuf.drain(0..response.len());
        if response.status != password_method::Status::Succeeded {
            return Err(crate::Error::from(format!("SOCKS authentication failed: {:?}", response.status)).into());
        }
        self.state = SocksState::SendRequest;
        self.state_change()
    }

    fn send_request_socks5(&mut self) -> std::io::Result<()> {
        let addr = if self.command == protocol::Command::UdpAssociate {
            Address::unspecified()
        } else {
            self.info.dst.into()
        };
        protocol::Request::new(self.command, addr).write_to_stream(&mut self.server_outbuf)?;
        self.state = SocksState::ReceiveResponse;
        self.state_change()
    }

    fn receive_connection_status(&mut self) -> std::io::Result<()> {
        let response = protocol::Response::retrieve_from_stream(&mut self.server_inbuf.clone());
        if let Err(e) = response {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                log::trace!("receive_connection_status needs more data \"{}\"...", e);
                return Ok(());
            } else {
                return Err(e);
            }
        }
        let response = response?;
        self.server_inbuf.drain(0..response.len());
        if response.reply != protocol::Reply::Succeeded {
            return Err(crate::Error::from(format!("SOCKS connection failed: {}", response.reply)).into());
        }
        if self.command == protocol::Command::UdpAssociate {
            self.udp_associate = Some(SocketAddr::try_from(&response.address)?);
            log::trace!("UDP associate recieved address {}", response.address);
        }

        self.state = SocksState::Established;
        self.state_change()
    }

    fn relay_traffic(&mut self) -> Result<(), Error> {
        self.client_outbuf.extend(self.server_inbuf.iter());
        self.server_outbuf.extend(self.client_inbuf.iter());
        self.server_inbuf.clear();
        self.client_inbuf.clear();
        Ok(())
    }

    fn state_change(&mut self) -> std::io::Result<()> {
        match self.state {
            SocksState::ServerHello => self.receive_server_hello()?,

            SocksState::SendAuthData => self.send_auth_data()?,

            SocksState::ReceiveAuthResponse => self.receive_auth_data()?,

            SocksState::SendRequest => self.send_request_socks5()?,

            SocksState::ReceiveResponse => self.receive_connection_status()?,

            SocksState::Established => self.relay_traffic()?,

            _ => {}
        }
        Ok(())
    }
}

impl ProxyHandler for SocksProxyImpl {
    fn get_connection_info(&self) -> SessionInfo {
        self.info
    }

    fn push_data(&mut self, event: IncomingDataEvent<'_>) -> std::io::Result<()> {
        let IncomingDataEvent { direction, buffer } = event;
        match direction {
            IncomingDirection::FromServer => {
                self.server_inbuf.extend(buffer.iter());
            }
            IncomingDirection::FromClient => {
                self.client_inbuf.extend(buffer.iter());
            }
        }

        self.state_change()
    }

    fn consume_data(&mut self, dir: OutgoingDirection, size: usize) {
        let buffer = match dir {
            OutgoingDirection::ToServer => &mut self.server_outbuf,
            OutgoingDirection::ToClient => &mut self.client_outbuf,
        };
        buffer.drain(0..size);
    }

    fn peek_data(&mut self, dir: OutgoingDirection) -> OutgoingDataEvent {
        let buffer = match dir {
            OutgoingDirection::ToServer => &mut self.server_outbuf,
            OutgoingDirection::ToClient => &mut self.client_outbuf,
        };
        OutgoingDataEvent {
            direction: dir,
            buffer: buffer.make_contiguous(),
        }
    }

    fn connection_established(&self) -> bool {
        self.state == SocksState::Established
    }

    fn data_len(&self, dir: OutgoingDirection) -> usize {
        match dir {
            OutgoingDirection::ToServer => self.server_outbuf.len(),
            OutgoingDirection::ToClient => self.client_outbuf.len(),
        }
    }

    fn reset_connection(&self) -> bool {
        false
    }

    fn get_udp_associate(&self) -> Option<SocketAddr> {
        self.udp_associate
    }
}

pub(crate) struct SocksProxyManager {
    server: SocketAddr,
    credentials: Option<UserKey>,
    version: Version,
}

impl ConnectionManager for SocksProxyManager {
    fn new_proxy_handler(&self, info: SessionInfo, udp_associate: bool) -> std::io::Result<Arc<Mutex<dyn ProxyHandler + Send + Sync>>> {
        use socks5_impl::protocol::Command::{Connect, UdpAssociate};
        let command = if udp_associate { UdpAssociate } else { Connect };
        let credentials = self.credentials.clone();
        Ok(Arc::new(Mutex::new(SocksProxyImpl::new(info, credentials, self.version, command)?)))
    }

    fn get_server_addr(&self) -> SocketAddr {
        self.server
    }
}

impl SocksProxyManager {
    pub(crate) fn new(server: SocketAddr, version: Version, credentials: Option<UserKey>) -> Self {
        Self {
            server,
            credentials,
            version,
        }
    }
}