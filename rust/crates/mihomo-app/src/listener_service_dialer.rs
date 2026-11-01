use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use mihomo_core::BoxedTcpStream;
use mihomo_dns::DnsRuntime;
use mihomo_transport::{
    NetTcpStreamAddr, SocketOptions, TcpDialPurpose, TcpDialer, TransportError,
    TransportTarget,
};

pub(crate) struct DnsAwareTcpDialer {
    dns_runtime: Option<DnsRuntime>,
}

impl DnsAwareTcpDialer {
    pub(crate) fn new(dns_runtime: Option<DnsRuntime>) -> Self {
        Self { dns_runtime }
    }

    fn resolve_addr(
        &mut self,
        target: &TransportTarget,
        purpose: TcpDialPurpose,
    ) -> Result<SocketAddr, TransportError> {
        if let Ok(ip) = target.host.parse::<IpAddr>() {
            return Ok(SocketAddr::new(ip, target.port));
        }
        if let Some(runtime) = self.dns_runtime.as_mut() {
            let resolved = match purpose {
                TcpDialPurpose::FinalTarget => {
                    runtime.resolve_direct_server_host_via_system(&target.host)
                }
                TcpDialPurpose::ProxyServer => {
                    runtime.resolve_proxy_server_host_via_system(&target.host)
                }
            }
            .map_err(|err| TransportError::Io {
                kind: io::ErrorKind::Other,
                message: err.to_string(),
            })?;
            if let Some(ip) = resolved {
                return Ok(SocketAddr::new(ip, target.port));
            }
        }

        let mut addrs = (target.host.as_str(), target.port)
            .to_socket_addrs()
            .map_err(TransportError::from)?;
        addrs.next().ok_or_else(|| TransportError::Io {
            kind: io::ErrorKind::NotFound,
            message: format!("failed to resolve tcp target: {}", target.authority()),
        })
    }
}

impl TcpDialer for DnsAwareTcpDialer {
    fn fork(&self,timeout_ms:u64)->Option<Box<dyn TcpDialer+Send>>{
        // The fork carries this resolver snapshot rather than using host DNS.
        Some(Box::new(BoundedDnsDialer{inner:Self::new(self.dns_runtime.clone()),timeout_ms}))
    }

    fn resolve_addrs(
        &mut self,
        target: &TransportTarget,
        _socket: &SocketOptions,
        purpose: TcpDialPurpose,
    ) -> Result<Vec<NetTcpStreamAddr>, TransportError> {
        if let Ok(ip) = target.host.parse::<IpAddr>() {
            return Ok(vec![NetTcpStreamAddr(SocketAddr::new(ip, target.port))]);
        }
        if let Some(runtime) = self.dns_runtime.as_mut() {
            let resolved = match purpose {
                TcpDialPurpose::FinalTarget => {
                    runtime.resolve_direct_server_host_addrs_via_system(&target.host)
                }
                TcpDialPurpose::ProxyServer => {
                    runtime.resolve_proxy_server_host_addrs_via_system(&target.host)
                }
            }
            .map_err(|err| TransportError::Io {
                kind: io::ErrorKind::Other,
                message: err.to_string(),
            })?;
            if !resolved.is_empty() {
                return Ok(resolved
                    .into_iter()
                    .map(|ip| NetTcpStreamAddr(SocketAddr::new(ip, target.port)))
                    .collect());
            }
        }

        let addrs = (target.host.as_str(), target.port)
            .to_socket_addrs()
            .map_err(TransportError::from)?
            .collect::<Vec<_>>();
        if addrs.is_empty() {
            return Err(TransportError::Io {
                kind: io::ErrorKind::NotFound,
                message: format!("failed to resolve tcp target: {}", target.authority()),
            });
        }
        Ok(addrs.into_iter().map(NetTcpStreamAddr).collect())
    }

    fn connect(
        &mut self,
        target: &TransportTarget,
        socket: &SocketOptions,
        purpose: TcpDialPurpose,
    ) -> Result<BoxedTcpStream, TransportError> {
        let addr = self.resolve_addr(target, purpose)?;
        let stream = mihomo_transport::connect_tcp_addr_with_options(addr,socket,None).map_err(TransportError::from)?;
        Ok(Box::new(stream))
    }
}

struct BoundedDnsDialer{inner:DnsAwareTcpDialer,timeout_ms:u64}
impl TcpDialer for BoundedDnsDialer{
 fn fork(&self,timeout_ms:u64)->Option<Box<dyn TcpDialer+Send>>{self.inner.fork(timeout_ms.min(self.timeout_ms))}
 fn resolve_addrs(&mut self,target:&TransportTarget,socket:&SocketOptions,purpose:TcpDialPurpose)->Result<Vec<NetTcpStreamAddr>,TransportError>{self.inner.resolve_addrs(target,socket,purpose)}
 fn connect(&mut self,target:&TransportTarget,socket:&SocketOptions,purpose:TcpDialPurpose)->Result<BoxedTcpStream,TransportError>{
  let address=self.inner.resolve_addr(target,purpose)?;
  let stream=mihomo_transport::connect_tcp_addr_with_options(address,socket,Some(self.timeout_ms))?;
  stream.set_read_timeout(Some(std::time::Duration::from_millis(self.timeout_ms)))?;stream.set_write_timeout(Some(std::time::Duration::from_millis(self.timeout_ms)))?;Ok(Box::new(stream))
 }
}
