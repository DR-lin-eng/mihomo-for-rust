use std::io::{self, Read};

use mihomo_runtime::ListenerRuntimeError;

pub(super) fn read_shadowsocks_target(
    stream: &mut dyn Read,
) -> Result<String, ListenerRuntimeError> {
    let mut atyp = [0_u8; 1];
    stream.read_exact(&mut atyp)?;
    let host = match atyp[0] {
        0x01 => {
            let mut addr = [0_u8; 4];
            stream.read_exact(&mut addr)?;
            std::net::Ipv4Addr::from(addr).to_string()
        }
        0x04 => {
            let mut addr = [0_u8; 16];
            stream.read_exact(&mut addr)?;
            std::net::Ipv6Addr::from(addr).to_string()
        }
        0x03 => {
            let mut len = [0_u8; 1];
            stream.read_exact(&mut len)?;
            let mut host = vec![0_u8; len[0] as usize];
            stream.read_exact(&mut host)?;
            String::from_utf8(host).map_err(|err| {
                ListenerRuntimeError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    err.to_string(),
                ))
            })?
        }
        other => {
            return Err(ListenerRuntimeError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected shadowsocks atyp {other}"),
            )))
        }
    };
    let mut port = [0_u8; 2];
    stream.read_exact(&mut port)?;
    Ok(format!("{host}:{}", u16::from_be_bytes(port)))
}

pub(super) fn read_trojan_request(
    stream: &mut dyn Read,
) -> Result<(String, u8, String), ListenerRuntimeError> {
    let mut password = [0_u8; 56];
    stream.read_exact(&mut password)?;
    let mut crlf = [0_u8; 2];
    stream.read_exact(&mut crlf)?;
    if &crlf != b"\r\n" {
        return Err(ListenerRuntimeError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid trojan request delimiter after password",
        )));
    }
    let mut command = [0_u8; 1];
    stream.read_exact(&mut command)?;
    let target = read_shadowsocks_target(stream)?;
    stream.read_exact(&mut crlf)?;
    if &crlf != b"\r\n" {
        return Err(ListenerRuntimeError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid trojan request delimiter after target",
        )));
    }
    let password = String::from_utf8(password.to_vec()).map_err(|err| {
        ListenerRuntimeError::Io(io::Error::new(io::ErrorKind::InvalidData, err.to_string()))
    })?;
    Ok((password, command[0], target))
}
