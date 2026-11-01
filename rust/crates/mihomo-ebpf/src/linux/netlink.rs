//! Remove a clsact qdisc we created only when both hooks are now empty.
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

pub(super) fn remove_empty_clsact(index: u32) -> io::Result<()> {
    for parent in [0xfffffff2u32, 0xfffffff3u32] {
        if !request(46, 0x301, index, 0, parent)?.is_empty() {
            return Ok(());
        }
    }
    request(37, 5, index, 0xffff0000, 0xfffffff1).map(|_| ())
}
fn request(
    kind: u16,
    flags: u16,
    index: u32,
    handle: u32,
    parent: u32,
) -> io::Result<Vec<Vec<u8>>> {
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let timeout = libc::timeval {
        tv_sec: 1,
        tv_usec: 0,
    };
    unsafe {
        libc::setsockopt(
            raw,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &timeout as *const _ as *const _,
            std::mem::size_of_val(&timeout) as _,
        );
    }
    let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    address.nl_family = libc::AF_NETLINK as u16;
    if unsafe {
        libc::connect(
            raw,
            &address as *const _ as *const _,
            std::mem::size_of_val(&address) as _,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut message = Vec::new();
    message.extend(36u32.to_ne_bytes());
    message.extend(kind.to_ne_bytes());
    message.extend(flags.to_ne_bytes());
    message.extend(1u32.to_ne_bytes());
    message.extend(0u32.to_ne_bytes());
    message.extend([libc::AF_UNSPEC as u8, 0, 0, 0]);
    message.extend(index.to_ne_bytes());
    message.extend(handle.to_ne_bytes());
    message.extend(parent.to_ne_bytes());
    message.extend(0u32.to_ne_bytes());
    if unsafe {
        libc::send(
            fd.as_raw_fd(),
            message.as_ptr() as *const _,
            message.len(),
            0,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut messages = Vec::new();
    let mut buffer = vec![0u8; 65536];
    loop {
        let size = unsafe {
            libc::recv(
                fd.as_raw_fd(),
                buffer.as_mut_ptr() as *mut _,
                buffer.len(),
                0,
            )
        };
        if size < 0 {
            return Err(io::Error::last_os_error());
        }
        if size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "netlink closed",
            ));
        }
        let mut offset = 0;
        while offset + 16 <= size as usize {
            let length =
                u32::from_ne_bytes(buffer[offset..offset + 4].try_into().unwrap()) as usize;
            if length < 16 || offset + length > size as usize {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid netlink response",
                ));
            }
            let kind = u16::from_ne_bytes(buffer[offset + 4..offset + 6].try_into().unwrap());
            if kind == 3 {
                return Ok(messages);
            }
            if kind == 2 {
                if length < 20 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "short netlink error",
                    ));
                }
                let code = i32::from_ne_bytes(buffer[offset + 16..offset + 20].try_into().unwrap());
                return if code == 0 {
                    Ok(messages)
                } else {
                    Err(io::Error::from_raw_os_error(-code))
                };
            }
            if kind == 44 {
                messages.push(buffer[offset..offset + length].to_vec());
            }
            offset += (length + 3) & !3;
        }
    }
}
