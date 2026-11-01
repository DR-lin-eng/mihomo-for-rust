use std::collections::VecDeque;

use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};

pub(super) struct TunTcpDevice {
    recv: TunTcpToken,
    send: TunTcpToken,
    mtu: usize,
}

pub(super) struct TunTcpToken {
    queue: VecDeque<Vec<u8>>,
}

impl TunTcpDevice {
    pub(super) fn new(mtu: usize) -> Self {
        Self {
            recv: TunTcpToken {
                queue: VecDeque::new(),
            },
            send: TunTcpToken {
                queue: VecDeque::new(),
            },
            mtu,
        }
    }

    pub(super) fn enqueue_received(&mut self, packet: Vec<u8>) {
        self.recv.queue.push_back(packet);
    }

    pub(super) fn dequeue_sent(&mut self) -> Option<Vec<u8>> {
        self.send.queue.pop_front()
    }
}

impl Device for TunTcpDevice {
    type RxToken<'a> = &'a mut TunTcpToken;
    type TxToken<'a> = &'a mut TunTcpToken;

    fn receive(
        &mut self,
        _: smoltcp::time::Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.recv.queue.is_empty() {
            None
        } else {
            Some((&mut self.recv, &mut self.send))
        }
    }

    fn transmit(&mut self, _: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        Some(&mut self.send)
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

impl RxToken for &mut TunTcpToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = self.queue.pop_front().unwrap_or_default();
        f(&mut packet)
    }
}

impl TxToken for &mut TunTcpToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0_u8; len];
        let result = f(&mut packet);
        self.queue.push_back(packet);
        result
    }
}
