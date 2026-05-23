use std::io::IoSlice;
use std::ops::Range;
use std::sync::Arc;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ByteWindow {
    storage: Arc<Vec<u8>>,
    start: usize,
    end: usize,
}

impl ByteWindow {
    pub fn freeze(bytes: Vec<u8>) -> Self {
        let len = bytes.len();
        Self {
            storage: Arc::new(bytes),
            start: 0,
            end: len,
        }
    }

    pub fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.storage[self.start..self.end]
    }

    pub fn slice(&self, range: Range<usize>) -> Self {
        assert!(range.start <= range.end);
        assert!(range.end <= self.len());
        Self {
            storage: Arc::clone(&self.storage),
            start: self.start + range.start,
            end: self.start + range.end,
        }
    }

    pub fn split_to(&mut self, at: usize) -> Self {
        assert!(at <= self.len());
        let head = self.slice(0..at);
        self.start += at;
        head
    }

    pub fn split_off(&mut self, at: usize) -> Self {
        assert!(at <= self.len());
        let tail = self.slice(at..self.len());
        self.end = self.start + at;
        tail
    }

    pub fn io_slice(&self) -> [IoSlice<'_>; 1] {
        [IoSlice::new(self.as_slice())]
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketBuf {
    payload: ByteWindow,
    headroom: usize,
    tailroom: usize,
}

impl PacketBuf {
    pub fn new(payload: ByteWindow, headroom: usize, tailroom: usize) -> Self {
        Self {
            payload,
            headroom,
            tailroom,
        }
    }

    pub fn payload(&self) -> &ByteWindow {
        &self.payload
    }

    pub fn headroom(&self) -> usize {
        self.headroom
    }

    pub fn tailroom(&self) -> usize {
        self.tailroom
    }
}

#[cfg(test)]
mod tests {
    use super::{ByteWindow, PacketBuf};

    #[test]
    fn windows_share_the_same_storage() {
        let base = ByteWindow::freeze(vec![1, 2, 3, 4, 5]);
        let left = base.slice(0..2);
        let right = base.slice(2..5);
        assert_eq!(left.as_slice(), &[1, 2]);
        assert_eq!(right.as_slice(), &[3, 4, 5]);
    }

    #[test]
    fn split_to_and_split_off_keep_views() {
        let mut base = ByteWindow::freeze(b"mihomo".to_vec());
        let head = base.split_to(3);
        let tail = base.split_off(1);
        assert_eq!(head.as_slice(), b"mih");
        assert_eq!(base.as_slice(), b"o");
        assert_eq!(tail.as_slice(), b"mo");
    }

    #[test]
    fn packet_buf_carries_head_and_tail_room() {
        let packet = PacketBuf::new(ByteWindow::freeze(vec![9, 8, 7]), 32, 64);
        assert_eq!(packet.payload().as_slice(), &[9, 8, 7]);
        assert_eq!(packet.headroom(), 32);
        assert_eq!(packet.tailroom(), 64);
    }
}
