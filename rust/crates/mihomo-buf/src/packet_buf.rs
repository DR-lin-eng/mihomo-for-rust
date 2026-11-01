use crate::ByteWindow;

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
