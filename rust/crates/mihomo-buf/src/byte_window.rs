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
