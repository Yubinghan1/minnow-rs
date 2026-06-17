use std::cmp::min;
use std::collections::VecDeque;

use bytes::Bytes;

#[derive(Debug)]
pub struct ByteStream {
    capacity: usize,
    chunks: VecDeque<Bytes>,
    bytes_buffered: usize,
    closed: bool,
    error: bool,
    bytes_pushed: u64,
    bytes_popped: u64,
}

impl ByteStream {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            chunks: VecDeque::new(),
            bytes_buffered: 0,
            closed: false,
            error: false,
            bytes_pushed: 0,
            bytes_popped: 0,
        }
    }

    pub fn push(&mut self, data: Bytes) -> usize {
        if self.closed || self.error {
            return 0;
        }

        let accepted = min(data.len(), self.available_capacity());

        if accepted > 0 {
            let chunk = if accepted == data.len() {
                data
            } else {
                data.slice(..accepted)
            };

            self.chunks.push_back(chunk);
            self.bytes_buffered += accepted;
            self.bytes_pushed += accepted as u64;
        }

        accepted
    }

    pub fn close(&mut self) {
        self.closed = true;
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    pub fn set_error(&mut self) {
        self.error = true;
    }

    pub fn has_error(&self) -> bool {
        self.error
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn available_capacity(&self) -> usize {
        self.capacity - self.bytes_buffered
    }

    pub fn peek(&self) -> Bytes {
        self.chunks.front().cloned().unwrap_or_default()
    }

    pub fn chunks(&self) -> impl Iterator<Item = &Bytes> {
        self.chunks.iter()
    }

    pub fn pop(&mut self, len: usize) -> Bytes {
        let Some(front) = self.chunks.pop_front() else {
            return Bytes::new();
        };

        let popped = min(len, front.len());

        if popped == 0 {
            self.chunks.push_front(front);
            return Bytes::new();
        }

        self.bytes_buffered -= popped;
        self.bytes_popped += popped as u64;

        if popped == front.len() {
            front
        } else {
            let prefix = front.slice(..popped);
            let suffix = front.slice(popped..);

            self.chunks.push_front(suffix);

            prefix
        }
    }

    pub fn bytes_buffered(&self) -> usize {
        self.bytes_buffered
    }

    pub fn bytes_pushed(&self) -> u64 {
        self.bytes_pushed
    }

    pub fn bytes_popped(&self) -> u64 {
        self.bytes_popped
    }

    pub fn is_finished(&self) -> bool {
        self.closed && self.bytes_buffered == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stream_is_empty() {
        let stream = ByteStream::new(5);

        assert_eq!(stream.available_capacity(), 5);
        assert_eq!(stream.bytes_buffered(), 0);
        assert_eq!(stream.bytes_pushed(), 0);
        assert_eq!(stream.bytes_popped(), 0);
        assert!(!stream.is_closed());
        assert!(!stream.is_finished());
        assert!(!stream.has_error());
    }

    #[test]
    fn push_and_peek() {
        let mut stream = ByteStream::new(5);

        assert_eq!(stream.push(Bytes::from_static(b"abc")), 3);
        assert_eq!(stream.peek(), Bytes::from_static(b"abc"));
        assert_eq!(stream.bytes_buffered(), 3);
        assert_eq!(stream.available_capacity(), 2);
        assert_eq!(stream.bytes_pushed(), 3);
    }

    #[test]
    fn push_respects_capacity() {
        let mut stream = ByteStream::new(4);

        assert_eq!(stream.push(Bytes::from_static(b"abcdef")), 4);
        assert_eq!(stream.peek(), Bytes::from_static(b"abcd"));
        assert_eq!(stream.bytes_buffered(), 4);
        assert_eq!(stream.available_capacity(), 0);
        assert_eq!(stream.bytes_pushed(), 4);
    }

    #[test]
    fn pop_releases_capacity() {
        let mut stream = ByteStream::new(4);

        assert_eq!(stream.push(Bytes::from_static(b"abcd")), 4);

        stream.pop(2);

        assert_eq!(stream.peek(), Bytes::from_static(b"cd"));
        assert_eq!(stream.bytes_buffered(), 2);
        assert_eq!(stream.available_capacity(), 2);
        assert_eq!(stream.bytes_popped(), 2);

        assert_eq!(stream.push(Bytes::from_static(b"XY")), 2);
        assert_eq!(stream.bytes_buffered(), 4);
    }

    #[test]
    fn close_rejects_new_data() {
        let mut stream = ByteStream::new(4);

        stream.close();

        assert_eq!(stream.push(Bytes::from_static(b"abc")), 0);
        assert_eq!(stream.bytes_buffered(), 0);
        assert!(stream.is_closed());
        assert!(stream.is_finished());
    }

    #[test]
    fn closed_stream_finishes_after_reader_drains_buffer() {
        let mut stream = ByteStream::new(4);

        stream.push(Bytes::from_static(b"abc"));
        stream.close();

        assert!(stream.is_closed());
        assert!(!stream.is_finished());

        stream.pop(3);

        assert!(stream.is_finished());
    }

    #[test]
    fn pop_more_than_buffered_is_safe() {
        let mut stream = ByteStream::new(4);

        stream.push(Bytes::from_static(b"ab"));
        stream.pop(100);

        assert_eq!(stream.bytes_buffered(), 0);
        assert_eq!(stream.bytes_popped(), 2);
        assert_eq!(stream.available_capacity(), 4);
    }

    #[test]
    fn tiny_capacity_can_carry_a_long_stream() {
        let mut stream = ByteStream::new(1);

        for byte in b"hello world" {
            assert_eq!(stream.push(Bytes::copy_from_slice(&[*byte])), 1);
            assert_eq!(stream.peek(), Bytes::copy_from_slice(&[*byte]));
            stream.pop(1);
        }

        assert_eq!(stream.bytes_pushed(), 11);
        assert_eq!(stream.bytes_popped(), 11);
        assert_eq!(stream.bytes_buffered(), 0);
        assert_eq!(stream.available_capacity(), 1);
    }

    #[test]
    fn error_state_rejects_new_data() {
        let mut stream = ByteStream::new(5);

        stream.push(Bytes::from_static(b"ab"));
        stream.set_error();

        assert!(stream.has_error());
        assert_eq!(stream.push(Bytes::from_static(b"cd")), 0);
        assert_eq!(stream.bytes_buffered(), 2);
    }

    #[test]
    fn push_and_pop_move_chunks() {
        let mut stream = ByteStream::new(8);

        assert_eq!(stream.push(Bytes::from_static(b"abcdef")), 6);

        let first = stream.pop(2);
        let second = stream.pop(10);

        assert_eq!(first, Bytes::from_static(b"ab"));
        assert_eq!(second, Bytes::from_static(b"cdef"));
        assert_eq!(stream.bytes_buffered(), 0);
        assert_eq!(stream.bytes_pushed(), 6);
        assert_eq!(stream.bytes_popped(), 6);
    }

    #[test]
    fn push_respects_capacity_without_copying_past_window() {
        let mut stream = ByteStream::new(3);

        assert_eq!(stream.push(Bytes::from_static(b"abcdef")), 3);
        assert_eq!(stream.peek(), Bytes::from_static(b"abc"));
        assert_eq!(stream.bytes_buffered(), 3);
        assert_eq!(stream.available_capacity(), 0);
    }
}
