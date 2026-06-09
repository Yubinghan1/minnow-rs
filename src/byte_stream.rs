use std::cmp::min;
use std::collections::VecDeque;

#[derive(Debug)]
pub struct ByteStream {
    capacity: usize,
    buffer: VecDeque<u8>,
    closed: bool,
    error: bool,
    bytes_pushed: u64,
    bytes_popped: u64,
}

impl ByteStream {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            buffer: VecDeque::with_capacity(capacity),
            closed: false,
            error: false,
            bytes_pushed: 0,
            bytes_popped: 0,
        }
    }

    pub fn push(&mut self, data: &[u8]) -> usize {
        if self.closed || self.error {
            return 0;
        }

        let accepted = min(data.len(), self.available_capacity());

        self.buffer.extend(data[..accepted].iter().copied());
        self.bytes_pushed += accepted as u64;

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

    pub fn available_capacity(&self) -> usize {
        self.capacity - self.buffer.len()
    }

    pub fn peek(&self) -> &[u8] {
        let (first, second) = self.buffer.as_slices();

        if !first.is_empty() { first } else { second }
    }

    pub fn pop(&mut self, len: usize) {
        let popped = min(len, self.buffer.len());

        self.buffer.drain(..popped);
        self.bytes_popped += popped as u64;
    }

    pub fn bytes_buffered(&self) -> usize {
        self.buffer.len()
    }

    pub fn bytes_pushed(&self) -> u64 {
        self.bytes_pushed
    }

    pub fn bytes_popped(&self) -> u64 {
        self.bytes_popped
    }

    pub fn is_finished(&self) -> bool {
        self.closed && self.buffer.is_empty()
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

        assert_eq!(stream.push(b"abc"), 3);
        assert_eq!(stream.peek(), b"abc");
        assert_eq!(stream.bytes_buffered(), 3);
        assert_eq!(stream.available_capacity(), 2);
        assert_eq!(stream.bytes_pushed(), 3);
    }

    #[test]
    fn push_respects_capacity() {
        let mut stream = ByteStream::new(4);

        assert_eq!(stream.push(b"abcdef"), 4);
        assert_eq!(stream.peek(), b"abcd");
        assert_eq!(stream.bytes_buffered(), 4);
        assert_eq!(stream.available_capacity(), 0);
        assert_eq!(stream.bytes_pushed(), 4);
    }

    #[test]
    fn pop_releases_capacity() {
        let mut stream = ByteStream::new(4);

        assert_eq!(stream.push(b"abcd"), 4);

        stream.pop(2);

        assert_eq!(stream.peek(), b"cd");
        assert_eq!(stream.bytes_buffered(), 2);
        assert_eq!(stream.available_capacity(), 2);
        assert_eq!(stream.bytes_popped(), 2);

        assert_eq!(stream.push(b"XY"), 2);
        assert_eq!(stream.bytes_buffered(), 4);
    }

    #[test]
    fn close_rejects_new_data() {
        let mut stream = ByteStream::new(4);

        stream.close();

        assert_eq!(stream.push(b"abc"), 0);
        assert_eq!(stream.bytes_buffered(), 0);
        assert!(stream.is_closed());
        assert!(stream.is_finished());
    }

    #[test]
    fn closed_stream_finishes_after_reader_drains_buffer() {
        let mut stream = ByteStream::new(4);

        stream.push(b"abc");
        stream.close();

        assert!(stream.is_closed());
        assert!(!stream.is_finished());

        stream.pop(3);

        assert!(stream.is_finished());
    }

    #[test]
    fn pop_more_than_buffered_is_safe() {
        let mut stream = ByteStream::new(4);

        stream.push(b"ab");
        stream.pop(100);

        assert_eq!(stream.bytes_buffered(), 0);
        assert_eq!(stream.bytes_popped(), 2);
        assert_eq!(stream.available_capacity(), 4);
    }

    #[test]
    fn tiny_capacity_can_carry_a_long_stream() {
        let mut stream = ByteStream::new(1);

        for byte in b"hello world" {
            assert_eq!(stream.push(&[*byte]), 1);
            assert_eq!(stream.peek(), &[*byte]);
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

        stream.push(b"ab");
        stream.set_error();

        assert!(stream.has_error());
        assert_eq!(stream.push(b"cd"), 0);
        assert_eq!(stream.bytes_buffered(), 2);
    }
}
