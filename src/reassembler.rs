use std::cmp::{max, min};
use std::collections::BTreeMap;

use crate::byte_stream::ByteStream;

#[derive(Debug)]
pub struct Reassembler {
    output: ByteStream,
    pending: BTreeMap<u64, Vec<u8>>,
    eof_index: Option<u64>,
}

impl Reassembler {
    pub fn new(capacity: usize) -> Self {
        Self {
            output: ByteStream::new(capacity),
            pending: BTreeMap::new(),
            eof_index: None,
        }
    }

    pub fn insert(&mut self, first_index: u64, data: &[u8], is_last_substring: bool) {
        let original_end = first_index.saturating_add(data.len() as u64);

        if is_last_substring {
            match self.eof_index {
                Some(existing) => {
                    debug_assert_eq!(existing, original_end, "Inconsistent EOF indices");
                }
                None => {
                    self.eof_index = Some(original_end);
                }
            }
        }

        let first_unassembled = self.output.bytes_pushed();

        let first_unacceptable = self
            .output
            .bytes_popped()
            .saturating_add(self.output.capacity() as u64);

        let clipped_start = max(first_index, first_unassembled);
        let clipped_end = min(original_end, first_unacceptable);

        if clipped_start < clipped_end {
            let data_start = (clipped_start - first_index) as usize;
            let data_end = (clipped_end - first_index) as usize;

            let clipped_data = data[data_start..data_end].to_vec();

            self.merge_segment(clipped_start, clipped_data);
            self.flush_contiguous();
        }
        self.close_if_complete();
    }

    pub fn bytes_pending(&self) -> usize {
        self.pending.values().map(Vec::len).sum()
    }

    pub fn output(&self) -> &ByteStream {
        &self.output
    }

    pub fn output_mut(&mut self) -> &mut ByteStream {
        &mut self.output
    }

    fn merge_segment(&mut self, start: u64, data: Vec<u8>) {
        if data.is_empty() {
            return;
        }

        let mut merged_start = start;
        let mut merged_data = data;

        if let Some((&previous_start, previous_data)) =
            self.pending.range(..=merged_start).next_back()
        {
            let previous_end = previous_start.saturating_add(previous_data.len() as u64);

            if previous_end >= merged_start {
                let previous_data = self
                    .pending
                    .remove(&previous_start)
                    .expect("predecessor must exist");

                (merged_start, merged_data) = Self::merge_two_segements(
                    previous_start,
                    previous_data,
                    merged_start,
                    merged_data,
                );
            }
        }

        loop {
            let merged_end = merged_start.saturating_add(merged_data.len() as u64);

            let next = self
                .pending
                .range(merged_start..)
                .next()
                .map(|(&next_start, _)| next_start);

            let Some(next_start) = next else {
                break;
            };

            if next_start > merged_end {
                break;
            }

            let next_data = self
                .pending
                .remove(&next_start)
                .expect("successor must exist");

            (merged_start, merged_data) =
                Self::merge_two_segements(merged_start, merged_data, next_start, next_data);
        }

        self.pending.insert(merged_start, merged_data);
    }

    fn merge_two_segements(
        left_start: u64,
        left_data: Vec<u8>,
        right_start: u64,
        right_data: Vec<u8>,
    ) -> (u64, Vec<u8>) {
        let left_end = left_start.saturating_add(left_data.len() as u64);
        let right_end = right_start.saturating_add(right_data.len() as u64);

        let merged_start = min(left_start, right_start);
        let merged_end = max(left_end, right_end);

        let merged_len = (merged_end - merged_start) as usize;
        let mut merged = vec![0_u8; merged_len];

        let left_offset = (left_start - merged_start) as usize;
        let right_offset = (right_start - merged_start) as usize;

        merged[left_offset..left_offset + left_data.len()].copy_from_slice(&left_data);
        merged[right_offset..right_offset + right_data.len()].copy_from_slice(&right_data);

        (merged_start, merged)
    }

    fn flush_contiguous(&mut self) {
        loop {
            let next_required = self.output.bytes_pushed();

            let first_pending_start = self.pending.first_key_value().map(|(&start, _)| start);

            let Some(start) = first_pending_start else {
                break;
            };

            if start != next_required {
                break;
            }

            let data = self
                .pending
                .remove(&start)
                .expect("first peding segment must exist");

            let accepted = self.output.push(&data);

            if accepted < data.len() {
                let remainder_start = start + accepted as u64;
                let remainder_data = data[accepted..].to_vec();

                self.pending.insert(remainder_start, remainder_data);
                break;
            }
        }
    }

    fn close_if_complete(&mut self) {
        if let Some(eof_index) = self.eof_index {
            if self.output.bytes_pushed() == eof_index {
                self.output.close();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordered_insert_is_written_immediately() {
        let mut reassembler = Reassembler::new(10);

        reassembler.insert(0, b"abc", false);

        assert_eq!(reassembler.output().peek(), b"abc");
        assert_eq!(reassembler.output().bytes_pushed(), 3);
        assert_eq!(reassembler.bytes_pending(), 0);
    }

    #[test]
    fn out_of_order_insert_waits_for_missing_prefix() {
        let mut reassembler = Reassembler::new(10);

        reassembler.insert(3, b"def", false);

        assert_eq!(reassembler.output().bytes_buffered(), 0);
        assert_eq!(reassembler.bytes_pending(), 3);

        reassembler.insert(0, b"abc", false);

        assert_eq!(reassembler.output().peek(), b"abcdef");
        assert_eq!(reassembler.output().bytes_pushed(), 6);
        assert_eq!(reassembler.bytes_pending(), 0);
    }

    #[test]
    fn duplicate_segment_is_stored_once() {
        let mut reassembler = Reassembler::new(10);

        reassembler.insert(3, b"def", false);
        reassembler.insert(3, b"def", false);

        assert_eq!(reassembler.bytes_pending(), 3);
    }

    #[test]
    fn overlapping_segments_are_merged() {
        let mut reassembler = Reassembler::new(10);

        reassembler.insert(2, b"cdef", false);
        reassembler.insert(0, b"abcd", false);

        assert_eq!(reassembler.output().peek(), b"abcdef");
        assert_eq!(reassembler.bytes_pending(), 0);
    }

    #[test]
    fn adjacent_segments_are_merged() {
        let mut reassembler = Reassembler::new(20);

        reassembler.insert(5, b"fgh", false);
        reassembler.insert(8, b"ijk", false);

        assert_eq!(reassembler.bytes_pending(), 6);

        reassembler.insert(0, b"abcde", false);

        assert_eq!(reassembler.output().peek(), b"abcdefghijk");
        assert_eq!(reassembler.bytes_pending(), 0);
    }

    #[test]
    fn earlier_already_assembled_bytes_are_discarded() {
        let mut reassembler = Reassembler::new(10);

        reassembler.insert(0, b"abcd", false);
        reassembler.insert(0, b"abcdef", false);

        assert_eq!(reassembler.output().peek(), b"abcdef");
        assert_eq!(reassembler.output().bytes_pushed(), 6);
        assert_eq!(reassembler.bytes_pending(), 0);
    }

    #[test]
    fn bytes_beyond_capacity_window_are_discarded() {
        let mut reassembler = Reassembler::new(5);

        reassembler.insert(0, b"abcdefghij", false);

        assert_eq!(reassembler.output().peek(), b"abcde");
        assert_eq!(reassembler.output().bytes_pushed(), 5);
        assert_eq!(reassembler.bytes_pending(), 0);
    }

    #[test]
    fn future_bytes_beyond_window_are_not_saved() {
        let mut reassembler = Reassembler::new(5);

        reassembler.insert(100, b"xyz", false);

        assert_eq!(reassembler.output().bytes_buffered(), 0);
        assert_eq!(reassembler.bytes_pending(), 0);
    }

    #[test]
    fn reader_pop_advances_the_acceptable_window() {
        let mut reassembler = Reassembler::new(5);

        reassembler.insert(0, b"abcde", false);

        assert_eq!(reassembler.output().peek(), b"abcde");

        reassembler.output_mut().pop(3);

        reassembler.insert(5, b"fgh", false);

        assert_eq!(reassembler.output().bytes_pushed(), 8);
        assert_eq!(reassembler.output().bytes_popped(), 3);
        assert_eq!(reassembler.output().bytes_buffered(), 5);
    }

    #[test]
    fn final_substring_closes_output_after_complete_assembly() {
        let mut reassembler = Reassembler::new(10);

        reassembler.insert(3, b"def", true);

        assert!(!reassembler.output().is_closed());

        reassembler.insert(0, b"abc", false);

        assert_eq!(reassembler.output().peek(), b"abcdef");
        assert!(reassembler.output().is_closed());
        assert!(!reassembler.output().is_finished());

        reassembler.output_mut().pop(6);

        assert!(reassembler.output().is_finished());
    }

    #[test]
    fn empty_final_segment_can_close_an_empty_stream() {
        let mut reassembler = Reassembler::new(10);

        reassembler.insert(0, b"", true);

        assert!(reassembler.output().is_closed());
        assert!(reassembler.output().is_finished());
    }

    #[test]
    fn multiple_out_of_order_segments_bridge_into_one_stream() {
        let mut reassembler = Reassembler::new(20);

        reassembler.insert(6, b"ghi", false);
        reassembler.insert(3, b"def", false);
        reassembler.insert(9, b"jkl", true);

        assert_eq!(reassembler.bytes_pending(), 9);

        reassembler.insert(0, b"abc", false);

        assert_eq!(reassembler.output().peek(), b"abcdefghijkl");
        assert_eq!(reassembler.bytes_pending(), 0);
        assert!(reassembler.output().is_closed());
    }
}
