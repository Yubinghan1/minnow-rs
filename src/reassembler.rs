use std::cmp::{max, min};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use bytes::Bytes;

use crate::byte_stream::ByteStream;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReassemblerError {
    IndexOverflow,

    InconsistentEof {
        existing: u64,
        received: u64,
    },

    SegmentBeyondEof {
        eof: u64,
        segment_start: u64,
        segment_end: u64,
    },

    BufferedDataBeyondEof {
        eof: u64,
        buffered_end: u64,
    },
}

impl fmt::Display for ReassemblerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IndexOverflow => {
                write!(formatter, "reassembler index calculation overflowed")
            }

            Self::InconsistentEof { existing, received } => {
                write!(
                    formatter,
                    "inconsistent EOF indices: existing={existing}, received={received}"
                )
            }

            Self::SegmentBeyondEof {
                eof,
                segment_start,
                segment_end,
            } => {
                write!(
                    formatter,
                    "segment [{segment_start}, {segment_end}) extends beyond EOF {eof}"
                )
            }

            Self::BufferedDataBeyondEof { eof, buffered_end } => {
                write!(
                    formatter,
                    "buffered data ends at {buffered_end}, beyond EOF {eof}"
                )
            }
        }
    }
}

impl Error for ReassemblerError {}

#[derive(Debug)]
pub struct Reassembler {
    output: ByteStream,
    pending: BTreeMap<u64, Bytes>,
    eof_index: Option<u64>,
}

impl Reassembler {
    pub fn new(capacity: usize) -> Self {
        let reassembler = Self {
            output: ByteStream::new(capacity),
            pending: BTreeMap::new(),
            eof_index: None,
        };

        reassembler.debug_check_invariants();
        reassembler
    }

    pub fn insert(&mut self, first_index: u64, data: &[u8], is_last_substring: bool) {
        self.try_insert(first_index, data, is_last_substring)
            .expect("incoming fragment is inconsistent with the byte stream");
    }

    pub fn try_insert(
        &mut self,
        first_index: u64,
        data: &[u8],
        is_last_substring: bool,
    ) -> Result<(), ReassemblerError> {
        let data_len = u64::try_from(data.len()).map_err(|_| ReassemblerError::IndexOverflow)?;

        let original_end = first_index
            .checked_add(data_len)
            .ok_or(ReassemblerError::IndexOverflow)?;

        self.record_and_validate_eof(original_end, is_last_substring)?;

        if let Some(eof_index) = self.eof_index
            && original_end > eof_index
        {
            return Err(ReassemblerError::SegmentBeyondEof {
                eof: eof_index,
                segment_start: first_index,
                segment_end: original_end,
            });
        }

        let first_unassembled = self.output.bytes_pushed();

        let first_unacceptable = self
            .output
            .bytes_popped()
            .saturating_add(self.output.capacity() as u64);

        let clipped_start = max(first_index, first_unassembled);
        let clipped_end = min(original_end, first_unacceptable);

        if clipped_start < clipped_end {
            let data_start = usize::try_from(clipped_start - first_index)
                .expect("clipped start must fit in usize");

            let data_end =
                usize::try_from(clipped_end - first_index).expect("clipped end must fit in usize");

            let clipped_data = &data[data_start..data_end];

            if clipped_start == self.output.bytes_pushed() {
                self.output.push(clipped_data);
            } else {
                self.insert_missing_gaps(clipped_start, clipped_data);
            }
            self.flush_contiguous();
        }

        self.close_if_complete();
        self.debug_check_invariants();

        Ok(())
    }

    pub fn bytes_pending(&self) -> usize {
        self.pending.values().map(Bytes::len).sum()
    }

    pub fn output(&self) -> &ByteStream {
        &self.output
    }

    pub fn output_mut(&mut self) -> &mut ByteStream {
        &mut self.output
    }

    fn insert_missing_gaps(&mut self, start: u64, data: &[u8]) {
        if data.is_empty() {
            return;
        }

        let end = start
            .checked_add(data.len() as u64)
            .expect("clipped fragment end must fit in u64");

        let mut cursor = start;

        if let Some((&previous_start, previous_data)) = self.pending.range(..=cursor).next_back() {
            let previous_end = previous_start.saturating_add(previous_data.len() as u64);

            if previous_end > cursor {
                cursor = min(previous_end, end);
            }
        }

        while cursor < end {
            let next_existing =
                self.pending
                    .range(cursor..end)
                    .next()
                    .map(|(&next_start, next_data)| {
                        let next_end = next_start.saturating_add(next_data.len() as u64);

                        (next_start, next_end)
                    });

            match next_existing {
                Some((next_start, next_end)) => {
                    if cursor < next_start {
                        self.insert_gap(start, data, cursor, next_start);
                    }

                    cursor = min(max(cursor, next_end), end);
                }

                None => {
                    self.insert_gap(start, data, cursor, end);
                    break;
                }
            }
        }
    }

    fn insert_gap(
        &mut self,
        original_start: u64,
        original_data: &[u8],
        gap_start: u64,
        gap_end: u64,
    ) {
        if gap_start >= gap_end {
            return;
        }

        let slice_start =
            usize::try_from(gap_start - original_start).expect("gap start must fit in usize");

        let slice_end =
            usize::try_from(gap_end - original_start).expect("gap end must fit in usize");

        let gap = Bytes::copy_from_slice(&original_data[slice_start..slice_end]);

        let previous = self.pending.insert(gap_start, gap);

        debug_assert!(
            previous.is_none(),
            "insert_gap must never replace an existing fragment"
        );
    }

    fn flush_contiguous(&mut self) {
        loop {
            let next_required = self.output.bytes_pushed();

            let first_pending_start = self.pending.first_key_value().map(|(&start, _)| start);

            let Some(start) = first_pending_start else {
                break;
            };

            if start < next_required {
                self.trim_stale_prefix(start, next_required);
                continue;
            }

            if start != next_required {
                break;
            }

            let data = self
                .pending
                .remove(&start)
                .expect("first pending fragment must exist");

            let accepted = self.output.push(&data);

            debug_assert!(
                accepted <= data.len(),
                "ByteStream cannot accept more bytes than provided"
            );

            if accepted < data.len() {
                let remainder_start = start + accepted as u64;
                let remainder = data.slice(accepted..);

                self.pending.insert(remainder_start, remainder);

                break;
            }
        }
    }

    fn trim_stale_prefix(&mut self, start: u64, next_required: u64) {
        let data = self
            .pending
            .remove(&start)
            .expect("pending fragment must exist");

        let end = start.saturating_add(data.len() as u64);

        if end <= next_required {
            return;
        }

        let suffix_start =
            usize::try_from(next_required - start).expect("suffix offset must fit in usize");

        let suffix = data.slice(suffix_start..);

        self.pending.insert(next_required, suffix);
    }

    fn record_and_validate_eof(
        &mut self,
        received_eof: u64,
        is_last_substring: bool,
    ) -> Result<(), ReassemblerError> {
        if !is_last_substring {
            return Ok(());
        }

        match self.eof_index {
            Some(existing) if existing != received_eof => {
                return Err(ReassemblerError::InconsistentEof {
                    existing,
                    received: received_eof,
                });
            }

            Some(_) => {
                return Ok(());
            }

            None => {}
        }

        if self.output.bytes_pushed() > received_eof {
            return Err(ReassemblerError::BufferedDataBeyondEof {
                eof: received_eof,
                buffered_end: self.output.bytes_pushed(),
            });
        }

        for (&start, data) in &self.pending {
            let end = start
                .checked_add(data.len() as u64)
                .ok_or(ReassemblerError::IndexOverflow)?;

            if end > received_eof {
                return Err(ReassemblerError::BufferedDataBeyondEof {
                    eof: received_eof,
                    buffered_end: end,
                });
            }
        }

        self.eof_index = Some(received_eof);

        Ok(())
    }

    fn close_if_complete(&mut self) {
        if let Some(eof_index) = self.eof_index
            && self.output.bytes_pushed() == eof_index
        {
            self.output.close();
        }
    }

    fn debug_check_invariants(&self) {
        let first_unassembled = self.output.bytes_pushed();

        let first_unacceptable = self
            .output
            .bytes_popped()
            .saturating_add(self.output.capacity() as u64);

        let mut previous_end: Option<u64> = None;

        for (&start, data) in &self.pending {
            debug_assert!(!data.is_empty(), "pending fragments must be non-empty");

            let end = start.saturating_add(data.len() as u64);

            debug_assert!(
                start >= first_unassembled,
                "pending fragment begins before first_unassembled"
            );

            debug_assert!(
                end <= first_unacceptable,
                "pending fragment exceeds the acceptable receive window"
            );

            if let Some(previous_end) = previous_end {
                debug_assert!(previous_end <= start, "pending fragments must not overlap");
            }

            if let Some(eof_index) = self.eof_index {
                debug_assert!(end <= eof_index, "pending fragment extends beyond EOF");
            }

            previous_end = Some(end);
        }

        debug_assert!(
            self.output
                .bytes_buffered()
                .saturating_add(self.bytes_pending())
                <= self.output.capacity(),
            "ByteStream and Reassembler must jointly respect capacity"
        );

        if let Some(eof_index) = self.eof_index {
            debug_assert!(
                self.output.bytes_pushed() <= eof_index,
                "assembled bytes cannot extend beyond EOF"
            );
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
    fn overlapping_insert_keeps_only_missing_ranges() {
        let mut reassembler = Reassembler::new(20);

        reassembler.insert(4, b"ef", false);
        reassembler.insert(2, b"cdefgh", false);

        assert_eq!(reassembler.bytes_pending(), 6);

        reassembler.insert(0, b"ab", false);

        assert_eq!(reassembler.output().peek(), b"abcdefgh");
        assert_eq!(reassembler.bytes_pending(), 0);
    }

    #[test]
    fn adjacent_segments_flush_in_order() {
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
    fn zero_capacity_discards_everything() {
        let mut reassembler = Reassembler::new(0);

        reassembler.insert(0, b"abc", false);

        assert_eq!(reassembler.output().bytes_pushed(), 0);
        assert_eq!(reassembler.bytes_pending(), 0);
    }

    #[test]
    fn segment_is_clipped_on_both_sides() {
        let mut reassembler = Reassembler::new(5);

        reassembler.insert(0, b"abc", false);
        reassembler.output_mut().pop(2);

        // Current acceptable window: [2, 7)
        // Already assembled: [0, 3)
        // New fragment: [1, 9)
        // Newly useful bytes: [3, 7)
        reassembler.insert(1, b"bcdefghi", false);

        assert_eq!(reassembler.output().bytes_pushed(), 7);
        assert_eq!(reassembler.output().bytes_buffered(), 5);
    }

    #[test]
    fn reverse_single_byte_segments_are_reassembled() {
        let mut reassembler = Reassembler::new(10);

        for index in (0..10).rev() {
            let byte = [b'a' + index as u8];
            reassembler.insert(index, &byte, false);
        }

        assert_eq!(reassembler.output().peek(), b"abcdefghij");
        assert_eq!(reassembler.bytes_pending(), 0);
    }

    #[test]
    fn combined_storage_never_exceeds_capacity() {
        let mut reassembler = Reassembler::new(10);

        reassembler.insert(5, b"fghij", false);

        assert!(
            reassembler.output().bytes_buffered() + reassembler.bytes_pending()
                <= reassembler.output().capacity()
        );

        reassembler.insert(0, b"abcdefghij", false);

        assert_eq!(reassembler.output().peek(), b"abcdefghij");
        assert_eq!(reassembler.bytes_pending(), 0);

        assert!(
            reassembler.output().bytes_buffered() + reassembler.bytes_pending()
                <= reassembler.output().capacity()
        );
    }

    #[test]
    fn inconsistent_eof_is_rejected() {
        let mut reassembler = Reassembler::new(10);

        assert!(reassembler.try_insert(3, b"def", true).is_ok());

        let error = reassembler
            .try_insert(4, b"def", true)
            .expect_err("conflicting EOF must be rejected");

        assert_eq!(
            error,
            ReassemblerError::InconsistentEof {
                existing: 6,
                received: 7,
            }
        );
    }

    #[test]
    fn bytes_beyond_known_eof_are_rejected() {
        let mut reassembler = Reassembler::new(10);

        assert!(reassembler.try_insert(3, b"def", true).is_ok());

        let error = reassembler
            .try_insert(5, b"fg", false)
            .expect_err("bytes beyond EOF must be rejected");

        assert_eq!(
            error,
            ReassemblerError::SegmentBeyondEof {
                eof: 6,
                segment_start: 5,
                segment_end: 7,
            }
        );
    }
}
