use bytes::Bytes;

use crate::wrapping_integers::Wrap32;

/// A segment sent from a TCP sender to a TCP receiver.
///
/// SYN and FIN each occupy one sequence number.
/// Every payload byte also occupies one sequence number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpSenderMessage {
    /// Sequence number occupied by SYN when `syn == true`.
    /// Otherwise, the sequence number of the first payload byte or FIN.
    pub seqno: Wrap32,

    /// Marks the beginning of this byte stream.
    pub syn: bool,

    /// Application bytes carried by this segment.
    pub payload: Bytes,

    /// Marks the end of this byte stream.
    pub fin: bool,

    /// Aborts the stream because of an error.
    pub rst: bool,
}

impl TcpSenderMessage {
    pub fn new(seqno: Wrap32) -> Self {
        Self {
            seqno,
            syn: false,
            payload: Bytes::new(),
            fin: false,
            rst: false,
        }
    }

    /// Number of TCP sequence numbers occupied by this segment.
    ///
    /// SYN occupies one sequence number.
    /// Every payload byte occupies one sequence number.
    /// FIN occupies one sequence number.
    pub fn sequence_length(&self) -> u64 {
        self.syn as u64 + self.payload.len() as u64 + self.fin as u64
    }

    /// Empty messages are useful as ACK carriers, but should not be tracked
    /// as outstanding and should not be retransmitted.
    pub fn is_empty_in_sequence_space(&self) -> bool {
        self.sequence_length() == 0
    }
}

/// Receiver feedback sent back to the peer's sender.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TcpReceiverMessage {
    /// The next TCP sequence number needed by the receiver.
    ///
    /// `None` means the receiver has not accepted SYN yet.
    pub ackno: Option<Wrap32>,

    /// Advertised receive window.
    pub window_size: u16,

    /// Aborts the stream because of an error.
    pub rst: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence_length_counts_syn_payload_and_fin() {
        let message = TcpSenderMessage {
            seqno: Wrap32::new(100),
            syn: true,
            payload: Bytes::from_static(b"cat"),
            fin: true,
            rst: false,
        };

        assert_eq!(message.sequence_length(), 5);
    }

    #[test]
    fn empty_message_occupies_no_sequence_space() {
        let message = TcpSenderMessage::new(Wrap32::new(100));

        assert_eq!(message.sequence_length(), 0);
        assert!(message.is_empty_in_sequence_space());
    }
}
