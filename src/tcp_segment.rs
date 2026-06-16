use bytes::{BufMut, Bytes, BytesMut};

use crate::checksum::tcp_checksum_ipv4;
use crate::tcp_message::{TcpReceiverMessage, TcpSenderMessage};
use crate::wrapping_integers::Wrap32;

pub const TCP_HEADER_MIN_LEN: usize = 20;

const TCP_FLAG_FIN: u16 = 0x001;
const TCP_FLAG_SYN: u16 = 0x002;
const TCP_FLAG_RST: u16 = 0x004;
const TCP_FLAG_ACK: u16 = 0x010;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seqno: Wrap32,
    pub ackno: Option<Wrap32>,
    pub window_size: u16,
    pub syn: bool,
    pub fin: bool,
    pub rst: bool,
}

impl TcpHeader {
    pub fn flags(&self) -> u16 {
        let mut flags = 0u16;

        if self.fin {
            flags |= TCP_FLAG_FIN;
        }

        if self.syn {
            flags |= TCP_FLAG_SYN;
        }

        if self.rst {
            flags |= TCP_FLAG_RST;
        }

        if self.ackno.is_some() {
            flags |= TCP_FLAG_ACK;
        }

        flags
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpSegment {
    pub header: TcpHeader,
    pub payload: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpParseError {
    SegmentTooShort,
    InvalidDataOffset,
    InvalidChecksum,
}

impl TcpSegment {
    pub fn new(header: TcpHeader, payload: Bytes) -> Self {
        Self { header, payload }
    }

    /// Build a wire TCP segment from a sender message and optional receiver
    /// feedback.
    ///
    /// TCP is full-duplex, so a segment carrying outbound data may also carry
    /// ACK/window information for inbound data.
    pub fn from_messages(
        src_port: u16,
        dst_port: u16,
        sender: &TcpSenderMessage,
        receiver: Option<TcpReceiverMessage>,
    ) -> Self {
        let ackno = receiver.and_then(|message| message.ackno);
        let window_size = receiver.map_or(0, |message| message.window_size);

        let rst = sender.rst || receiver.is_some_and(|message| message.rst);

        Self {
            header: TcpHeader {
                src_port,
                dst_port,
                seqno: sender.seqno,
                ackno,
                window_size,
                syn: sender.syn,
                fin: sender.fin,
                rst,
            },
            payload: sender.payload.clone(),
        }
    }

    pub fn to_sender_message(&self) -> TcpSenderMessage {
        TcpSenderMessage {
            seqno: self.header.seqno,
            syn: self.header.syn,
            payload: self.payload.clone(),
            fin: self.header.fin,
            rst: self.header.rst,
        }
    }

    pub fn to_receiver_message(&self) -> TcpReceiverMessage {
        TcpReceiverMessage {
            ackno: self.header.ackno,
            window_size: self.header.window_size,
            rst: self.header.rst,
        }
    }

    pub fn serialize_ipv4(&self, src_ip: [u8; 4], dst_ip: [u8; 4]) -> Bytes {
        let tcp_len = TCP_HEADER_MIN_LEN
            .checked_add(self.payload.len())
            .expect("TCP segment length overflow");

        assert!(
            tcp_len <= u16::MAX as usize,
            "TCP segment exceeds IPv4 pseudo-header length"
        );

        let mut buf = BytesMut::with_capacity(tcp_len);

        buf.put_u16(self.header.src_port);
        buf.put_u16(self.header.dst_port);
        buf.put_u32(self.header.seqno.raw_value());
        buf.put_u32(self.header.ackno.map_or(0, Wrap32::raw_value));

        let data_offset = 5u8;
        let offset_and_flags = ((data_offset as u16) << 12) | (self.header.flags() & 0x01ff);

        buf.put_u16(offset_and_flags);
        buf.put_u16(self.header.window_size);

        // TCP checksum placeholder.
        buf.put_u16(0);

        // Urgent pointer.
        buf.put_u16(0);

        debug_assert_eq!(buf.len(), TCP_HEADER_MIN_LEN);

        buf.extend_from_slice(&self.payload);

        let checksum = tcp_checksum_ipv4(src_ip, dst_ip, &buf);

        buf[16..18].copy_from_slice(&checksum.to_be_bytes());

        buf.freeze()
    }

    pub fn parse_ipv4(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        segment: &[u8],
    ) -> Result<Self, TcpParseError> {
        Self::parse_ipv4_bytes(src_ip, dst_ip, Bytes::copy_from_slice(segment))
    }

    pub fn parse_ipv4_bytes(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        segment: Bytes,
    ) -> Result<Self, TcpParseError> {
        if segment.len() < TCP_HEADER_MIN_LEN {
            return Err(TcpParseError::SegmentTooShort);
        }

        if tcp_checksum_ipv4(src_ip, dst_ip, &segment) != 0 {
            return Err(TcpParseError::InvalidChecksum);
        }

        let data_offset = segment[12] >> 4;
        let header_len = data_offset as usize * 4;

        if header_len < TCP_HEADER_MIN_LEN || header_len > segment.len() {
            return Err(TcpParseError::InvalidDataOffset);
        }

        let src_port = u16::from_be_bytes([segment[0], segment[1]]);
        let dst_port = u16::from_be_bytes([segment[2], segment[3]]);
        let seqno = Wrap32::new(u32::from_be_bytes([
            segment[4], segment[5], segment[6], segment[7],
        ]));

        let raw_ackno = u32::from_be_bytes([segment[8], segment[9], segment[10], segment[11]]);

        let offset_and_flags = u16::from_be_bytes([segment[12], segment[13]]);
        let flags = offset_and_flags & 0x01ff;

        let ackno = if (flags & TCP_FLAG_ACK) != 0 {
            Some(Wrap32::new(raw_ackno))
        } else {
            None
        };

        let window_size = u16::from_be_bytes([segment[14], segment[15]]);

        let header = TcpHeader {
            src_port,
            dst_port,
            seqno,
            ackno,
            window_size,
            syn: (flags & TCP_FLAG_SYN) != 0,
            fin: (flags & TCP_FLAG_FIN) != 0,
            rst: (flags & TCP_FLAG_RST) != 0,
        };

        let payload = segment.slice(header_len..);

        Ok(Self { header, payload })
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;

    fn sender_message() -> TcpSenderMessage {
        TcpSenderMessage {
            seqno: Wrap32::new(1_000),
            syn: true,
            payload: Bytes::from_static(b"abc"),
            fin: false,
            rst: false,
        }
    }

    #[test]
    fn tcp_segment_round_trip_with_syn_payload_and_ack() {
        let sender = sender_message();

        let receiver = TcpReceiverMessage {
            ackno: Some(Wrap32::new(9_001)),
            window_size: 4096,
            rst: false,
        };

        let segment = TcpSegment::from_messages(12345, 80, &sender, Some(receiver));

        let serialized = segment.serialize_ipv4([10, 0, 0, 1], [10, 0, 0, 2]);

        let parsed =
            TcpSegment::parse_ipv4_bytes([10, 0, 0, 1], [10, 0, 0, 2], serialized).unwrap();

        assert_eq!(parsed.header.src_port, 12345);
        assert_eq!(parsed.header.dst_port, 80);
        assert_eq!(parsed.header.seqno, Wrap32::new(1_000));
        assert_eq!(parsed.header.ackno, Some(Wrap32::new(9_001)));
        assert_eq!(parsed.header.window_size, 4096);
        assert!(parsed.header.syn);
        assert!(!parsed.header.fin);
        assert!(!parsed.header.rst);
        assert_eq!(parsed.payload, Bytes::from_static(b"abc"));

        assert_eq!(parsed.to_sender_message(), sender);
        assert_eq!(parsed.to_receiver_message(), receiver);
    }

    #[test]
    fn tcp_segment_round_trip_fin_without_ack() {
        let sender = TcpSenderMessage {
            seqno: Wrap32::new(77),
            syn: false,
            payload: Bytes::new(),
            fin: true,
            rst: false,
        };

        let segment = TcpSegment::from_messages(5000, 5001, &sender, None);

        let serialized = segment.serialize_ipv4([192, 168, 0, 1], [192, 168, 0, 2]);

        let parsed =
            TcpSegment::parse_ipv4_bytes([192, 168, 0, 1], [192, 168, 0, 2], serialized).unwrap();

        assert_eq!(parsed.header.seqno, Wrap32::new(77));
        assert_eq!(parsed.header.ackno, None);
        assert!(parsed.header.fin);
        assert!(!parsed.header.syn);
        assert_eq!(parsed.payload, Bytes::new());
    }

    #[test]
    fn tcp_checksum_rejects_wrong_pseudo_header() {
        let sender = sender_message();

        let segment = TcpSegment::from_messages(12345, 80, &sender, None);

        let serialized = segment.serialize_ipv4([10, 0, 0, 1], [10, 0, 0, 2]);

        let error =
            TcpSegment::parse_ipv4_bytes([10, 0, 0, 9], [10, 0, 0, 2], serialized).unwrap_err();

        assert_eq!(error, TcpParseError::InvalidChecksum);
    }

    #[test]
    fn tcp_parse_rejects_short_segment() {
        let error = TcpSegment::parse_ipv4([1, 1, 1, 1], [2, 2, 2, 2], &[0; 10]).unwrap_err();

        assert_eq!(error, TcpParseError::SegmentTooShort);
    }

    #[test]
    fn tcp_parse_rejects_invalid_data_offset() {
        let sender = sender_message();

        let segment = TcpSegment::from_messages(12345, 80, &sender, None);

        let mut serialized = segment
            .serialize_ipv4([10, 0, 0, 1], [10, 0, 0, 2])
            .to_vec();

        serialized[12] = 4 << 4;

        // Recompute checksum after corrupting data offset so the parser
        // reaches InvalidDataOffset instead of InvalidChecksum.
        serialized[16] = 0;
        serialized[17] = 0;

        let checksum =
            crate::checksum::tcp_checksum_ipv4([10, 0, 0, 1], [10, 0, 0, 2], &serialized);

        serialized[16..18].copy_from_slice(&checksum.to_be_bytes());

        let error = TcpSegment::parse_ipv4([10, 0, 0, 1], [10, 0, 0, 2], &serialized).unwrap_err();

        assert_eq!(error, TcpParseError::InvalidDataOffset);
    }

    #[test]
    fn rst_propagates_from_receiver_message() {
        let sender = TcpSenderMessage::new(Wrap32::new(100));

        let receiver = TcpReceiverMessage {
            ackno: Some(Wrap32::new(200)),
            window_size: 0,
            rst: true,
        };

        let segment = TcpSegment::from_messages(1, 2, &sender, Some(receiver));

        assert!(segment.header.rst);
    }
}
