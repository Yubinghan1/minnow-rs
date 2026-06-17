use bytes::{BufMut, Bytes, BytesMut};

use crate::checksum::{internet_checksum, verify_internet_checksum};

pub const ICMP_ECHO_REPLY: u8 = 0;
pub const ICMP_ECHO_REQUEST: u8 = 8;

const ICMP_ECHO_HEADER_LEN: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpMessage {
    pub icmp_type: u8,
    pub code: u8,
    pub identifier: u16,
    pub sequence_number: u16,
    pub payload: Bytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpParseError {
    MessageTooShort,
    InvalidChecksum,
}

impl IcmpMessage {
    pub fn echo_request(identifier: u16, sequence_number: u16, payload: Bytes) -> Self {
        Self {
            icmp_type: ICMP_ECHO_REQUEST,
            code: 0,
            identifier,
            sequence_number,
            payload,
        }
    }

    pub fn echo_reply_from_request(request: &Self) -> Option<Self> {
        if request.icmp_type != ICMP_ECHO_REQUEST || request.code != 0 {
            return None;
        }

        Some(Self {
            icmp_type: ICMP_ECHO_REPLY,
            code: 0,
            identifier: request.identifier,
            sequence_number: request.sequence_number,
            payload: request.payload.clone(),
        })
    }

    pub fn parse_bytes(bytes: Bytes) -> Result<Self, IcmpParseError> {
        if bytes.len() < ICMP_ECHO_HEADER_LEN {
            return Err(IcmpParseError::MessageTooShort);
        }

        if !verify_internet_checksum(&bytes) {
            return Err(IcmpParseError::InvalidChecksum);
        }

        Ok(Self {
            icmp_type: bytes[0],
            code: bytes[1],
            identifier: u16::from_be_bytes([bytes[4], bytes[5]]),
            sequence_number: u16::from_be_bytes([bytes[6], bytes[7]]),
            payload: bytes.slice(ICMP_ECHO_HEADER_LEN..),
        })
    }

    pub fn serialize(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(ICMP_ECHO_HEADER_LEN + self.payload.len());

        buf.put_u8(self.icmp_type);
        buf.put_u8(self.code);
        buf.put_u16(0);
        buf.put_u16(self.identifier);
        buf.put_u16(self.sequence_number);
        buf.extend_from_slice(&self.payload);

        let checksum = internet_checksum(&buf);
        buf[2..4].copy_from_slice(&checksum.to_be_bytes());

        buf.freeze()
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;

    #[test]
    fn echo_request_round_trips() {
        let request = IcmpMessage::echo_request(0x1234, 7, Bytes::from_static(b"hello"));

        let parsed = IcmpMessage::parse_bytes(request.serialize()).unwrap();

        assert_eq!(parsed, request);
    }

    #[test]
    fn echo_reply_preserves_id_sequence_and_payload() {
        let request = IcmpMessage::echo_request(0xabcd, 42, Bytes::from_static(b"payload"));

        let reply = IcmpMessage::echo_reply_from_request(&request).unwrap();

        assert_eq!(reply.icmp_type, ICMP_ECHO_REPLY);
        assert_eq!(reply.code, 0);
        assert_eq!(reply.identifier, request.identifier);
        assert_eq!(reply.sequence_number, request.sequence_number);
        assert_eq!(reply.payload, request.payload);
        assert!(IcmpMessage::parse_bytes(reply.serialize()).is_ok());
    }

    #[test]
    fn parse_rejects_bad_checksum() {
        let mut bytes = IcmpMessage::echo_request(1, 1, Bytes::from_static(b"x"))
            .serialize()
            .to_vec();
        bytes[8] ^= 0xff;

        assert_eq!(
            IcmpMessage::parse_bytes(Bytes::from(bytes)),
            Err(IcmpParseError::InvalidChecksum)
        );
    }
}
