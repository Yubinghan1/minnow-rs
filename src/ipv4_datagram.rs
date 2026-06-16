use bytes::{BufMut, Bytes, BytesMut};

use crate::checksum::{internet_checksum, verify_internet_checksum};

pub const IPV4_HEADER_MIN_LEN: usize = 20;
pub const IPV4_PROTOCOL_TCP: u8 = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv4AddrBytes(pub [u8; 4]);

impl Ipv4AddrBytes {
    pub const fn new(bytes: [u8; 4]) -> Self {
        Self(bytes)
    }

    pub const fn octets(self) -> [u8; 4] {
        self.0
    }
}

impl From<[u8; 4]> for Ipv4AddrBytes {
    fn from(value: [u8; 4]) -> Self {
        Self(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Header {
    pub src: Ipv4AddrBytes,
    pub dst: Ipv4AddrBytes,
    pub ttl: u8,
    pub protocol: u8,
    pub identification: u16,
    pub flags_fragment_offset: u16,
}

impl Ipv4Header {
    pub fn new_tcp(src: [u8; 4], dst: [u8; 4]) -> Self {
        Self {
            src: Ipv4AddrBytes::new(src),
            dst: Ipv4AddrBytes::new(dst),
            ttl: 64,
            protocol: IPV4_PROTOCOL_TCP,
            identification: 0,
            flags_fragment_offset: 0x4000, // don't fragment
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Datagram {
    pub header: Ipv4Header,
    pub payload: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ipv4ParseError {
    PacketTooShort,
    NotIpv4,
    InvalidHeaderLength,
    InvalidTotalLength,
    InvalidChecksum,
}

impl Ipv4Datagram {
    pub fn new_tcp(src: [u8; 4], dst: [u8; 4], payload: Bytes) -> Self {
        Self {
            header: Ipv4Header::new_tcp(src, dst),
            payload,
        }
    }

    pub fn serialize(&self) -> Bytes {
        let total_len = IPV4_HEADER_MIN_LEN
            .checked_add(self.payload.len())
            .expect("IPv4 total length overflow");

        assert!(
            total_len <= u16::MAX as usize,
            "IPv4 datagram exceeds maximum total length"
        );

        let mut buf = BytesMut::with_capacity(total_len);

        // Version = 4, IHL = 5.
        buf.put_u8((4 << 4) | 5);

        // DSCP/ECN.
        buf.put_u8(0);

        buf.put_u16(total_len as u16);
        buf.put_u16(self.header.identification);
        buf.put_u16(self.header.flags_fragment_offset);
        buf.put_u8(self.header.ttl);
        buf.put_u8(self.header.protocol);

        // Header checksum placeholder.
        buf.put_u16(0);

        buf.extend_from_slice(&self.header.src.octets());
        buf.extend_from_slice(&self.header.dst.octets());

        debug_assert_eq!(buf.len(), IPV4_HEADER_MIN_LEN);

        let checksum = internet_checksum(&buf[..IPV4_HEADER_MIN_LEN]);

        buf[10..12].copy_from_slice(&checksum.to_be_bytes());

        buf.extend_from_slice(&self.payload);

        buf.freeze()
    }

    pub fn parse(packet: &[u8]) -> Result<Self, Ipv4ParseError> {
        Self::parse_bytes(Bytes::copy_from_slice(packet))
    }

    pub fn parse_bytes(packet: Bytes) -> Result<Self, Ipv4ParseError> {
        if packet.len() < IPV4_HEADER_MIN_LEN {
            return Err(Ipv4ParseError::PacketTooShort);
        }

        let version = packet[0] >> 4;
        let ihl = packet[0] & 0x0f;

        if version != 4 {
            return Err(Ipv4ParseError::NotIpv4);
        }

        let header_len = ihl as usize * 4;

        if header_len < IPV4_HEADER_MIN_LEN || header_len > packet.len() {
            return Err(Ipv4ParseError::InvalidHeaderLength);
        }

        let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;

        if total_len < header_len || total_len > packet.len() {
            return Err(Ipv4ParseError::InvalidTotalLength);
        }

        if !verify_internet_checksum(&packet[..header_len]) {
            return Err(Ipv4ParseError::InvalidChecksum);
        }

        let header = Ipv4Header {
            identification: u16::from_be_bytes([packet[4], packet[5]]),
            flags_fragment_offset: u16::from_be_bytes([packet[6], packet[7]]),
            ttl: packet[8],
            protocol: packet[9],
            src: Ipv4AddrBytes::new([packet[12], packet[13], packet[14], packet[15]]),
            dst: Ipv4AddrBytes::new([packet[16], packet[17], packet[18], packet[19]]),
        };

        let payload = packet.slice(header_len..total_len);

        Ok(Self { header, payload })
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;

    #[test]
    fn ipv4_round_trip_tcp_payload() {
        let payload = Bytes::from_static(b"tcp bytes");

        let datagram =
            Ipv4Datagram::new_tcp([192, 168, 1, 10], [93, 184, 216, 34], payload.clone());

        let serialized = datagram.serialize();

        assert_eq!(serialized[0], 0x45);
        assert_eq!(
            u16::from_be_bytes([serialized[2], serialized[3]]) as usize,
            IPV4_HEADER_MIN_LEN + payload.len()
        );

        let parsed = Ipv4Datagram::parse_bytes(serialized).unwrap();

        assert_eq!(parsed.header.src.octets(), [192, 168, 1, 10]);
        assert_eq!(parsed.header.dst.octets(), [93, 184, 216, 34]);
        assert_eq!(parsed.header.protocol, IPV4_PROTOCOL_TCP);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn rejects_non_ipv4_packet() {
        let mut packet = Ipv4Datagram::new_tcp([1, 1, 1, 1], [2, 2, 2, 2], Bytes::new())
            .serialize()
            .to_vec();

        packet[0] = 0x65;

        assert_eq!(
            Ipv4Datagram::parse(&packet).unwrap_err(),
            Ipv4ParseError::NotIpv4
        );
    }

    #[test]
    fn rejects_bad_ipv4_checksum() {
        let mut packet = Ipv4Datagram::new_tcp([1, 1, 1, 1], [2, 2, 2, 2], Bytes::new())
            .serialize()
            .to_vec();

        packet[10] ^= 0xff;

        assert_eq!(
            Ipv4Datagram::parse(&packet).unwrap_err(),
            Ipv4ParseError::InvalidChecksum
        );
    }

    #[test]
    fn parse_allows_extra_trailing_bytes_but_respects_total_length() {
        let mut packet =
            Ipv4Datagram::new_tcp([10, 0, 0, 1], [10, 0, 0, 2], Bytes::from_static(b"abc"))
                .serialize()
                .to_vec();

        packet.extend_from_slice(b"trailing garbage");

        let parsed = Ipv4Datagram::parse(&packet).unwrap();

        assert_eq!(parsed.payload, Bytes::from_static(b"abc"));
    }

    #[test]
    fn rejects_invalid_total_length() {
        let mut packet =
            Ipv4Datagram::new_tcp([10, 0, 0, 1], [10, 0, 0, 2], Bytes::from_static(b"abc"))
                .serialize()
                .to_vec();

        packet[2..4].copy_from_slice(&10u16.to_be_bytes());

        // Need to recompute checksum to isolate total-length validation.
        packet[10] = 0;
        packet[11] = 0;
        let checksum = internet_checksum(&packet[..IPV4_HEADER_MIN_LEN]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());

        assert_eq!(
            Ipv4Datagram::parse(&packet).unwrap_err(),
            Ipv4ParseError::InvalidTotalLength
        );
    }
}
