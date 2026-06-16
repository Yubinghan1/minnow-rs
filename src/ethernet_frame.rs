use std::fmt;

use bytes::{BufMut, Bytes, BytesMut};

pub const ETHERNET_HEADER_LEN: usize = 14;

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct EthernetAddress(pub [u8; 6]);

impl EthernetAddress {
    pub const BROADCAST: Self = Self([0xFF; 6]);
    pub const ZERO: Self = Self([0; 6]);

    pub const fn new(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }

    pub const fn octets(self) -> [u8; 6] {
        self.0
    }

    pub fn is_broadcast(self) -> bool {
        self == Self::BROADCAST
    }
}

impl fmt::Debug for EthernetAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let octets = self.octets();
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            octets[0], octets[1], octets[2], octets[3], octets[4], octets[5]
        )
    }
}

impl fmt::Display for EthernetAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl From<[u8; 6]> for EthernetAddress {
    fn from(value: [u8; 6]) -> Self {
        Self(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EthernetHeader {
    pub dst: EthernetAddress,
    pub src: EthernetAddress,
    pub ethertype: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthernetFrame {
    pub header: EthernetHeader,
    pub payload: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EthernetParseError {
    FrameTooShort,
}

impl EthernetFrame {
    pub fn new(dst: EthernetAddress, src: EthernetAddress, ethertype: u16, payload: Bytes) -> Self {
        Self {
            header: EthernetHeader {
                dst,
                src,
                ethertype,
            },
            payload,
        }
    }

    pub fn ipv4(dst: EthernetAddress, src: EthernetAddress, payload: Bytes) -> Self {
        Self::new(dst, src, ETHERTYPE_IPV4, payload)
    }

    pub fn arp(dst: EthernetAddress, src: EthernetAddress, payload: Bytes) -> Self {
        Self::new(dst, src, ETHERTYPE_ARP, payload)
    }

    pub fn is_for(&self, ethernet_address: EthernetAddress) -> bool {
        self.header.dst == ethernet_address || self.header.dst.is_broadcast()
    }

    pub fn serialize(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(ETHERNET_HEADER_LEN + self.payload.len());

        buf.put_slice(&self.header.dst.octets());
        buf.put_slice(&self.header.src.octets());
        buf.put_u16(self.header.ethertype);
        buf.put_slice(&self.payload);

        buf.freeze()
    }

    pub fn parse(data: &[u8]) -> Result<Self, EthernetParseError> {
        Self::parse_bytes(Bytes::copy_from_slice(data))
    }

    pub fn parse_bytes(data: Bytes) -> Result<Self, EthernetParseError> {
        if data.len() < ETHERNET_HEADER_LEN {
            return Err(EthernetParseError::FrameTooShort);
        }

        let dst = EthernetAddress::new([data[0], data[1], data[2], data[3], data[4], data[5]]);

        let src = EthernetAddress::new([data[6], data[7], data[8], data[9], data[10], data[11]]);

        let ethertype = u16::from_be_bytes([data[12], data[13]]);

        let payload = data.slice(ETHERNET_HEADER_LEN..);

        Ok(Self {
            header: EthernetHeader {
                dst,
                src,
                ethertype,
            },
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;

    fn mac_a() -> EthernetAddress {
        EthernetAddress::new([0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01])
    }

    fn mac_b() -> EthernetAddress {
        EthernetAddress::new([0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x02])
    }

    #[test]
    fn ethernet_address_debug_and_display() {
        let mac = mac_a();

        assert_eq!(format!("{mac:?}"), "02:aa:bb:cc:dd:01");

        assert_eq!(format!("{mac}"), "02:aa:bb:cc:dd:01");
    }

    #[test]
    fn ethernet_ipv4_round_trip() {
        let frame = EthernetFrame::ipv4(mac_b(), mac_a(), Bytes::from_static(b"ipv4-payload"));

        let serialized = frame.serialize();

        assert_eq!(serialized.len(), ETHERNET_HEADER_LEN + 12);
        assert_eq!(&serialized[0..6], &mac_b().octets());
        assert_eq!(&serialized[6..12], &mac_a().octets());
        assert_eq!(
            u16::from_be_bytes([serialized[12], serialized[13]]),
            ETHERTYPE_IPV4
        );

        let parsed = EthernetFrame::parse_bytes(serialized).unwrap();

        assert_eq!(parsed, frame);
    }

    #[test]
    fn ethernet_arp_round_trip() {
        let frame = EthernetFrame::arp(
            EthernetAddress::BROADCAST,
            mac_a(),
            Bytes::from_static(b"arp-payload"),
        );

        let parsed = EthernetFrame::parse_bytes(frame.serialize()).unwrap();

        assert_eq!(parsed.header.dst, EthernetAddress::BROADCAST);
        assert_eq!(parsed.header.src, mac_a());
        assert_eq!(parsed.header.ethertype, ETHERTYPE_ARP);
        assert_eq!(parsed.payload, Bytes::from_static(b"arp-payload"));
    }

    #[test]
    fn rejects_short_frame() {
        let error = EthernetFrame::parse(&[0u8; 13]).unwrap_err();

        assert_eq!(error, EthernetParseError::FrameTooShort);
    }

    #[test]
    fn frame_destination_filter() {
        let mine = mac_a();

        let unicast_to_me = EthernetFrame::ipv4(mine, mac_b(), Bytes::new());

        let broadcast = EthernetFrame::ipv4(EthernetAddress::BROADCAST, mac_b(), Bytes::new());

        let other = EthernetFrame::ipv4(mac_b(), mine, Bytes::new());

        assert!(unicast_to_me.is_for(mine));
        assert!(broadcast.is_for(mine));
        assert!(!other.is_for(mine));
    }
}
