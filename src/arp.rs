use bytes::{BufMut, Bytes, BytesMut};

use crate::ethernet_frame::{ETHERTYPE_IPV4, EthernetAddress};

pub const ARP_MESSAGE_LEN: usize = 28;

pub const ARP_HARDWARE_TYPE_ETHERNET: u16 = 1;

pub const ARP_PROTOCOL_TYPE_IPV4: u16 = ETHERTYPE_IPV4;

pub const ARP_HARDWARE_ADDRESS_LEN_ETHERNET: u8 = 6;

pub const ARP_PROTOCOL_ADDRESS_LEN_IPV4: u8 = 4;

pub const ARP_OPCODE_REQUEST: u16 = 1;

pub const ARP_OPCODE_REPLY: u16 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]

pub enum ArpOperation {
    Request,

    Reply,
}

impl ArpOperation {
    pub fn opcode(self) -> u16 {
        match self {
            Self::Request => ARP_OPCODE_REQUEST,

            Self::Reply => ARP_OPCODE_REPLY,
        }
    }

    pub fn from_opcode(opcode: u16) -> Option<Self> {
        match opcode {
            ARP_OPCODE_REQUEST => Some(Self::Request),

            ARP_OPCODE_REPLY => Some(Self::Reply),

            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]

pub struct ArpMessage {
    pub operation: ArpOperation,

    pub sender_ethernet_address: EthernetAddress,

    pub sender_ip_address: [u8; 4],

    pub target_ethernet_address: EthernetAddress,

    pub target_ip_address: [u8; 4],
}

#[derive(Debug, Clone, PartialEq, Eq)]

pub enum ArpParseError {
    MessageTooShort,

    UnsupportedHardwareType(u16),

    UnsupportedProtocolType(u16),

    UnsupportedHardwareAddressLength(u8),

    UnsupportedProtocolAddressLength(u8),

    UnsupportedOperation(u16),
}

impl ArpMessage {
    pub fn request(
        sender_ethernet_address: EthernetAddress,
        sender_ip_address: [u8; 4],
        target_ip_address: [u8; 4],
    ) -> Self {
        Self {
            operation: ArpOperation::Request,
            sender_ethernet_address,
            sender_ip_address,
            target_ethernet_address: EthernetAddress::ZERO,
            target_ip_address,
        }
    }

    pub fn reply(
        sender_ethernet_address: EthernetAddress,
        sender_ip_address: [u8; 4],
        target_ethernet_address: EthernetAddress,
        target_ip_address: [u8; 4],
    ) -> Self {
        Self {
            operation: ArpOperation::Reply,
            sender_ethernet_address,
            sender_ip_address,
            target_ethernet_address,
            target_ip_address,
        }
    }

    pub fn is_request(&self) -> bool {
        self.operation == ArpOperation::Request
    }

    pub fn is_reply(&self) -> bool {
        self.operation == ArpOperation::Reply
    }

    pub fn serialize(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(ARP_MESSAGE_LEN);

        buf.put_u16(ARP_HARDWARE_TYPE_ETHERNET);

        buf.put_u16(ARP_PROTOCOL_TYPE_IPV4);

        buf.put_u8(ARP_HARDWARE_ADDRESS_LEN_ETHERNET);

        buf.put_u8(ARP_PROTOCOL_ADDRESS_LEN_IPV4);

        buf.put_u16(self.operation.opcode());

        buf.extend_from_slice(&self.sender_ethernet_address.octets());

        buf.extend_from_slice(&self.sender_ip_address);

        buf.extend_from_slice(&self.target_ethernet_address.octets());

        buf.extend_from_slice(&self.target_ip_address);

        debug_assert_eq!(buf.len(), ARP_MESSAGE_LEN);

        buf.freeze()
    }

    pub fn parse(data: &[u8]) -> Result<Self, ArpParseError> {
        Self::parse_bytes(Bytes::copy_from_slice(data))
    }

    pub fn parse_bytes(data: Bytes) -> Result<Self, ArpParseError> {
        if data.len() < ARP_MESSAGE_LEN {
            return Err(ArpParseError::MessageTooShort);
        }

        let hardware_type = u16::from_be_bytes([data[0], data[1]]);

        let protocol_type = u16::from_be_bytes([data[2], data[3]]);

        let hardware_len = data[4];

        let protocol_len = data[5];

        let opcode = u16::from_be_bytes([data[6], data[7]]);

        if hardware_type != ARP_HARDWARE_TYPE_ETHERNET {
            return Err(ArpParseError::UnsupportedHardwareType(hardware_type));
        }

        if protocol_type != ARP_PROTOCOL_TYPE_IPV4 {
            return Err(ArpParseError::UnsupportedProtocolType(protocol_type));
        }

        if hardware_len != ARP_HARDWARE_ADDRESS_LEN_ETHERNET {
            return Err(ArpParseError::UnsupportedHardwareAddressLength(
                hardware_len,
            ));
        }

        if protocol_len != ARP_PROTOCOL_ADDRESS_LEN_IPV4 {
            return Err(ArpParseError::UnsupportedProtocolAddressLength(
                protocol_len,
            ));
        }

        let Some(operation) = ArpOperation::from_opcode(opcode) else {
            return Err(ArpParseError::UnsupportedOperation(opcode));
        };

        let sender_ethernet_address =
            EthernetAddress::new([data[8], data[9], data[10], data[11], data[12], data[13]]);

        let sender_ip_address = [data[14], data[15], data[16], data[17]];

        let target_ethernet_address =
            EthernetAddress::new([data[18], data[19], data[20], data[21], data[22], data[23]]);

        let target_ip_address = [data[24], data[25], data[26], data[27]];

        Ok(Self {
            operation,

            sender_ethernet_address,

            sender_ip_address,

            target_ethernet_address,

            target_ip_address,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac_a() -> EthernetAddress {
        EthernetAddress::new([0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01])
    }

    fn mac_b() -> EthernetAddress {
        EthernetAddress::new([0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x02])
    }

    #[test]

    fn arp_request_round_trip() {
        let request = ArpMessage::request(mac_a(), [169, 254, 144, 2], [169, 254, 144, 1]);

        let serialized = request.serialize();

        assert_eq!(serialized.len(), ARP_MESSAGE_LEN);

        assert_eq!(
            u16::from_be_bytes([serialized[0], serialized[1]]),
            ARP_HARDWARE_TYPE_ETHERNET
        );

        assert_eq!(
            u16::from_be_bytes([serialized[2], serialized[3]]),
            ARP_PROTOCOL_TYPE_IPV4
        );

        assert_eq!(serialized[4], 6);

        assert_eq!(serialized[5], 4);

        assert_eq!(
            u16::from_be_bytes([serialized[6], serialized[7]]),
            ARP_OPCODE_REQUEST
        );

        let parsed = ArpMessage::parse_bytes(serialized).unwrap();

        assert_eq!(parsed, request);

        assert!(parsed.is_request());

        assert!(!parsed.is_reply());

        assert_eq!(parsed.target_ethernet_address, EthernetAddress::ZERO);
    }

    #[test]

    fn arp_reply_round_trip() {
        let reply = ArpMessage::reply(mac_a(), [169, 254, 144, 1], mac_b(), [169, 254, 144, 2]);

        let parsed = ArpMessage::parse_bytes(reply.serialize()).unwrap();

        assert_eq!(parsed, reply);

        assert!(parsed.is_reply());

        assert!(!parsed.is_request());

        assert_eq!(parsed.sender_ethernet_address, mac_a());

        assert_eq!(parsed.target_ethernet_address, mac_b());
    }

    #[test]

    fn rejects_short_arp_message() {
        let error = ArpMessage::parse(&[0u8; 27]).unwrap_err();

        assert_eq!(error, ArpParseError::MessageTooShort);
    }

    #[test]

    fn rejects_unsupported_hardware_type() {
        let mut data = ArpMessage::request(mac_a(), [1, 1, 1, 1], [2, 2, 2, 2])
            .serialize()
            .to_vec();

        data[1] = 2;

        assert_eq!(
            ArpMessage::parse(&data).unwrap_err(),
            ArpParseError::UnsupportedHardwareType(2)
        );
    }

    #[test]

    fn rejects_unsupported_protocol_type() {
        let mut data = ArpMessage::request(mac_a(), [1, 1, 1, 1], [2, 2, 2, 2])
            .serialize()
            .to_vec();

        data[2..4].copy_from_slice(&0x86ddu16.to_be_bytes());

        assert_eq!(
            ArpMessage::parse(&data).unwrap_err(),
            ArpParseError::UnsupportedProtocolType(0x86dd)
        );
    }

    #[test]

    fn rejects_unsupported_opcode() {
        let mut data = ArpMessage::request(mac_a(), [1, 1, 1, 1], [2, 2, 2, 2])
            .serialize()
            .to_vec();

        data[6..8].copy_from_slice(&9u16.to_be_bytes());

        assert_eq!(
            ArpMessage::parse(&data).unwrap_err(),
            ArpParseError::UnsupportedOperation(9)
        );
    }
}
