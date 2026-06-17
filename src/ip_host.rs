use bytes::Bytes;

use crate::icmp::IcmpMessage;
use crate::ipv4_datagram::{IPV4_PROTOCOL_ICMP, IPV4_PROTOCOL_TCP, Ipv4Datagram};
use crate::tcp_connection::{TcpConnection, TcpConnectionConfig};
use crate::tcp_segment::TcpSegment;
use crate::tcp_sender::TcpSenderConfig;
use crate::wrapping_integers::Wrap32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpHostConfig {
    pub local_ip: [u8; 4],
    pub peer_ip: [u8; 4],
    pub local_port: u16,
    pub peer_port: u16,
    pub sender_capacity: usize,
    pub receiver_capacity: usize,
    pub isn: Wrap32,
    pub sender_config: TcpSenderConfig,
}

impl IpHostConfig {
    pub fn tcp_demo(
        local_ip: [u8; 4],
        peer_ip: [u8; 4],
        local_port: u16,
        peer_port: u16,
        isn: Wrap32,
    ) -> Self {
        Self {
            local_ip,
            peer_ip,
            local_port,
            peer_port,
            sender_capacity: 64 * 1024,
            receiver_capacity: 64 * 1024,
            isn,
            sender_config: TcpSenderConfig {
                initial_rto_ms: 1_000,
                max_timer_interval_ms: 60_000,
                max_payload_size: 1_000,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpHostEvent {
    IncomingTcp(TcpSegment),
    OutgoingTcp(TcpSegment),
    TcpPayload(Bytes),
    IcmpEchoRequest {
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        identifier: u16,
        sequence_number: u16,
        payload_len: usize,
    },
    IcmpEchoReply {
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        identifier: u16,
        sequence_number: u16,
        payload_len: usize,
    },
    IgnoredMalformedIpv4(String),
    IgnoredMalformedTcp(String),
    IgnoredMalformedIcmp(String),
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct IpHostOutput {
    pub datagrams: Vec<Ipv4Datagram>,
    pub events: Vec<IpHostEvent>,
}

#[derive(Debug)]
pub struct IpHost {
    config: IpHostConfig,
    connection: TcpConnection,
}

impl IpHost {
    pub fn new(config: IpHostConfig) -> Self {
        let connection = TcpConnection::new(TcpConnectionConfig::new(
            config.local_port,
            config.peer_port,
            config.sender_capacity,
            config.receiver_capacity,
            config.isn,
            config.sender_config,
        ));

        Self { config, connection }
    }

    pub fn local_ip(&self) -> [u8; 4] {
        self.config.local_ip
    }

    pub fn peer_ip(&self) -> [u8; 4] {
        self.config.peer_ip
    }

    pub fn local_port(&self) -> u16 {
        self.config.local_port
    }

    pub fn peer_port(&self) -> u16 {
        self.config.peer_port
    }

    pub fn is_established(&self) -> bool {
        self.connection.is_established()
    }

    pub fn is_finished(&self) -> bool {
        self.connection.is_finished()
    }

    pub fn connect(&mut self) -> IpHostOutput {
        let segments = self.connection.connect();

        self.wrap_tcp_segments(segments)
    }

    pub fn write(&mut self, data: Bytes) -> (usize, IpHostOutput) {
        let (accepted, segments) = self.connection.write(data);

        (accepted, self.wrap_tcp_segments(segments))
    }

    pub fn close(&mut self) -> IpHostOutput {
        let segments = self.connection.close();

        self.wrap_tcp_segments(segments)
    }

    pub fn tick(&mut self, elapsed_ms: u64) -> IpHostOutput {
        let segments = self.connection.tick(elapsed_ms);

        self.wrap_tcp_segments(segments)
    }

    pub fn receive_ipv4_bytes(&mut self, packet: Bytes) -> IpHostOutput {
        match Ipv4Datagram::parse_bytes(packet) {
            Ok(datagram) => self.receive_datagram(datagram),
            Err(err) => IpHostOutput {
                datagrams: Vec::new(),
                events: vec![IpHostEvent::IgnoredMalformedIpv4(format!("{err:?}"))],
            },
        }
    }

    pub fn receive_datagram(&mut self, datagram: Ipv4Datagram) -> IpHostOutput {
        let src_ip = datagram.header.src.octets();
        let dst_ip = datagram.header.dst.octets();

        if dst_ip != self.config.local_ip {
            return IpHostOutput::default();
        }

        match datagram.header.protocol {
            IPV4_PROTOCOL_ICMP => self.receive_icmp(src_ip, dst_ip, datagram.payload),
            IPV4_PROTOCOL_TCP if src_ip == self.config.peer_ip => {
                self.receive_tcp(src_ip, dst_ip, datagram.payload)
            }
            _ => IpHostOutput::default(),
        }
    }

    fn receive_icmp(&mut self, src_ip: [u8; 4], dst_ip: [u8; 4], payload: Bytes) -> IpHostOutput {
        let message = match IcmpMessage::parse_bytes(payload) {
            Ok(message) => message,
            Err(err) => {
                return IpHostOutput {
                    datagrams: Vec::new(),
                    events: vec![IpHostEvent::IgnoredMalformedIcmp(format!("{err:?}"))],
                };
            }
        };

        let mut output = IpHostOutput::default();

        let Some(reply) = IcmpMessage::echo_reply_from_request(&message) else {
            return output;
        };

        output.events.push(IpHostEvent::IcmpEchoRequest {
            src_ip,
            dst_ip,
            identifier: message.identifier,
            sequence_number: message.sequence_number,
            payload_len: message.payload.len(),
        });
        output.events.push(IpHostEvent::IcmpEchoReply {
            src_ip: dst_ip,
            dst_ip: src_ip,
            identifier: reply.identifier,
            sequence_number: reply.sequence_number,
            payload_len: reply.payload.len(),
        });
        output
            .datagrams
            .push(Ipv4Datagram::new_icmp(dst_ip, src_ip, reply.serialize()));

        output
    }

    fn receive_tcp(&mut self, src_ip: [u8; 4], dst_ip: [u8; 4], payload: Bytes) -> IpHostOutput {
        let segment = match TcpSegment::parse_ipv4_bytes(src_ip, dst_ip, payload) {
            Ok(segment) => segment,
            Err(err) => {
                return IpHostOutput {
                    datagrams: Vec::new(),
                    events: vec![IpHostEvent::IgnoredMalformedTcp(format!("{err:?}"))],
                };
            }
        };

        if segment.header.src_port != self.connection.peer_port()
            || segment.header.dst_port != self.connection.local_port()
        {
            return IpHostOutput::default();
        }

        let mut output = IpHostOutput::default();

        output
            .events
            .push(IpHostEvent::IncomingTcp(segment.clone()));

        if !segment.payload.is_empty() {
            output
                .events
                .push(IpHostEvent::TcpPayload(segment.payload.clone()));
        }

        let responses = self.connection.receive_segment(segment);

        output.extend(self.wrap_tcp_segments(responses));

        output
    }

    fn wrap_tcp_segments(&self, segments: Vec<TcpSegment>) -> IpHostOutput {
        let mut output = IpHostOutput::default();

        for segment in segments {
            let tcp_bytes = segment.serialize_ipv4(self.config.local_ip, self.config.peer_ip);

            output.events.push(IpHostEvent::OutgoingTcp(segment));
            output.datagrams.push(Ipv4Datagram::new_tcp(
                self.config.local_ip,
                self.config.peer_ip,
                tcp_bytes,
            ));
        }

        output
    }
}

impl IpHostOutput {
    pub fn extend(&mut self, other: Self) {
        self.datagrams.extend(other.datagrams);
        self.events.extend(other.events);
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;
    use crate::icmp::{ICMP_ECHO_REPLY, IcmpMessage};

    fn host() -> IpHost {
        IpHost::new(IpHostConfig::tcp_demo(
            [169, 254, 144, 2],
            [169, 254, 144, 1],
            50_000,
            9_090,
            Wrap32::new(1),
        ))
    }

    #[test]
    fn replies_to_icmp_echo_request_for_local_ip() {
        let request = IcmpMessage::echo_request(7, 11, Bytes::from_static(b"hello"));
        let datagram =
            Ipv4Datagram::new_icmp([169, 254, 144, 1], [169, 254, 144, 2], request.serialize());

        let mut host = host();
        let output = host.receive_datagram(datagram);

        assert_eq!(output.datagrams.len(), 1);
        assert_eq!(output.datagrams[0].header.src.octets(), [169, 254, 144, 2]);
        assert_eq!(output.datagrams[0].header.dst.octets(), [169, 254, 144, 1]);

        let reply = IcmpMessage::parse_bytes(output.datagrams[0].payload.clone()).unwrap();

        assert_eq!(reply.icmp_type, ICMP_ECHO_REPLY);
        assert_eq!(reply.identifier, 7);
        assert_eq!(reply.sequence_number, 11);
        assert_eq!(reply.payload, Bytes::from_static(b"hello"));
    }

    #[test]
    fn ignores_datagram_for_other_ip() {
        let request = IcmpMessage::echo_request(7, 11, Bytes::new());
        let datagram =
            Ipv4Datagram::new_icmp([169, 254, 144, 1], [10, 0, 0, 99], request.serialize());

        let mut host = host();
        let output = host.receive_datagram(datagram);

        assert!(output.datagrams.is_empty());
        assert!(output.events.is_empty());
    }
}
