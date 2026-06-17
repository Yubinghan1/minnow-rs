use bytes::Bytes;
use minnow_rs::arp::{ArpMessage, ArpOperation};
use minnow_rs::ethernet_frame::{ETHERTYPE_ARP, ETHERTYPE_IPV4, EthernetAddress, EthernetFrame};
use minnow_rs::icmp::{ICMP_ECHO_REPLY, IcmpMessage};
use minnow_rs::ip_host::{IpHost, IpHostConfig, IpHostEvent};
use minnow_rs::ipv4_datagram::{Ipv4AddrBytes, Ipv4Datagram};
use minnow_rs::network_interface::NetworkInterface;
use minnow_rs::tcp_segment::{TcpHeader, TcpSegment};
use minnow_rs::wrapping_integers::Wrap32;

const LOCAL_IP: [u8; 4] = [169, 254, 144, 2];
const PEER_IP: [u8; 4] = [169, 254, 144, 1];
const LOCAL_PORT: u16 = 50_000;
const PEER_PORT: u16 = 9_090;
const LOCAL_ISN: u32 = 1_000;
const PEER_ISN: u32 = 9_000;

fn local_mac() -> EthernetAddress {
    EthernetAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x02])
}

fn peer_mac() -> EthernetAddress {
    EthernetAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
}

fn iface() -> NetworkInterface {
    NetworkInterface::new(local_mac(), Ipv4AddrBytes::new(LOCAL_IP))
}

fn host() -> IpHost {
    IpHost::new(IpHostConfig::tcp_demo(
        LOCAL_IP,
        PEER_IP,
        LOCAL_PORT,
        PEER_PORT,
        Wrap32::new(LOCAL_ISN),
    ))
}

fn peer_arp_reply() -> EthernetFrame {
    EthernetFrame::arp(
        local_mac(),
        peer_mac(),
        ArpMessage::reply(peer_mac(), PEER_IP, local_mac(), LOCAL_IP).serialize(),
    )
}

fn parse_tcp(datagram: &Ipv4Datagram) -> TcpSegment {
    TcpSegment::parse_ipv4_bytes(
        datagram.header.src.octets(),
        datagram.header.dst.octets(),
        datagram.payload.clone(),
    )
    .expect("outgoing datagram should contain a valid TCP segment")
}

fn peer_tcp_segment(seqno: u32, ackno: Option<u32>, syn: bool, payload: Bytes) -> Ipv4Datagram {
    let segment = TcpSegment::new(
        TcpHeader {
            src_port: PEER_PORT,
            dst_port: LOCAL_PORT,
            seqno: Wrap32::new(seqno),
            ackno: ackno.map(Wrap32::new),
            window_size: 4096,
            syn,
            fin: false,
            rst: false,
        },
        payload,
    );

    Ipv4Datagram::new_tcp(PEER_IP, LOCAL_IP, segment.serialize_ipv4(PEER_IP, LOCAL_IP))
}

#[test]
fn arp_resolution_releases_queued_ipv4_datagram_as_ethernet_frame() {
    let mut iface = iface();
    let datagram = Ipv4Datagram::new_tcp(LOCAL_IP, PEER_IP, Bytes::from_static(b"tcp payload"));

    iface.send_datagram(datagram.clone(), Ipv4AddrBytes::new(PEER_IP));

    let request_frame = iface
        .pop_frame()
        .expect("unknown next hop should trigger an ARP request");
    assert_eq!(request_frame.header.dst, EthernetAddress::BROADCAST);
    assert_eq!(request_frame.header.src, local_mac());
    assert_eq!(request_frame.header.ethertype, ETHERTYPE_ARP);

    let request = ArpMessage::parse_bytes(request_frame.payload).unwrap();
    assert_eq!(request.operation, ArpOperation::Request);
    assert_eq!(request.sender_ethernet_address, local_mac());
    assert_eq!(request.sender_ip_address, LOCAL_IP);
    assert_eq!(request.target_ip_address, PEER_IP);
    assert_eq!(iface.pending_len(), 1);

    iface.recv_frame(peer_arp_reply());

    assert_eq!(iface.pending_len(), 0);
    assert_eq!(
        iface.lookup_ethernet_address(Ipv4AddrBytes::new(PEER_IP)),
        Some(peer_mac())
    );

    let ipv4_frame = iface
        .pop_frame()
        .expect("ARP reply should release the queued IPv4 datagram");
    assert_eq!(ipv4_frame.header.dst, peer_mac());
    assert_eq!(ipv4_frame.header.src, local_mac());
    assert_eq!(ipv4_frame.header.ethertype, ETHERTYPE_IPV4);

    let parsed = Ipv4Datagram::parse_bytes(ipv4_frame.payload).unwrap();
    assert_eq!(parsed, datagram);
}

#[test]
fn tap_style_arp_and_icmp_echo_flow_round_trips_through_stack() {
    let mut iface = iface();
    let mut host = host();

    let arp_request = EthernetFrame::arp(
        EthernetAddress::BROADCAST,
        peer_mac(),
        ArpMessage::request(peer_mac(), PEER_IP, LOCAL_IP).serialize(),
    );

    iface.recv_frame(arp_request);

    let arp_reply_frame = iface
        .pop_frame()
        .expect("ARP request for the local IP should produce a reply");
    assert_eq!(arp_reply_frame.header.dst, peer_mac());
    assert_eq!(arp_reply_frame.header.src, local_mac());
    assert_eq!(arp_reply_frame.header.ethertype, ETHERTYPE_ARP);

    let arp_reply = ArpMessage::parse_bytes(arp_reply_frame.payload).unwrap();
    assert_eq!(arp_reply.operation, ArpOperation::Reply);
    assert_eq!(arp_reply.sender_ethernet_address, local_mac());
    assert_eq!(arp_reply.sender_ip_address, LOCAL_IP);
    assert_eq!(arp_reply.target_ethernet_address, peer_mac());
    assert_eq!(arp_reply.target_ip_address, PEER_IP);

    let echo_request = IcmpMessage::echo_request(0x1234, 7, Bytes::from_static(b"hello minnow"));
    let request_datagram = Ipv4Datagram::new_icmp(PEER_IP, LOCAL_IP, echo_request.serialize());
    let request_frame = EthernetFrame::ipv4(local_mac(), peer_mac(), request_datagram.serialize());

    iface.recv_frame(request_frame);
    let inbound = iface
        .pop_datagram()
        .expect("IPv4 frame for the interface should be delivered upward");
    let host_output = host.receive_datagram(inbound);

    assert_eq!(host_output.datagrams.len(), 1);
    assert!(host_output.events.iter().any(|event| {
        matches!(
            event,
            IpHostEvent::IcmpEchoRequest {
                identifier: 0x1234,
                sequence_number: 7,
                payload_len: 12,
                ..
            }
        )
    }));
    assert!(host_output.events.iter().any(|event| {
        matches!(
            event,
            IpHostEvent::IcmpEchoReply {
                identifier: 0x1234,
                sequence_number: 7,
                payload_len: 12,
                ..
            }
        )
    }));

    iface.send_datagram(
        host_output.datagrams[0].clone(),
        Ipv4AddrBytes::new(PEER_IP),
    );

    let reply_frame = iface
        .pop_frame()
        .expect("learned ARP entry should send ICMP reply immediately");
    assert_eq!(reply_frame.header.dst, peer_mac());
    assert_eq!(reply_frame.header.src, local_mac());
    assert_eq!(reply_frame.header.ethertype, ETHERTYPE_IPV4);

    let reply_datagram = Ipv4Datagram::parse_bytes(reply_frame.payload).unwrap();
    assert_eq!(reply_datagram.header.src.octets(), LOCAL_IP);
    assert_eq!(reply_datagram.header.dst.octets(), PEER_IP);

    let reply = IcmpMessage::parse_bytes(reply_datagram.payload).unwrap();
    assert_eq!(reply.icmp_type, ICMP_ECHO_REPLY);
    assert_eq!(reply.identifier, 0x1234);
    assert_eq!(reply.sequence_number, 7);
    assert_eq!(reply.payload, Bytes::from_static(b"hello minnow"));
}

#[test]
fn tcp_host_completes_handshake_and_acks_peer_payload() {
    let mut host = host();

    let connect_output = host.connect();
    assert_eq!(connect_output.datagrams.len(), 1);

    let syn = parse_tcp(&connect_output.datagrams[0]);
    assert_eq!(syn.header.src_port, LOCAL_PORT);
    assert_eq!(syn.header.dst_port, PEER_PORT);
    assert_eq!(syn.header.seqno, Wrap32::new(LOCAL_ISN));
    assert!(syn.header.syn);
    assert!(syn.header.ackno.is_none());

    let syn_ack = peer_tcp_segment(PEER_ISN, Some(LOCAL_ISN + 1), true, Bytes::new());
    let ack_output = host.receive_datagram(syn_ack);

    assert!(host.is_established());
    assert_eq!(ack_output.datagrams.len(), 1);

    let ack = parse_tcp(&ack_output.datagrams[0]);
    assert!(!ack.header.syn);
    assert_eq!(ack.header.ackno, Some(Wrap32::new(PEER_ISN + 1)));
    assert!(ack.payload.is_empty());

    let peer_data = peer_tcp_segment(
        PEER_ISN + 1,
        Some(LOCAL_ISN + 1),
        false,
        Bytes::from_static(b"pong"),
    );
    let data_output = host.receive_datagram(peer_data);

    assert_eq!(data_output.datagrams.len(), 1);
    assert!(data_output.events.iter().any(|event| {
        matches!(event, IpHostEvent::TcpPayload(payload) if payload == &Bytes::from_static(b"pong"))
    }));

    let data_ack = parse_tcp(&data_output.datagrams[0]);
    assert_eq!(data_ack.header.ackno, Some(Wrap32::new(PEER_ISN + 5)));
    assert!(data_ack.payload.is_empty());
}
