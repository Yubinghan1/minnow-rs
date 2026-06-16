use std::collections::{HashMap, VecDeque};

use crate::arp::{ArpMessage, ArpOperation};
use crate::ethernet_frame::{ETHERTYPE_ARP, ETHERTYPE_IPV4, EthernetAddress, EthernetFrame};
use crate::ipv4_datagram::{Ipv4AddrBytes, Ipv4Datagram};

pub const ARP_CACHE_TTL_MS: u64 = 30_000;
pub const ARP_REQUEST_COOLDOWN_MS: u64 = 5_000;
pub const PENDING_DATAGRAM_TTL_MS: u64 = 5_000;

#[derive(Debug, Clone)]
struct ArpCacheEntry {
    ethernet_address: EthernetAddress,
    age_ms: u64,
}

#[derive(Debug, Clone)]
struct PendingResolution {
    datagrams: VecDeque<Ipv4Datagram>,
    age_ms: u64,
    request_age_ms: u64,
}

impl PendingResolution {
    fn new() -> Self {
        Self {
            datagrams: VecDeque::new(),
            age_ms: 0,
            request_age_ms: ARP_REQUEST_COOLDOWN_MS,
        }
    }

    fn should_send_arp_request(&self) -> bool {
        self.request_age_ms >= ARP_REQUEST_COOLDOWN_MS
    }

    fn mark_request_sent(&mut self) {
        self.request_age_ms = 0;
    }

    fn tick(&mut self, elapsed_ms: u64) {
        self.age_ms = self.age_ms.saturating_add(elapsed_ms);
        self.request_age_ms = self.request_age_ms.saturating_add(elapsed_ms);
    }

    fn is_expired(&self) -> bool {
        self.age_ms >= PENDING_DATAGRAM_TTL_MS
    }
}

#[derive(Debug)]
pub struct NetworkInterface {
    ethernet_address: EthernetAddress,
    ip_address: Ipv4AddrBytes,

    arp_cache: HashMap<Ipv4AddrBytes, ArpCacheEntry>,
    pending: HashMap<Ipv4AddrBytes, PendingResolution>,

    frames_out: VecDeque<EthernetFrame>,
    datagrams_in: VecDeque<Ipv4Datagram>,
}

impl NetworkInterface {
    pub fn new(ethernet_address: EthernetAddress, ip_address: Ipv4AddrBytes) -> Self {
        Self {
            ethernet_address,
            ip_address,
            arp_cache: HashMap::new(),
            pending: HashMap::new(),
            frames_out: VecDeque::new(),
            datagrams_in: VecDeque::new(),
        }
    }

    pub fn ethernet_address(&self) -> EthernetAddress {
        self.ethernet_address
    }

    pub fn ip_address(&self) -> Ipv4AddrBytes {
        self.ip_address
    }

    pub fn frames_out_len(&self) -> usize {
        self.frames_out.len()
    }

    pub fn datagrams_in_len(&self) -> usize {
        self.datagrams_in.len()
    }

    pub fn arp_cache_len(&self) -> usize {
        self.arp_cache.len()
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub fn has_arp_cache_entry(&self, ip: Ipv4AddrBytes) -> bool {
        self.arp_cache.contains_key(&ip)
    }

    pub fn lookup_ethernet_address(&self, ip: Ipv4AddrBytes) -> Option<EthernetAddress> {
        self.arp_cache.get(&ip).map(|entry| entry.ethernet_address)
    }

    pub fn pop_frame(&mut self) -> Option<EthernetFrame> {
        self.frames_out.pop_front()
    }

    pub fn pop_datagram(&mut self) -> Option<Ipv4Datagram> {
        self.datagrams_in.pop_front()
    }

    /// Send an IPv4 datagram to the next hop.
    ///
    /// If the next-hop Ethernet address is cached, this immediately emits an
    /// IPv4 Ethernet frame.
    ///
    /// If the next-hop Ethernet address is unknown, this queues the datagram
    /// and sends at most one ARP request per 5 seconds for that next hop.
    pub fn send_datagram(&mut self, datagram: Ipv4Datagram, next_hop: Ipv4AddrBytes) {
        if let Some(ethernet_address) = self.lookup_ethernet_address(next_hop) {
            self.emit_ipv4_frame(datagram, ethernet_address);
            return;
        }

        let pending = self
            .pending
            .entry(next_hop)
            .or_insert_with(PendingResolution::new);

        pending.datagrams.push_back(datagram);

        if pending.should_send_arp_request() {
            pending.mark_request_sent();

            self.emit_arp_request(next_hop);
        }
    }

    /// Receive one Ethernet frame.
    ///
    /// Frames not addressed to this interface or to Ethernet broadcast are
    /// ignored.
    ///
    /// IPv4 frames are parsed into datagrams and queued for the upper layer.
    ///
    /// ARP frames are used to learn IP->Ethernet mappings. ARP requests for
    /// this interface's IP receive an ARP reply.
    pub fn recv_frame(&mut self, frame: EthernetFrame) {
        if !frame.is_for(self.ethernet_address) {
            return;
        }

        match frame.header.ethertype {
            ETHERTYPE_IPV4 => {
                if let Ok(datagram) = Ipv4Datagram::parse_bytes(frame.payload.clone()) {
                    self.datagrams_in.push_back(datagram);
                }
            }

            ETHERTYPE_ARP => {
                if let Ok(message) = ArpMessage::parse_bytes(frame.payload) {
                    self.learn_arp_mapping(
                        Ipv4AddrBytes::new(message.sender_ip_address),
                        message.sender_ethernet_address,
                    );

                    if message.operation == ArpOperation::Request
                        && Ipv4AddrBytes::new(message.target_ip_address) == self.ip_address
                    {
                        self.emit_arp_reply(
                            message.sender_ethernet_address,
                            Ipv4AddrBytes::new(message.sender_ip_address),
                        );
                    }
                }
            }

            _ => {}
        }
    }

    /// Advance interface timers.
    ///
    /// This expires ARP cache entries after 30 seconds and drops unresolved
    /// queued datagrams after 5 seconds.
    pub fn tick(&mut self, elapsed_ms: u64) {
        for entry in self.arp_cache.values_mut() {
            entry.age_ms = entry.age_ms.saturating_add(elapsed_ms);
        }

        self.arp_cache
            .retain(|_, entry| entry.age_ms < ARP_CACHE_TTL_MS);

        for pending in self.pending.values_mut() {
            pending.tick(elapsed_ms);
        }

        self.pending.retain(|_, pending| !pending.is_expired());
    }

    fn learn_arp_mapping(&mut self, ip: Ipv4AddrBytes, ethernet_address: EthernetAddress) {
        self.arp_cache.insert(
            ip,
            ArpCacheEntry {
                ethernet_address,
                age_ms: 0,
            },
        );

        if let Some(mut pending) = self.pending.remove(&ip) {
            while let Some(datagram) = pending.datagrams.pop_front() {
                self.emit_ipv4_frame(datagram, ethernet_address);
            }
        }
    }

    fn emit_ipv4_frame(&mut self, datagram: Ipv4Datagram, dst: EthernetAddress) {
        let payload = datagram.serialize();

        let frame = EthernetFrame::ipv4(dst, self.ethernet_address, payload);

        self.frames_out.push_back(frame);
    }

    fn emit_arp_request(&mut self, target_ip: Ipv4AddrBytes) {
        let arp = ArpMessage::request(
            self.ethernet_address,
            self.ip_address.octets(),
            target_ip.octets(),
        );

        let frame = EthernetFrame::arp(
            EthernetAddress::BROADCAST,
            self.ethernet_address,
            arp.serialize(),
        );

        self.frames_out.push_back(frame);
    }

    fn emit_arp_reply(
        &mut self,
        target_ethernet_address: EthernetAddress,
        target_ip: Ipv4AddrBytes,
    ) {
        let arp = ArpMessage::reply(
            self.ethernet_address,
            self.ip_address.octets(),
            target_ethernet_address,
            target_ip.octets(),
        );

        let frame = EthernetFrame::arp(
            target_ethernet_address,
            self.ethernet_address,
            arp.serialize(),
        );

        self.frames_out.push_back(frame);
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;
    use crate::arp::{ArpMessage, ArpOperation};
    use crate::ethernet_frame::{ETHERTYPE_ARP, ETHERTYPE_IPV4};

    fn my_mac() -> EthernetAddress {
        EthernetAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
    }

    fn peer_mac() -> EthernetAddress {
        EthernetAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x02])
    }

    fn other_mac() -> EthernetAddress {
        EthernetAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x03])
    }

    fn my_ip() -> Ipv4AddrBytes {
        Ipv4AddrBytes::new([169, 254, 144, 2])
    }

    fn peer_ip() -> Ipv4AddrBytes {
        Ipv4AddrBytes::new([169, 254, 144, 1])
    }

    fn other_ip() -> Ipv4AddrBytes {
        Ipv4AddrBytes::new([10, 0, 0, 99])
    }

    fn interface() -> NetworkInterface {
        NetworkInterface::new(my_mac(), my_ip())
    }

    fn datagram(payload: &'static [u8]) -> Ipv4Datagram {
        Ipv4Datagram::new_tcp(
            my_ip().octets(),
            peer_ip().octets(),
            Bytes::from_static(payload),
        )
    }

    fn arp_reply_from_peer() -> EthernetFrame {
        let arp = ArpMessage::reply(peer_mac(), peer_ip().octets(), my_mac(), my_ip().octets());

        EthernetFrame::arp(my_mac(), peer_mac(), arp.serialize())
    }

    #[test]
    fn cache_hit_sends_ipv4_frame_immediately() {
        let mut iface = interface();

        iface.learn_arp_mapping(peer_ip(), peer_mac());

        iface.send_datagram(datagram(b"abc"), peer_ip());

        assert_eq!(iface.frames_out_len(), 1);

        let frame = iface.pop_frame().unwrap();

        assert_eq!(frame.header.dst, peer_mac());
        assert_eq!(frame.header.src, my_mac());
        assert_eq!(frame.header.ethertype, ETHERTYPE_IPV4);

        let parsed = Ipv4Datagram::parse_bytes(frame.payload).unwrap();

        assert_eq!(parsed.payload, Bytes::from_static(b"abc"));
    }

    #[test]
    fn cache_miss_sends_arp_request_and_queues_datagram() {
        let mut iface = interface();

        iface.send_datagram(datagram(b"abc"), peer_ip());

        assert_eq!(iface.frames_out_len(), 1);
        assert_eq!(iface.pending_len(), 1);

        let frame = iface.pop_frame().unwrap();

        assert_eq!(frame.header.dst, EthernetAddress::BROADCAST);
        assert_eq!(frame.header.src, my_mac());
        assert_eq!(frame.header.ethertype, ETHERTYPE_ARP);

        let arp = ArpMessage::parse_bytes(frame.payload).unwrap();

        assert_eq!(arp.operation, ArpOperation::Request);
        assert_eq!(arp.sender_ethernet_address, my_mac());
        assert_eq!(arp.sender_ip_address, my_ip().octets());
        assert_eq!(arp.target_ethernet_address, EthernetAddress::ZERO);
        assert_eq!(arp.target_ip_address, peer_ip().octets());
    }

    #[test]
    fn repeated_datagrams_within_cooldown_do_not_send_duplicate_arp_requests() {
        let mut iface = interface();

        iface.send_datagram(datagram(b"one"), peer_ip());
        iface.send_datagram(datagram(b"two"), peer_ip());
        iface.send_datagram(datagram(b"three"), peer_ip());

        assert_eq!(iface.frames_out_len(), 1);
        assert_eq!(iface.pending_len(), 1);

        let frame = iface.pop_frame().unwrap();
        let arp = ArpMessage::parse_bytes(frame.payload).unwrap();

        assert_eq!(arp.operation, ArpOperation::Request);
    }

    #[test]
    fn after_pending_expires_new_datagram_can_trigger_new_arp_request() {
        let mut iface = interface();

        iface.send_datagram(datagram(b"one"), peer_ip());

        assert_eq!(iface.frames_out_len(), 1);
        assert_eq!(iface.pending_len(), 1);

        iface.pop_frame();

        iface.tick(PENDING_DATAGRAM_TTL_MS);

        assert_eq!(iface.pending_len(), 0);

        iface.send_datagram(datagram(b"two"), peer_ip());

        assert_eq!(iface.frames_out_len(), 1);
        assert_eq!(iface.pending_len(), 1);
    }

    #[test]
    fn arp_reply_learns_mapping_and_flushes_queued_datagrams() {
        let mut iface = interface();

        iface.send_datagram(datagram(b"one"), peer_ip());
        iface.send_datagram(datagram(b"two"), peer_ip());

        assert_eq!(iface.frames_out_len(), 1);
        assert_eq!(iface.pending_len(), 1);

        iface.pop_frame();

        iface.recv_frame(arp_reply_from_peer());

        assert_eq!(iface.pending_len(), 0);
        assert_eq!(iface.arp_cache_len(), 1);
        assert_eq!(iface.lookup_ethernet_address(peer_ip()), Some(peer_mac()));

        assert_eq!(iface.frames_out_len(), 2);

        let first = iface.pop_frame().unwrap();
        let second = iface.pop_frame().unwrap();

        assert_eq!(first.header.dst, peer_mac());
        assert_eq!(second.header.dst, peer_mac());
        assert_eq!(first.header.ethertype, ETHERTYPE_IPV4);
        assert_eq!(second.header.ethertype, ETHERTYPE_IPV4);

        let first_datagram = Ipv4Datagram::parse_bytes(first.payload).unwrap();
        let second_datagram = Ipv4Datagram::parse_bytes(second.payload).unwrap();

        assert_eq!(first_datagram.payload, Bytes::from_static(b"one"));
        assert_eq!(second_datagram.payload, Bytes::from_static(b"two"));
    }

    #[test]
    fn arp_request_for_my_ip_gets_reply_and_learns_sender() {
        let mut iface = interface();

        let request = ArpMessage::request(peer_mac(), peer_ip().octets(), my_ip().octets());

        let frame = EthernetFrame::arp(EthernetAddress::BROADCAST, peer_mac(), request.serialize());

        iface.recv_frame(frame);

        assert_eq!(iface.lookup_ethernet_address(peer_ip()), Some(peer_mac()));
        assert_eq!(iface.frames_out_len(), 1);

        let reply_frame = iface.pop_frame().unwrap();

        assert_eq!(reply_frame.header.dst, peer_mac());
        assert_eq!(reply_frame.header.src, my_mac());
        assert_eq!(reply_frame.header.ethertype, ETHERTYPE_ARP);

        let reply = ArpMessage::parse_bytes(reply_frame.payload).unwrap();

        assert_eq!(reply.operation, ArpOperation::Reply);
        assert_eq!(reply.sender_ethernet_address, my_mac());
        assert_eq!(reply.sender_ip_address, my_ip().octets());
        assert_eq!(reply.target_ethernet_address, peer_mac());
        assert_eq!(reply.target_ip_address, peer_ip().octets());
    }

    #[test]
    fn arp_request_for_someone_else_is_learned_but_not_replied_to() {
        let mut iface = interface();

        let request = ArpMessage::request(peer_mac(), peer_ip().octets(), other_ip().octets());

        let frame = EthernetFrame::arp(EthernetAddress::BROADCAST, peer_mac(), request.serialize());

        iface.recv_frame(frame);

        assert_eq!(iface.lookup_ethernet_address(peer_ip()), Some(peer_mac()));
        assert_eq!(iface.frames_out_len(), 0);
    }

    #[test]
    fn ipv4_frame_for_me_is_accepted() {
        let mut iface = interface();

        let dgram = datagram(b"hello");
        let frame = EthernetFrame::ipv4(my_mac(), peer_mac(), dgram.serialize());

        iface.recv_frame(frame);

        assert_eq!(iface.datagrams_in_len(), 1);

        let received = iface.pop_datagram().unwrap();

        assert_eq!(received.payload, Bytes::from_static(b"hello"));
    }

    #[test]
    fn broadcast_ipv4_frame_is_accepted() {
        let mut iface = interface();

        let dgram = datagram(b"hello");
        let frame = EthernetFrame::ipv4(EthernetAddress::BROADCAST, peer_mac(), dgram.serialize());

        iface.recv_frame(frame);

        assert_eq!(iface.datagrams_in_len(), 1);
    }

    #[test]
    fn frame_not_for_me_is_ignored() {
        let mut iface = interface();

        let dgram = datagram(b"hello");
        let frame = EthernetFrame::ipv4(other_mac(), peer_mac(), dgram.serialize());

        iface.recv_frame(frame);

        assert_eq!(iface.datagrams_in_len(), 0);
        assert_eq!(iface.frames_out_len(), 0);
    }

    #[test]
    fn malformed_ipv4_frame_is_ignored() {
        let mut iface = interface();

        let frame = EthernetFrame::ipv4(
            my_mac(),
            peer_mac(),
            Bytes::from_static(b"not-an-ipv4-packet"),
        );

        iface.recv_frame(frame);

        assert_eq!(iface.datagrams_in_len(), 0);
    }

    #[test]
    fn malformed_arp_frame_is_ignored() {
        let mut iface = interface();

        let frame = EthernetFrame::arp(my_mac(), peer_mac(), Bytes::from_static(b"too-short"));

        iface.recv_frame(frame);

        assert_eq!(iface.frames_out_len(), 0);
        assert_eq!(iface.arp_cache_len(), 0);
    }

    #[test]
    fn arp_cache_entry_expires_after_30_seconds() {
        let mut iface = interface();

        iface.learn_arp_mapping(peer_ip(), peer_mac());

        assert!(iface.has_arp_cache_entry(peer_ip()));

        iface.tick(ARP_CACHE_TTL_MS - 1);

        assert!(iface.has_arp_cache_entry(peer_ip()));

        iface.tick(1);

        assert!(!iface.has_arp_cache_entry(peer_ip()));
    }

    #[test]
    fn learning_existing_arp_mapping_refreshes_ttl() {
        let mut iface = interface();

        iface.learn_arp_mapping(peer_ip(), peer_mac());

        iface.tick(ARP_CACHE_TTL_MS - 1);

        assert!(iface.has_arp_cache_entry(peer_ip()));

        iface.learn_arp_mapping(peer_ip(), peer_mac());

        iface.tick(1);

        assert!(iface.has_arp_cache_entry(peer_ip()));
    }

    #[test]
    fn arp_reply_for_unrelated_ip_is_still_learned() {
        let mut iface = interface();

        let reply = ArpMessage::reply(
            other_mac(),
            other_ip().octets(),
            peer_mac(),
            peer_ip().octets(),
        );

        let frame = EthernetFrame::arp(my_mac(), other_mac(), reply.serialize());

        iface.recv_frame(frame);

        assert_eq!(iface.lookup_ethernet_address(other_ip()), Some(other_mac()));
    }
}
