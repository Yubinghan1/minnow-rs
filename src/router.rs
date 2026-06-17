use crate::ipv4_datagram::{Ipv4AddrBytes, Ipv4Datagram};
use crate::network_interface::NetworkInterface;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub route_prefix: Ipv4AddrBytes,
    pub prefix_length: u8,
    pub next_hop: Option<Ipv4AddrBytes>,
    pub interface_num: usize,
}

#[derive(Debug, Default)]
pub struct Router {
    interfaces: Vec<NetworkInterface>,
    routes: Vec<Route>,
}

impl Router {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_interface(&mut self, interface: NetworkInterface) -> usize {
        let interface_num = self.interfaces.len();

        self.interfaces.push(interface);

        interface_num
    }

    pub fn interface(&self, interface_num: usize) -> Option<&NetworkInterface> {
        self.interfaces.get(interface_num)
    }

    pub fn interface_mut(&mut self, interface_num: usize) -> Option<&mut NetworkInterface> {
        self.interfaces.get_mut(interface_num)
    }

    pub fn interfaces(&self) -> &[NetworkInterface] {
        &self.interfaces
    }

    pub fn interfaces_mut(&mut self) -> &mut [NetworkInterface] {
        &mut self.interfaces
    }

    pub fn routes(&self) -> &[Route] {
        &self.routes
    }

    pub fn add_route(
        &mut self,
        route_prefix: Ipv4AddrBytes,
        prefix_length: u8,
        next_hop: Option<Ipv4AddrBytes>,
        interface_num: usize,
    ) {
        assert!(prefix_length <= 32, "IPv4 prefix length must be <= 32");

        self.routes.push(Route {
            route_prefix,
            prefix_length,
            next_hop,
            interface_num,
        });
    }

    pub fn route(&mut self) {
        for interface_num in 0..self.interfaces.len() {
            while let Some(datagram) = self.interfaces[interface_num].pop_datagram() {
                self.route_one_datagram(datagram);
            }
        }
    }

    fn route_one_datagram(&mut self, mut datagram: Ipv4Datagram) {
        if datagram.header.ttl <= 1 {
            return;
        }

        let destination = datagram.header.dst;

        let Some((interface_num, next_hop)) = self
            .find_route(destination)
            .map(|route| (route.interface_num, route.next_hop.unwrap_or(destination)))
        else {
            return;
        };

        let Some(interface) = self.interfaces.get_mut(interface_num) else {
            return;
        };

        datagram.header.ttl -= 1;

        interface.send_datagram(datagram, next_hop);
    }

    fn find_route(&self, destination: Ipv4AddrBytes) -> Option<&Route> {
        let mut best = None;

        for route in &self.routes {
            if route.matches(destination)
                && best.is_none_or(|best: &Route| route.prefix_length > best.prefix_length)
            {
                best = Some(route);
            }
        }

        best
    }
}

impl Route {
    fn matches(&self, destination: Ipv4AddrBytes) -> bool {
        let mask = prefix_mask(self.prefix_length);
        let prefix = u32::from_be_bytes(self.route_prefix.octets());
        let destination = u32::from_be_bytes(destination.octets());

        (prefix & mask) == (destination & mask)
    }
}

fn prefix_mask(prefix_length: u8) -> u32 {
    if prefix_length == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_length)
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;
    use crate::arp::ArpMessage;
    use crate::ethernet_frame::{ETHERTYPE_ARP, ETHERTYPE_IPV4, EthernetAddress, EthernetFrame};

    fn mac(n: u8) -> EthernetAddress {
        EthernetAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, n])
    }

    fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4AddrBytes {
        Ipv4AddrBytes::new([a, b, c, d])
    }

    fn datagram(dst: Ipv4AddrBytes, ttl: u8, payload: &'static [u8]) -> Ipv4Datagram {
        let mut datagram =
            Ipv4Datagram::new_tcp([10, 0, 0, 100], dst.octets(), Bytes::from_static(payload));

        datagram.header.ttl = ttl;

        datagram
    }

    fn interface(n: u8, addr: Ipv4AddrBytes) -> NetworkInterface {
        NetworkInterface::new(mac(n), addr)
    }

    fn prime_arp(
        router: &mut Router,
        interface_num: usize,
        next_hop_ip: Ipv4AddrBytes,
        next_hop_mac: EthernetAddress,
    ) {
        let interface = router.interface(interface_num).unwrap();
        let reply = ArpMessage::reply(
            next_hop_mac,
            next_hop_ip.octets(),
            interface.ethernet_address(),
            interface.ip_address().octets(),
        );

        let frame = EthernetFrame::arp(
            interface.ethernet_address(),
            next_hop_mac,
            reply.serialize(),
        );

        router
            .interface_mut(interface_num)
            .unwrap()
            .recv_frame(frame);
    }

    fn inject_datagram(router: &mut Router, interface_num: usize, datagram: Ipv4Datagram) {
        let interface = router.interface(interface_num).unwrap();
        let frame =
            EthernetFrame::ipv4(interface.ethernet_address(), mac(99), datagram.serialize());

        router
            .interface_mut(interface_num)
            .unwrap()
            .recv_frame(frame);
    }

    fn pop_forwarded(router: &mut Router, interface_num: usize) -> (EthernetFrame, Ipv4Datagram) {
        let frame = router
            .interface_mut(interface_num)
            .unwrap()
            .pop_frame()
            .unwrap();

        assert_eq!(frame.header.ethertype, ETHERTYPE_IPV4);

        let datagram = Ipv4Datagram::parse_bytes(frame.payload.clone()).unwrap();

        (frame, datagram)
    }

    fn pop_arp(router: &mut Router, interface_num: usize) -> (EthernetFrame, ArpMessage) {
        let frame = router
            .interface_mut(interface_num)
            .unwrap()
            .pop_frame()
            .unwrap();

        assert_eq!(frame.header.ethertype, ETHERTYPE_ARP);

        let message = ArpMessage::parse_bytes(frame.payload.clone()).unwrap();

        (frame, message)
    }

    #[test]
    fn longest_prefix_match_selects_most_specific_route() {
        let mut router = Router::new();
        let input = router.add_interface(interface(1, ip(10, 0, 0, 1)));
        let output_default = router.add_interface(interface(2, ip(172, 16, 0, 1)));
        let output_specific = router.add_interface(interface(3, ip(192, 168, 1, 1)));

        let default_hop = ip(172, 16, 0, 2);
        let specific_hop = ip(192, 168, 1, 2);
        let specific_mac = mac(42);

        prime_arp(&mut router, output_default, default_hop, mac(41));
        prime_arp(&mut router, output_specific, specific_hop, specific_mac);

        router.add_route(ip(0, 0, 0, 0), 0, Some(default_hop), output_default);
        router.add_route(ip(192, 168, 1, 0), 24, Some(specific_hop), output_specific);

        inject_datagram(
            &mut router,
            input,
            datagram(ip(192, 168, 1, 99), 64, b"hello"),
        );

        router.route();

        assert_eq!(
            router.interface(output_default).unwrap().frames_out_len(),
            0
        );

        let (frame, forwarded) = pop_forwarded(&mut router, output_specific);

        assert_eq!(frame.header.dst, specific_mac);
        assert_eq!(frame.header.src, mac(3));
        assert_eq!(forwarded.header.ttl, 63);
        assert_eq!(forwarded.header.dst, ip(192, 168, 1, 99));
        assert_eq!(forwarded.payload, Bytes::from_static(b"hello"));
    }

    #[test]
    fn direct_route_uses_destination_as_next_hop() {
        let mut router = Router::new();
        let input = router.add_interface(interface(1, ip(10, 0, 0, 1)));
        let output = router.add_interface(interface(2, ip(10, 1, 0, 1)));

        let destination = ip(10, 1, 2, 3);
        let destination_mac = mac(23);

        prime_arp(&mut router, output, destination, destination_mac);
        router.add_route(ip(10, 1, 0, 0), 16, None, output);

        inject_datagram(&mut router, input, datagram(destination, 10, b"direct"));

        router.route();

        let (frame, forwarded) = pop_forwarded(&mut router, output);

        assert_eq!(frame.header.dst, destination_mac);
        assert_eq!(forwarded.header.ttl, 9);
        assert_eq!(forwarded.payload, Bytes::from_static(b"direct"));
    }

    #[test]
    fn ttl_one_is_dropped() {
        let mut router = Router::new();
        let input = router.add_interface(interface(1, ip(10, 0, 0, 1)));
        let output = router.add_interface(interface(2, ip(172, 16, 0, 1)));
        let next_hop = ip(172, 16, 0, 2);

        prime_arp(&mut router, output, next_hop, mac(50));
        router.add_route(ip(0, 0, 0, 0), 0, Some(next_hop), output);

        inject_datagram(&mut router, input, datagram(ip(8, 8, 8, 8), 1, b"drop"));

        router.route();

        assert_eq!(router.interface(output).unwrap().frames_out_len(), 0);
    }

    #[test]
    fn datagram_without_matching_route_is_dropped() {
        let mut router = Router::new();
        let input = router.add_interface(interface(1, ip(10, 0, 0, 1)));
        let output = router.add_interface(interface(2, ip(172, 16, 0, 1)));

        router.add_route(ip(192, 168, 0, 0), 16, None, output);

        inject_datagram(&mut router, input, datagram(ip(8, 8, 8, 8), 64, b"drop"));

        router.route();

        assert_eq!(router.interface(output).unwrap().frames_out_len(), 0);
    }

    #[test]
    fn default_route_handles_destinations_without_specific_match() {
        let mut router = Router::new();
        let input = router.add_interface(interface(1, ip(10, 0, 0, 1)));
        let output = router.add_interface(interface(2, ip(172, 16, 0, 1)));

        let next_hop = ip(172, 16, 0, 2);
        let next_hop_mac = mac(61);

        prime_arp(&mut router, output, next_hop, next_hop_mac);
        router.add_route(ip(0, 0, 0, 0), 0, Some(next_hop), output);

        inject_datagram(
            &mut router,
            input,
            datagram(ip(203, 0, 113, 9), 32, b"default"),
        );

        router.route();

        let (frame, forwarded) = pop_forwarded(&mut router, output);

        assert_eq!(frame.header.dst, next_hop_mac);
        assert_eq!(forwarded.header.ttl, 31);
        assert_eq!(forwarded.payload, Bytes::from_static(b"default"));
    }

    #[test]
    fn equal_length_routes_keep_first_added_route() {
        let mut router = Router::new();
        let input = router.add_interface(interface(1, ip(10, 0, 0, 1)));
        let first_output = router.add_interface(interface(2, ip(172, 16, 0, 1)));
        let second_output = router.add_interface(interface(3, ip(172, 17, 0, 1)));

        let first_hop = ip(172, 16, 0, 2);
        let second_hop = ip(172, 17, 0, 2);
        let first_mac = mac(71);

        prime_arp(&mut router, first_output, first_hop, first_mac);
        prime_arp(&mut router, second_output, second_hop, mac(72));

        router.add_route(ip(198, 51, 100, 0), 24, Some(first_hop), first_output);
        router.add_route(ip(198, 51, 100, 0), 24, Some(second_hop), second_output);

        inject_datagram(
            &mut router,
            input,
            datagram(ip(198, 51, 100, 77), 20, b"tie"),
        );

        router.route();

        assert_eq!(router.interface(second_output).unwrap().frames_out_len(), 0);

        let (frame, forwarded) = pop_forwarded(&mut router, first_output);

        assert_eq!(frame.header.dst, first_mac);
        assert_eq!(forwarded.header.ttl, 19);
        assert_eq!(forwarded.payload, Bytes::from_static(b"tie"));
    }

    #[test]
    fn unresolved_next_hop_emits_arp_and_forwards_after_reply() {
        let mut router = Router::new();
        let input = router.add_interface(interface(1, ip(10, 0, 0, 1)));
        let output = router.add_interface(interface(2, ip(172, 16, 0, 1)));

        let next_hop = ip(172, 16, 0, 2);
        let next_hop_mac = mac(88);

        router.add_route(ip(203, 0, 113, 0), 24, Some(next_hop), output);

        inject_datagram(
            &mut router,
            input,
            datagram(ip(203, 0, 113, 9), 64, b"queued"),
        );

        router.route();

        let (arp_frame, arp) = pop_arp(&mut router, output);

        assert_eq!(arp_frame.header.dst, EthernetAddress::BROADCAST);
        assert_eq!(arp.operation, crate::arp::ArpOperation::Request);
        assert_eq!(arp.target_ip_address, next_hop.octets());
        assert_eq!(router.interface(output).unwrap().pending_len(), 1);

        let reply = ArpMessage::reply(
            next_hop_mac,
            next_hop.octets(),
            router.interface(output).unwrap().ethernet_address(),
            router.interface(output).unwrap().ip_address().octets(),
        );
        let output_mac = router.interface(output).unwrap().ethernet_address();

        router
            .interface_mut(output)
            .unwrap()
            .recv_frame(EthernetFrame::arp(
                output_mac,
                next_hop_mac,
                reply.serialize(),
            ));

        let (frame, forwarded) = pop_forwarded(&mut router, output);

        assert_eq!(frame.header.dst, next_hop_mac);
        assert_eq!(forwarded.header.ttl, 63);
        assert_eq!(forwarded.payload, Bytes::from_static(b"queued"));
        assert_eq!(router.interface(output).unwrap().pending_len(), 0);
    }
}
