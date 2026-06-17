# Wireshark and pcap notes

`minnow-rs` can write classic pcap files directly from its demo hosts.

- `tun_host` writes `LINKTYPE_RAW` captures. Packets start at the IPv4 header.
- `tap_host` writes `LINKTYPE_ETHERNET` captures. Packets start at the Ethernet header, so ARP is visible.

## Generate a TUN capture

Terminal 1:

```bash
./scripts/tun_host.sh run
```

Terminal 2:

```bash
./scripts/tun_host.sh ping
```

Open the capture:

```bash
wireshark target/minnow-captures/tun-host.pcap
```

Useful filters:

```text
ip.addr == 169.254.144.2
icmp
tcp
```

Expected ping packets:

```text
IPv4 ICMP echo request  169.254.144.1 -> 169.254.144.2
IPv4 ICMP echo reply    169.254.144.2 -> 169.254.144.1
```

## Generate a TAP capture

Terminal 1:

```bash
./scripts/tap_host.sh run
```

Terminal 2:

```bash
./scripts/tap_host.sh ping
```

Open the capture:

```bash
wireshark target/minnow-captures/tap-host.pcap
```

Useful filters:

```text
arp
icmp
eth.addr == 02:00:00:00:00:02
ip.addr == 169.254.144.2
```

Expected first ping sequence:

```text
Ethernet ARP request    who has 169.254.144.2?
Ethernet ARP reply      169.254.144.2 is at 02:00:00:00:00:02
Ethernet IPv4 ICMP      echo request
Ethernet IPv4 ICMP      echo reply
```

## TCP demo capture

Terminal 1:

```bash
./scripts/tap_host.sh listen
```

Terminal 2:

```bash
./scripts/tap_host.sh run
```

Type a line into the `tap_host` terminal. The line should arrive in the `nc`
listener, and the capture should show a TCP handshake plus data and ACKs.

Useful TCP filters:

```text
tcp.port == 9090
tcp.flags.syn == 1
tcp.len > 0
```
