use std::env;
use std::io;

use minnow_rs::ipv4_datagram::IPV4_PROTOCOL_TCP;
use minnow_rs::tun::{DEFAULT_TUN_NAME, TunDevice};

fn main() -> io::Result<()> {
    let name = env::args()
        .nth(1)
        .unwrap_or_else(|| DEFAULT_TUN_NAME.to_string());

    eprintln!("opening TUN device: {name}");

    let mut tun = TunDevice::create(&name)?;

    eprintln!("opened TUN device: {}", tun.name());
    eprintln!("waiting for IPv4 packets...");
    eprintln!("try in another terminal:");
    eprintln!("  ping -c 3 169.254.144.2");
    eprintln!();

    loop {
        let packet = tun.read_packet()?;

        println!("raw packet: {} bytes", packet.len());

        match minnow_rs::ipv4_datagram::Ipv4Datagram::parse(&packet) {
            Ok(datagram) => {
                let src = datagram.header.src.octets();
                let dst = datagram.header.dst.octets();

                let proto = match datagram.header.protocol {
                    IPV4_PROTOCOL_TCP => "TCP",
                    1 => "ICMP",
                    17 => "UDP",
                    _ => "OTHER",
                };

                println!(
                    "IPv4: {}.{}.{}.{} -> {}.{}.{}.{} proto={} payload_len={}",
                    src[0],
                    src[1],
                    src[2],
                    src[3],
                    dst[0],
                    dst[1],
                    dst[2],
                    dst[3],
                    proto,
                    datagram.payload.len(),
                );
            }
            Err(err) => {
                println!("failed to parse IPv4 packet: {err:?}");
            }
        }

        println!();
    }
}
