use std::io::{self, BufRead, Write};
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::mpsc;
use std::thread;

use minnow_rs::ip_host::IpHostEvent;

#[derive(Debug)]
pub enum AppEvent {
    Data(Vec<u8>),
    Close,
}

pub fn spawn_stdin_thread(tx: mpsc::Sender<AppEvent>) {
    thread::spawn(move || {
        let stdin = io::stdin();

        for line in stdin.lock().lines() {
            match line {
                Ok(mut line) => {
                    line.push('\n');

                    if tx.send(AppEvent::Data(line.into_bytes())).is_err() {
                        return;
                    }
                }
                Err(_) => {
                    let _ = tx.send(AppEvent::Close);
                    return;
                }
            }
        }

        let _ = tx.send(AppEvent::Close);
    });
}

pub fn print_events(events: &[IpHostEvent]) -> io::Result<()> {
    for event in events {
        match event {
            IpHostEvent::IncomingTcp(segment) => {
                eprintln!(
                    "<< TCP {} -> {} seq={} ack={:?} SYN={} FIN={} RST={} win={} payload={}",
                    segment.header.src_port,
                    segment.header.dst_port,
                    segment.header.seqno.raw_value(),
                    segment.header.ackno.map(|ack| ack.raw_value()),
                    segment.header.syn,
                    segment.header.fin,
                    segment.header.rst,
                    segment.header.window_size,
                    segment.payload.len(),
                );
            }
            IpHostEvent::OutgoingTcp(segment) => {
                eprintln!(
                    ">> TCP {} -> {} seq={} ack={:?} SYN={} FIN={} RST={} win={} payload={}",
                    segment.header.src_port,
                    segment.header.dst_port,
                    segment.header.seqno.raw_value(),
                    segment.header.ackno.map(|ack| ack.raw_value()),
                    segment.header.syn,
                    segment.header.fin,
                    segment.header.rst,
                    segment.header.window_size,
                    segment.payload.len(),
                );
            }
            IpHostEvent::TcpPayload(payload) => {
                print!("{}", String::from_utf8_lossy(payload));
                io::stdout().flush()?;
            }
            IpHostEvent::IcmpEchoRequest {
                src_ip,
                dst_ip,
                identifier,
                sequence_number,
                payload_len,
            } => {
                eprintln!(
                    "<< ICMP echo request {} -> {} id={} seq={} payload={}",
                    fmt_ip(*src_ip),
                    fmt_ip(*dst_ip),
                    identifier,
                    sequence_number,
                    payload_len,
                );
            }
            IpHostEvent::IcmpEchoReply {
                src_ip,
                dst_ip,
                identifier,
                sequence_number,
                payload_len,
            } => {
                eprintln!(
                    ">> ICMP echo reply {} -> {} id={} seq={} payload={}",
                    fmt_ip(*src_ip),
                    fmt_ip(*dst_ip),
                    identifier,
                    sequence_number,
                    payload_len,
                );
            }
            IpHostEvent::IgnoredMalformedIpv4(err) => {
                eprintln!("ignored malformed IPv4 packet: {err}");
            }
            IpHostEvent::IgnoredMalformedTcp(err) => {
                eprintln!("ignored malformed TCP segment: {err}");
            }
            IpHostEvent::IgnoredMalformedIcmp(err) => {
                eprintln!("ignored malformed ICMP message: {err}");
            }
        }
    }

    Ok(())
}

pub fn require_arg<'a>(args: &'a [String], index: usize, flag: &str) -> io::Result<&'a str> {
    args.get(index).map(String::as_str).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("missing value for {flag}"),
        )
    })
}

pub fn parse_ipv4(value: &str) -> io::Result<[u8; 4]> {
    let addr = Ipv4Addr::from_str(value)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;

    Ok(addr.octets())
}

pub fn parse_port(value: &str) -> io::Result<u16> {
    let port = value
        .parse::<u16>()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;

    if port == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TCP port cannot be zero",
        ));
    }

    Ok(port)
}

pub fn fmt_ip(ip: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}
