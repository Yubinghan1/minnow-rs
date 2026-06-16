use std::env;
use std::io::{self, BufRead, Write};
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use bytes::Bytes;
use minnow_rs::ipv4_datagram::{IPV4_PROTOCOL_TCP, Ipv4Datagram};
use minnow_rs::tcp_connection::{TcpConnection, TcpConnectionConfig};
use minnow_rs::tcp_segment::TcpSegment;
use minnow_rs::tcp_sender::TcpSenderConfig;
use minnow_rs::tun::{DEFAULT_TUN_NAME, TunDevice};
use minnow_rs::wrapping_integers::Wrap32;

const DEFAULT_LOCAL_IP: [u8; 4] = [169, 254, 144, 2];
const DEFAULT_PEER_IP: [u8; 4] = [169, 254, 144, 1];
const DEFAULT_LOCAL_PORT: u16 = 50_000;
const DEFAULT_PEER_PORT: u16 = 9_090;

const DEFAULT_SENDER_CAPACITY: usize = 64 * 1024;
const DEFAULT_RECEIVER_CAPACITY: usize = 64 * 1024;
const DEFAULT_MAX_PAYLOAD_SIZE: usize = 1_000;
const DEFAULT_INITIAL_RTO_MS: u64 = 1_000;
const DEFAULT_MAX_TIMER_MS: u64 = 60_000;

const POLL_INTERVAL_MS: u64 = 10;

#[derive(Debug, Clone)]
struct Config {
    tun_name: String,
    local_ip: [u8; 4],
    peer_ip: [u8; 4],
    local_port: u16,
    peer_port: u16,
    isn: Wrap32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tun_name: DEFAULT_TUN_NAME.to_string(),
            local_ip: DEFAULT_LOCAL_IP,
            peer_ip: DEFAULT_PEER_IP,
            local_port: DEFAULT_LOCAL_PORT,
            peer_port: DEFAULT_PEER_PORT,
            isn: Wrap32::new(1_000_000),
        }
    }
}

#[derive(Debug)]
enum AppEvent {
    Data(Vec<u8>),
    Close,
}

fn main() -> io::Result<()> {
    let config = parse_args()?;

    eprintln!("=== minnow-rs tcp_ipv4 ===");
    eprintln!("TUN        : {}", config.tun_name);
    eprintln!(
        "local      : {}:{}",
        fmt_ip(config.local_ip),
        config.local_port
    );
    eprintln!(
        "peer       : {}:{}",
        fmt_ip(config.peer_ip),
        config.peer_port
    );
    eprintln!("ISN        : {}", config.isn.raw_value());
    eprintln!();

    let mut tun = TunDevice::create(&config.tun_name)?;
    tun.set_nonblocking(true)?;

    eprintln!("opened TUN device: {}", tun.name());

    let sender_config = TcpSenderConfig {
        initial_rto_ms: DEFAULT_INITIAL_RTO_MS,
        max_timer_interval_ms: DEFAULT_MAX_TIMER_MS,
        max_payload_size: DEFAULT_MAX_PAYLOAD_SIZE,
    };

    let mut connection = TcpConnection::new(TcpConnectionConfig::new(
        config.local_port,
        config.peer_port,
        DEFAULT_SENDER_CAPACITY,
        DEFAULT_RECEIVER_CAPACITY,
        config.isn,
        sender_config,
    ));

    let (app_tx, app_rx) = mpsc::channel();

    spawn_stdin_thread(app_tx);

    eprintln!("sending SYN...");
    let initial_segments = connection.connect();
    send_segments(&mut tun, config.local_ip, config.peer_ip, &initial_segments)?;

    eprintln!("type text and press Enter to send it over your Rust TCP stack.");
    eprintln!("press Ctrl-D to close outbound stream.");
    eprintln!();

    let mut last_tick = Instant::now();
    let mut was_established = false;

    loop {
        drain_tun_packets(&mut tun, &mut connection, config.local_ip, config.peer_ip)?;

        drain_app_events(
            &mut tun,
            &mut connection,
            &app_rx,
            config.local_ip,
            config.peer_ip,
        )?;

        let now = Instant::now();
        let elapsed_ms = now.duration_since(last_tick).as_millis() as u64;

        if elapsed_ms > 0 {
            last_tick = now;

            let retransmissions = connection.tick(elapsed_ms);

            if !retransmissions.is_empty() {
                eprintln!("timer emitted {} retransmission(s)", retransmissions.len());
                send_segments(&mut tun, config.local_ip, config.peer_ip, &retransmissions)?;
            }
        }

        if connection.is_established() && !was_established {
            was_established = true;
            eprintln!("connection established.");
            eprintln!();
        }

        if connection.is_finished() {
            eprintln!("local outbound stream finished and fully acknowledged.");
            eprintln!("you can Ctrl-C to exit, or keep reading peer data if any.");
        }

        thread::sleep(Duration::from_millis(POLL_INTERVAL_MS));
    }
}

fn drain_tun_packets(
    tun: &mut TunDevice,
    connection: &mut TcpConnection,
    local_ip: [u8; 4],
    peer_ip: [u8; 4],
) -> io::Result<()> {
    loop {
        match tun.read_packet() {
            Ok(packet) => {
                handle_packet(tun, connection, local_ip, peer_ip, &packet)?;
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                return Ok(());
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {
                continue;
            }
            Err(err) => return Err(err),
        }
    }
}

fn handle_packet(
    tun: &mut TunDevice,
    connection: &mut TcpConnection,
    local_ip: [u8; 4],
    peer_ip: [u8; 4],
    packet: &[u8],
) -> io::Result<()> {
    let datagram = match Ipv4Datagram::parse(packet) {
        Ok(datagram) => datagram,
        Err(err) => {
            eprintln!("ignored malformed IPv4 packet: {err:?}");
            return Ok(());
        }
    };

    if datagram.header.protocol != IPV4_PROTOCOL_TCP {
        return Ok(());
    }

    let src_ip = datagram.header.src.octets();
    let dst_ip = datagram.header.dst.octets();

    if src_ip != peer_ip || dst_ip != local_ip {
        return Ok(());
    }

    let segment = match TcpSegment::parse_ipv4_bytes(src_ip, dst_ip, datagram.payload.clone()) {
        Ok(segment) => segment,
        Err(err) => {
            eprintln!("ignored malformed TCP segment: {err:?}");
            return Ok(());
        }
    };

    if segment.header.src_port != connection.peer_port()
        || segment.header.dst_port != connection.local_port()
    {
        return Ok(());
    }

    print_incoming_segment(&segment);

    if !segment.payload.is_empty() {
        print!("{}", String::from_utf8_lossy(&segment.payload));
        io::stdout().flush()?;
    }

    let responses = connection.receive_segment(segment);

    if !responses.is_empty() {
        send_segments(tun, local_ip, peer_ip, &responses)?;
    }

    Ok(())
}

fn drain_app_events(
    tun: &mut TunDevice,
    connection: &mut TcpConnection,
    app_rx: &mpsc::Receiver<AppEvent>,
    local_ip: [u8; 4],
    peer_ip: [u8; 4],
) -> io::Result<()> {
    loop {
        match app_rx.try_recv() {
            Ok(AppEvent::Data(data)) => {
                let (written, segments) = connection.write(&data);

                if written < data.len() {
                    eprintln!(
                        "warning: outbound ByteStream accepted only {written}/{} bytes",
                        data.len()
                    );
                }

                send_segments(tun, local_ip, peer_ip, &segments)?;
            }
            Ok(AppEvent::Close) => {
                eprintln!("stdin closed; sending FIN when possible...");
                let segments = connection.close();
                send_segments(tun, local_ip, peer_ip, &segments)?;
            }
            Err(mpsc::TryRecvError::Empty) => return Ok(()),
            Err(mpsc::TryRecvError::Disconnected) => return Ok(()),
        }
    }
}

fn send_segments(
    tun: &mut TunDevice,
    local_ip: [u8; 4],
    peer_ip: [u8; 4],
    segments: &[TcpSegment],
) -> io::Result<()> {
    for segment in segments {
        print_outgoing_segment(segment);

        let tcp_bytes = segment.serialize_ipv4(local_ip, peer_ip);
        let datagram = Ipv4Datagram::new_tcp(local_ip, peer_ip, tcp_bytes);

        tun.write_ipv4_datagram(&datagram)?;
    }

    Ok(())
}

fn spawn_stdin_thread(tx: mpsc::Sender<AppEvent>) {
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

fn print_outgoing_segment(segment: &TcpSegment) {
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

fn print_incoming_segment(segment: &TcpSegment) {
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

fn parse_args() -> io::Result<Config> {
    let mut config = Config::default();

    let args: Vec<String> = env::args().collect();

    let mut i = 1;

    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            "--tun" => {
                i += 1;
                config.tun_name = require_arg(&args, i, "--tun")?.to_string();
            }
            "--local-ip" => {
                i += 1;
                config.local_ip = parse_ipv4(require_arg(&args, i, "--local-ip")?)?;
            }
            "--peer-ip" => {
                i += 1;
                config.peer_ip = parse_ipv4(require_arg(&args, i, "--peer-ip")?)?;
            }
            "--local-port" => {
                i += 1;
                config.local_port = parse_port(require_arg(&args, i, "--local-port")?)?;
            }
            "--peer-port" => {
                i += 1;
                config.peer_port = parse_port(require_arg(&args, i, "--peer-port")?)?;
            }
            "--isn" => {
                i += 1;
                let raw = require_arg(&args, i, "--isn")?
                    .parse::<u32>()
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;

                config.isn = Wrap32::new(raw);
            }
            unknown => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown argument: {unknown}"),
                ));
            }
        }

        i += 1;
    }

    if config.local_ip == config.peer_ip {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "local IP and peer IP must be different",
        ));
    }

    if config.local_port == config.peer_port {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "local port and peer port should be different",
        ));
    }

    Ok(config)
}

fn require_arg<'a>(args: &'a [String], index: usize, flag: &str) -> io::Result<&'a str> {
    args.get(index).map(String::as_str).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("missing value for {flag}"),
        )
    })
}

fn parse_ipv4(value: &str) -> io::Result<[u8; 4]> {
    let addr = Ipv4Addr::from_str(value)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;

    Ok(addr.octets())
}

fn parse_port(value: &str) -> io::Result<u16> {
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

fn fmt_ip(ip: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

fn print_help() {
    println!(
        "\
Usage:
  tcp_ipv4 [OPTIONS]

Options:
  --tun NAME             TUN device name. Default: tun144
  --local-ip IP          Rust TCP stack IP. Default: 169.254.144.2
  --peer-ip IP           Linux/native TCP peer IP. Default: 169.254.144.1
  --local-port PORT      Rust local TCP port. Default: 50000
  --peer-port PORT       Native peer TCP port. Default: 9090
  --isn N                Initial sequence number. Default: 1000000
  -h, --help             Show this help

Example:
  cargo run --bin tcp_ipv4 -- \\
    --tun tun144 \\
    --local-ip 169.254.144.2 \\
    --peer-ip 169.254.144.1 \\
    --local-port 50000 \\
    --peer-port 9090
"
    );
}
