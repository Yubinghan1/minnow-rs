use std::env;
use std::io;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use bytes::Bytes;
use minnow_rs::ethernet_frame::EthernetAddress;
use minnow_rs::ethernet_frame::EthernetFrame;
use minnow_rs::ip_host::{IpHost, IpHostConfig, IpHostOutput};
use minnow_rs::ipv4_datagram::Ipv4AddrBytes;
use minnow_rs::network_interface::NetworkInterface;
use minnow_rs::pcap::{PcapLinkType, PcapWriter};
use minnow_rs::tap::{DEFAULT_TAP_NAME, TapDevice};
use minnow_rs::wrapping_integers::Wrap32;

#[path = "common/host_cli.rs"]
mod host_cli;

use host_cli::{
    AppEvent, fmt_ip, parse_ipv4, parse_port, print_events, require_arg, spawn_stdin_thread,
};

const DEFAULT_LOCAL_MAC: EthernetAddress =
    EthernetAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
const DEFAULT_LOCAL_IP: [u8; 4] = [169, 254, 144, 2];
const DEFAULT_PEER_IP: [u8; 4] = [169, 254, 144, 1];
const DEFAULT_LOCAL_PORT: u16 = 50_000;
const DEFAULT_PEER_PORT: u16 = 9_090;
const POLL_INTERVAL_MS: u64 = 10;

#[derive(Debug, Clone)]
struct Config {
    tap_name: String,
    local_mac: EthernetAddress,
    local_ip: [u8; 4],
    peer_ip: [u8; 4],
    local_port: u16,
    peer_port: u16,
    isn: Wrap32,
    pcap_path: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tap_name: DEFAULT_TAP_NAME.to_string(),
            local_mac: DEFAULT_LOCAL_MAC,
            local_ip: DEFAULT_LOCAL_IP,
            peer_ip: DEFAULT_PEER_IP,
            local_port: DEFAULT_LOCAL_PORT,
            peer_port: DEFAULT_PEER_PORT,
            isn: Wrap32::new(1_000_000),
            pcap_path: None,
        }
    }
}

fn main() -> io::Result<()> {
    let config = parse_args()?;

    eprintln!("=== minnow-rs tap_host ===");
    eprintln!("TAP        : {}", config.tap_name);
    eprintln!("local MAC  : {}", config.local_mac);
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
    if let Some(path) = &config.pcap_path {
        eprintln!("pcap       : {} (Ethernet)", path.display());
    }
    eprintln!();

    let mut tap = TapDevice::create(&config.tap_name)?;
    tap.set_nonblocking(true)?;
    let mut pcap = config
        .pcap_path
        .as_ref()
        .map(|path| PcapWriter::create(path, PcapLinkType::Ethernet))
        .transpose()?;

    eprintln!("opened TAP device: {}", tap.name());

    let mut interface =
        NetworkInterface::new(config.local_mac, Ipv4AddrBytes::new(config.local_ip));
    let host_config = IpHostConfig::tcp_demo(
        config.local_ip,
        config.peer_ip,
        config.local_port,
        config.peer_port,
        config.isn,
    );
    let mut host = IpHost::new(host_config);
    let (app_tx, app_rx) = mpsc::channel();

    spawn_stdin_thread(app_tx);

    eprintln!("sending SYN...");
    send_host_output_to_interface(&mut interface, host.connect())?;
    flush_interface_frames(&mut tap, &mut pcap, &mut interface)?;

    eprintln!("type text and press Enter to send it over your Rust TCP stack.");
    eprintln!("press Ctrl-D to close outbound stream.");
    eprintln!();

    let mut last_tick = Instant::now();
    let mut was_established = false;

    loop {
        drain_tap_frames(&mut tap, &mut pcap, &mut interface, &mut host)?;
        drain_app_events(&mut interface, &mut host, &app_rx)?;

        let now = Instant::now();
        let elapsed_ms = now.duration_since(last_tick).as_millis() as u64;

        if elapsed_ms > 0 {
            last_tick = now;
            interface.tick(elapsed_ms);
            send_host_output_to_interface(&mut interface, host.tick(elapsed_ms))?;
        }

        flush_interface_frames(&mut tap, &mut pcap, &mut interface)?;

        if host.is_established() && !was_established {
            was_established = true;
            eprintln!("connection established.");
            eprintln!();
        }

        if host.is_finished() {
            eprintln!("local outbound stream finished and fully acknowledged.");
            eprintln!("you can Ctrl-C to exit, or keep reading peer data if any.");
        }

        thread::sleep(Duration::from_millis(POLL_INTERVAL_MS));
    }
}

fn drain_tap_frames(
    tap: &mut TapDevice,
    pcap: &mut Option<PcapWriter>,
    interface: &mut NetworkInterface,
    host: &mut IpHost,
) -> io::Result<()> {
    loop {
        match tap.read_frame() {
            Ok(frame_bytes) => {
                dump_packet(pcap, &frame_bytes)?;

                match EthernetFrame::parse_bytes(Bytes::from(frame_bytes)) {
                    Ok(frame) => {
                        interface.recv_frame(frame);
                        drain_interface_datagrams(interface, host)?;
                    }
                    Err(err) => eprintln!("ignored malformed Ethernet frame: {err:?}"),
                }
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
}

fn drain_interface_datagrams(
    interface: &mut NetworkInterface,
    host: &mut IpHost,
) -> io::Result<()> {
    while let Some(datagram) = interface.pop_datagram() {
        send_host_output_to_interface(interface, host.receive_datagram(datagram))?;
    }

    Ok(())
}

fn drain_app_events(
    interface: &mut NetworkInterface,
    host: &mut IpHost,
    app_rx: &mpsc::Receiver<AppEvent>,
) -> io::Result<()> {
    loop {
        match app_rx.try_recv() {
            Ok(AppEvent::Data(data)) => {
                let data_len = data.len();
                let (written, output) = host.write(Bytes::from(data));

                if written < data_len {
                    eprintln!(
                        "warning: outbound ByteStream accepted only {written}/{} bytes",
                        data_len
                    );
                }

                send_host_output_to_interface(interface, output)?;
            }
            Ok(AppEvent::Close) => {
                eprintln!("stdin closed; sending FIN when possible...");
                send_host_output_to_interface(interface, host.close())?;
            }
            Err(mpsc::TryRecvError::Empty | mpsc::TryRecvError::Disconnected) => return Ok(()),
        }
    }
}

fn send_host_output_to_interface(
    interface: &mut NetworkInterface,
    output: IpHostOutput,
) -> io::Result<()> {
    print_events(&output.events)?;

    for datagram in output.datagrams {
        let next_hop = datagram.header.dst;

        interface.send_datagram(datagram, next_hop);
    }

    Ok(())
}

fn flush_interface_frames(
    tap: &mut TapDevice,
    pcap: &mut Option<PcapWriter>,
    interface: &mut NetworkInterface,
) -> io::Result<()> {
    while let Some(frame) = interface.pop_frame() {
        let frame_bytes = frame.serialize();

        dump_packet(pcap, &frame_bytes)?;
        tap.write_frame(&frame_bytes)?;
    }

    Ok(())
}

fn dump_packet(pcap: &mut Option<PcapWriter>, packet: &[u8]) -> io::Result<()> {
    if let Some(writer) = pcap {
        writer.write_packet(packet)?;
    }

    Ok(())
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
            "--tap" => {
                i += 1;
                config.tap_name = require_arg(&args, i, "--tap")?.to_string();
            }
            "--local-mac" => {
                i += 1;
                config.local_mac = parse_mac(require_arg(&args, i, "--local-mac")?)?;
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
            "--pcap" => {
                i += 1;
                config.pcap_path = Some(PathBuf::from(require_arg(&args, i, "--pcap")?));
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

fn parse_mac(value: &str) -> io::Result<EthernetAddress> {
    let parts: Vec<&str> = value.split(':').collect();

    if parts.len() != 6 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "MAC address must have six colon-separated octets",
        ));
    }

    let mut octets = [0u8; 6];

    for (index, part) in parts.iter().enumerate() {
        if part.len() != 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "MAC address octets must be two hex digits",
            ));
        }

        octets[index] = u8::from_str_radix(part, 16)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    }

    Ok(EthernetAddress::new(octets))
}

fn print_help() {
    println!(
        "\
Usage:
  tap_host [OPTIONS]

Options:
  --tap NAME             TAP device name. Default: tap144
  --local-mac MAC        Rust Ethernet address. Default: 02:00:00:00:00:02
  --local-ip IP          Rust TCP stack IP. Default: 169.254.144.2
  --peer-ip IP           Linux/native TCP peer IP. Default: 169.254.144.1
  --local-port PORT      Rust local TCP port. Default: 50000
  --peer-port PORT       Native peer TCP port. Default: 9090
  --isn N                Initial sequence number. Default: 1000000
  --pcap PATH            Dump RX/TX Ethernet frames to classic pcap (LINKTYPE_ETHERNET)
  -h, --help             Show this help

Example:
  cargo run --bin tap_host -- \\
    --tap tap144 \\
    --local-mac 02:00:00:00:00:02 \\
    --local-ip 169.254.144.2 \\
    --peer-ip 169.254.144.1 \\
    --local-port 50000 \\
    --peer-port 9090 \\
    --pcap tap-host.pcap
"
    );
}
