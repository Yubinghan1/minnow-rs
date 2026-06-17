use std::env;
use std::io;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use bytes::Bytes;
use minnow_rs::ip_host::{IpHost, IpHostConfig, IpHostOutput};
use minnow_rs::pcap::{PcapLinkType, PcapWriter};
use minnow_rs::tun::{DEFAULT_TUN_NAME, TunDevice};
use minnow_rs::wrapping_integers::Wrap32;

#[path = "common/host_cli.rs"]
mod host_cli;

use host_cli::{
    AppEvent, fmt_ip, parse_ipv4, parse_port, print_events, require_arg, spawn_stdin_thread,
};

const DEFAULT_LOCAL_IP: [u8; 4] = [169, 254, 144, 2];
const DEFAULT_PEER_IP: [u8; 4] = [169, 254, 144, 1];
const DEFAULT_LOCAL_PORT: u16 = 50_000;
const DEFAULT_PEER_PORT: u16 = 9_090;
const POLL_INTERVAL_MS: u64 = 10;

#[derive(Debug, Clone)]
struct Config {
    tun_name: String,
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
            tun_name: DEFAULT_TUN_NAME.to_string(),
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

    eprintln!("=== minnow-rs tun_host ===");
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
    if let Some(path) = &config.pcap_path {
        eprintln!("pcap       : {} (RAW IPv4)", path.display());
    }
    eprintln!();

    let mut tun = TunDevice::create(&config.tun_name)?;
    tun.set_nonblocking(true)?;
    let mut pcap = config
        .pcap_path
        .as_ref()
        .map(|path| PcapWriter::create(path, PcapLinkType::RawIpv4))
        .transpose()?;

    eprintln!("opened TUN device: {}", tun.name());

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
    emit_output(&mut tun, &mut pcap, host.connect())?;

    eprintln!("type text and press Enter to send it over your Rust TCP stack.");
    eprintln!("press Ctrl-D to close outbound stream.");
    eprintln!();

    let mut last_tick = Instant::now();
    let mut was_established = false;

    loop {
        drain_tun_packets(&mut tun, &mut pcap, &mut host)?;
        drain_app_events(&mut tun, &mut pcap, &mut host, &app_rx)?;

        let now = Instant::now();
        let elapsed_ms = now.duration_since(last_tick).as_millis() as u64;

        if elapsed_ms > 0 {
            last_tick = now;
            emit_output(&mut tun, &mut pcap, host.tick(elapsed_ms))?;
        }

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

fn drain_tun_packets(
    tun: &mut TunDevice,
    pcap: &mut Option<PcapWriter>,
    host: &mut IpHost,
) -> io::Result<()> {
    loop {
        match tun.read_packet() {
            Ok(packet) => {
                dump_packet(pcap, &packet)?;
                emit_output(tun, pcap, host.receive_ipv4_bytes(Bytes::from(packet)))?;
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
}

fn drain_app_events(
    tun: &mut TunDevice,
    pcap: &mut Option<PcapWriter>,
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

                emit_output(tun, pcap, output)?;
            }
            Ok(AppEvent::Close) => {
                eprintln!("stdin closed; sending FIN when possible...");
                emit_output(tun, pcap, host.close())?;
            }
            Err(mpsc::TryRecvError::Empty | mpsc::TryRecvError::Disconnected) => return Ok(()),
        }
    }
}

fn emit_output(
    tun: &mut TunDevice,
    pcap: &mut Option<PcapWriter>,
    output: IpHostOutput,
) -> io::Result<()> {
    print_events(&output.events)?;

    for datagram in output.datagrams {
        let packet = datagram.serialize();

        dump_packet(pcap, &packet)?;
        tun.write_packet(&packet)?;
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

fn print_help() {
    println!(
        "\
Usage:
  tun_host [OPTIONS]

Options:
  --tun NAME             TUN device name. Default: tun144
  --local-ip IP          Rust TCP stack IP. Default: 169.254.144.2
  --peer-ip IP           Linux/native TCP peer IP. Default: 169.254.144.1
  --local-port PORT      Rust local TCP port. Default: 50000
  --peer-port PORT       Native peer TCP port. Default: 9090
  --isn N                Initial sequence number. Default: 1000000
  --pcap PATH            Dump RX/TX IPv4 packets to classic pcap (LINKTYPE_RAW)
  -h, --help             Show this help

Example:
  cargo run --bin tun_host -- \\
    --tun tun144 \\
    --local-ip 169.254.144.2 \\
    --peer-ip 169.254.144.1 \\
    --local-port 50000 \\
    --peer-port 9090 \\
    --pcap tun-host.pcap
"
    );
}
