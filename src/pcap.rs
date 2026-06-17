use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const PCAP_MAGIC_LE: u32 = 0xa1b2c3d4;
const PCAP_VERSION_MAJOR: u16 = 2;
const PCAP_VERSION_MINOR: u16 = 4;
const PCAP_SNAPLEN: u32 = 65_535;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcapLinkType {
    Ethernet,
    RawIpv4,
}

impl PcapLinkType {
    const fn code(self) -> u32 {
        match self {
            Self::Ethernet => 1,
            Self::RawIpv4 => 101,
        }
    }
}

pub struct PcapWriter {
    writer: BufWriter<File>,
}

impl PcapWriter {
    pub fn create(path: impl AsRef<Path>, link_type: PcapLinkType) -> io::Result<Self> {
        let file = File::create(path)?;
        let mut writer = Self {
            writer: BufWriter::new(file),
        };

        writer.write_global_header(link_type)?;

        Ok(writer)
    }

    pub fn write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?;
        let len = u32::try_from(packet.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "pcap packet length exceeds u32::MAX",
            )
        })?;

        self.writer
            .write_all(&(timestamp.as_secs() as u32).to_le_bytes())?;
        self.writer
            .write_all(&timestamp.subsec_micros().to_le_bytes())?;
        self.writer.write_all(&len.to_le_bytes())?;
        self.writer.write_all(&len.to_le_bytes())?;
        self.writer.write_all(packet)
    }

    fn write_global_header(&mut self, link_type: PcapLinkType) -> io::Result<()> {
        self.writer.write_all(&PCAP_MAGIC_LE.to_le_bytes())?;
        self.writer.write_all(&PCAP_VERSION_MAJOR.to_le_bytes())?;
        self.writer.write_all(&PCAP_VERSION_MINOR.to_le_bytes())?;
        self.writer.write_all(&0i32.to_le_bytes())?;
        self.writer.write_all(&0u32.to_le_bytes())?;
        self.writer.write_all(&PCAP_SNAPLEN.to_le_bytes())?;
        self.writer.write_all(&link_type.code().to_le_bytes())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn writes_classic_pcap_with_raw_linktype() {
        let path =
            std::env::temp_dir().join(format!("minnow-rs-pcap-test-{}.pcap", std::process::id()));
        let packet = [
            0x45, 0x00, 0x00, 0x14, 0, 0, 0x40, 0, 64, 1, 0, 0, 127, 0, 0, 1, 127, 0, 0, 1,
        ];

        {
            let mut writer = PcapWriter::create(&path, PcapLinkType::RawIpv4).unwrap();
            writer.write_packet(&packet).unwrap();
        }

        let bytes = fs::read(&path).unwrap();
        let _ = fs::remove_file(&path);

        assert_eq!(&bytes[0..4], &[0xd4, 0xc3, 0xb2, 0xa1]);
        assert_eq!(
            u32::from_le_bytes(bytes[20..24].try_into().unwrap()),
            PcapLinkType::RawIpv4.code()
        );
        assert_eq!(
            u32::from_le_bytes(bytes[32..36].try_into().unwrap()),
            packet.len() as u32
        );
        assert_eq!(&bytes[40..], &packet);
    }

    #[test]
    fn writes_ethernet_linktype() {
        let path = std::env::temp_dir().join(format!(
            "minnow-rs-ethernet-pcap-test-{}.pcap",
            std::process::id()
        ));

        {
            let mut writer = PcapWriter::create(&path, PcapLinkType::Ethernet).unwrap();
            writer.write_packet(&[0xff; 14]).unwrap();
        }

        let bytes = fs::read(&path).unwrap();
        let _ = fs::remove_file(&path);

        assert_eq!(
            u32::from_le_bytes(bytes[20..24].try_into().unwrap()),
            PcapLinkType::Ethernet.code()
        );
    }
}
