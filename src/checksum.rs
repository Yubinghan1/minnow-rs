/// Internet checksum utilities.
///
/// Used by IPv4 header checksum and TCP checksum.
///
/// Algorithm:
///
/// 1. Split bytes into 16-bit big-endian words.
/// 2. Add using one's-complement arithmetic.
/// 3. Fold carries back into the low 16 bits.
/// 4. Return the one's complement.
#[derive(Debug, Clone, Copy, Default)]
pub struct InternetChecksum {
    sum: u32,
    odd_byte: Option<u8>,
}

impl InternetChecksum {
    pub fn new() -> Self {
        Self {
            sum: 0,
            odd_byte: None,
        }
    }

    /// Add bytes into the checksum accumulator.
    ///
    /// This method supports incremental updates. If a previous call ended
    /// with an odd byte, the next call completes the 16-bit word.
    pub fn add_bytes(&mut self, data: &[u8]) {
        let mut index = 0;

        if let Some(high) = self.odd_byte.take() {
            if let Some(&low) = data.first() {
                self.sum += u16::from_be_bytes([high, low]) as u32;
                index = 1;
            } else {
                self.odd_byte = Some(high);
                return;
            }
        }

        while index + 1 < data.len() {
            self.sum += u16::from_be_bytes([data[index], data[index + 1]]) as u32;

            index += 2;
        }

        if index < data.len() {
            self.odd_byte = Some(data[index]);
        }
    }

    /// Finalize and return the Internet checksum.
    pub fn checksum(mut self) -> u16 {
        if let Some(high) = self.odd_byte.take() {
            self.sum += u16::from_be_bytes([high, 0]) as u32;
        }

        while (self.sum >> 16) != 0 {
            self.sum = (self.sum & 0xffff) + (self.sum >> 16);
        }

        !(self.sum as u16)
    }
}

/// Compute the Internet checksum over one byte slice.
pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut checksum = InternetChecksum::new();
    checksum.add_bytes(data);
    checksum.checksum()
}

/// Verify a packet/header that already contains its checksum field.
///
/// For a valid Internet-checksummed byte sequence, recomputing the checksum
/// over the complete sequence should produce zero.
pub fn verify_internet_checksum(data: &[u8]) -> bool {
    internet_checksum(data) == 0
}

/// Compute TCP checksum over IPv4 pseudo-header plus TCP segment bytes.
///
/// The TCP checksum covers:
///
/// - source IPv4 address
/// - destination IPv4 address
/// - zero byte
/// - protocol number
/// - TCP length
/// - TCP header and payload
pub fn tcp_checksum_ipv4(src_ip: [u8; 4], dst_ip: [u8; 4], tcp_segment: &[u8]) -> u16 {
    assert!(
        tcp_segment.len() <= u16::MAX as usize,
        "TCP segment too large for IPv4 pseudo-header length"
    );

    let tcp_len = tcp_segment.len() as u16;

    let mut checksum = InternetChecksum::new();

    checksum.add_bytes(&src_ip);
    checksum.add_bytes(&dst_ip);
    checksum.add_bytes(&[0]);
    checksum.add_bytes(&[6]); // TCP protocol number
    checksum.add_bytes(&tcp_len.to_be_bytes());
    checksum.add_bytes(tcp_segment);

    checksum.checksum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_of_empty_data_is_ffff() {
        assert_eq!(internet_checksum(&[]), 0xffff);
    }

    #[test]
    fn checksum_handles_even_length_data() {
        let data = [0x00, 0x01, 0xf2, 0x03];

        assert_eq!(internet_checksum(&data), 0x0dfb);
    }

    #[test]
    fn checksum_handles_odd_length_data() {
        let data = [0x00, 0x01, 0xf2];

        assert_eq!(internet_checksum(&data), 0x0dfe);
    }

    #[test]
    fn checksum_verifies_header_with_checksum_inserted() {
        let mut data = vec![0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x40, 0x00];
        data.extend_from_slice(&[64, 6, 0x00, 0x00]);
        data.extend_from_slice(&[127, 0, 0, 1]);
        data.extend_from_slice(&[127, 0, 0, 1]);

        let checksum = internet_checksum(&data);

        data[10] = (checksum >> 8) as u8;
        data[11] = checksum as u8;

        assert!(verify_internet_checksum(&data));
    }

    #[test]
    fn incremental_checksum_matches_one_shot() {
        let data = b"hello world";

        let mut incremental = InternetChecksum::new();
        incremental.add_bytes(&data[..3]);
        incremental.add_bytes(&data[3..8]);
        incremental.add_bytes(&data[8..]);

        assert_eq!(incremental.checksum(), internet_checksum(data));
    }

    #[test]
    fn tcp_checksum_ipv4_is_stable() {
        let src = [10, 0, 0, 1];
        let dst = [10, 0, 0, 2];

        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&1234u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&80u16.to_be_bytes());
        tcp[12] = 5u8 << 4;

        let csum = tcp_checksum_ipv4(src, dst, &tcp);

        tcp[16..18].copy_from_slice(&csum.to_be_bytes());

        assert_eq!(tcp_checksum_ipv4(src, dst, &tcp), 0);
    }
}
