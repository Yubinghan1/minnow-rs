#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::CString;
    use std::fs::{File, OpenOptions};
    use std::io::{self, Read, Write};
    use std::os::fd::{AsRawFd, RawFd};
    use std::path::Path;

    use bytes::Bytes;

    use crate::ipv4_datagram::Ipv4Datagram;

    pub const DEFAULT_TUN_NAME: &str = "tun144";
    pub const MAX_IPV4_PACKET_SIZE: usize = 65_535;

    const DEV_NET_TUN: &str = "/dev/net/tun";

    // Linux ioctl request for TUNSETIFF.
    //
    // Defined in Linux as:
    //   #define TUNSETIFF _IOW('T', 202, int)
    //
    // Common value on Linux:
    //   0x400454ca
    const TUNSETIFF: libc::c_ulong = 0x4004_54ca;

    /// A Linux TUN device.
    ///
    /// With IFF_NO_PI, every read returns a raw IP packet directly.
    ///
    /// Without IFF_NO_PI, Linux prepends a 4-byte packet-info header.
    /// We deliberately use IFF_NO_PI because our `Ipv4Datagram::parse()`
    /// expects byte zero to be the IPv4 header's version/IHL byte.
    #[derive(Debug)]
    pub struct TunDevice {
        file: File,
        name: String,
    }

    impl TunDevice {
        /// Attach to or create a Linux TUN device.
        ///
        /// If the named TUN device already exists and permissions allow it,
        /// this attaches to it.
        ///
        /// If it does not exist, creating it usually requires CAP_NET_ADMIN,
        /// meaning you may need `sudo`.
        pub fn create(name: &str) -> io::Result<Self> {
            validate_interface_name(name)?;

            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(Path::new(DEV_NET_TUN))?;

            let flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;

            let mut ifreq = IfReq::new(name, flags)?;

            let rc = unsafe { libc::ioctl(file.as_raw_fd(), TUNSETIFF, &mut ifreq) };

            if rc < 0 {
                return Err(io::Error::last_os_error());
            }

            let actual_name = ifreq_name_to_string(&ifreq.ifr_name);

            Ok(Self {
                file,
                name: actual_name,
            })
        }

        /// Name assigned by Linux.
        ///
        /// If you pass a concrete name like `tun144`, this should be `tun144`.
        /// If you pass a pattern like `tun%d`, Linux may pick a number.
        pub fn name(&self) -> &str {
            &self.name
        }

        /// Read one raw packet from the TUN device.
        ///
        /// This blocks unless the file descriptor is in nonblocking mode.
        pub fn read_packet(&mut self) -> io::Result<Vec<u8>> {
            let mut buffer = vec![0u8; MAX_IPV4_PACKET_SIZE];

            let len = self.file.read(&mut buffer)?;

            buffer.truncate(len);

            Ok(buffer)
        }

        /// Read one raw packet into a caller-provided buffer.
        ///
        /// Returns the number of bytes read.
        pub fn read_packet_into(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.file.read(buffer)
        }

        /// Read one IPv4 datagram from the TUN device.
        pub fn read_ipv4_datagram(&mut self) -> io::Result<Ipv4Datagram> {
            let packet = self.read_packet()?;

            Ipv4Datagram::parse(&packet).map_err(|err| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("failed to parse IPv4 datagram from TUN: {err:?}"),
                )
            })
        }

        /// Write one raw IP packet to the TUN device.
        pub fn write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
            if packet.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "cannot write an empty packet to TUN",
                ));
            }

            self.file.write_all(packet)
        }

        /// Write one IPv4 datagram to the TUN device.
        pub fn write_ipv4_datagram(&mut self, datagram: &Ipv4Datagram) -> io::Result<()> {
            let packet = datagram.serialize();

            self.write_packet(&packet)
        }

        /// Put the TUN file descriptor into nonblocking mode.
        ///
        /// Later, when we build an event loop around TUN + stdin + timers,
        /// nonblocking mode will be useful.
        pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
            let fd = self.file.as_raw_fd();

            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };

            if flags < 0 {
                return Err(io::Error::last_os_error());
            }

            let new_flags = if nonblocking {
                flags | libc::O_NONBLOCK
            } else {
                flags & !libc::O_NONBLOCK
            };

            let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, new_flags) };

            if rc < 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(())
        }

        /// Clone the underlying file descriptor.
        pub fn try_clone(&self) -> io::Result<Self> {
            Ok(Self {
                file: self.file.try_clone()?,
                name: self.name.clone(),
            })
        }

        /// Convenience helper used by future code when it already has Bytes.
        pub fn write_bytes(&mut self, packet: Bytes) -> io::Result<()> {
            self.write_packet(&packet)
        }
    }

    impl AsRawFd for TunDevice {
        fn as_raw_fd(&self) -> RawFd {
            self.file.as_raw_fd()
        }
    }

    /// Linux `struct ifreq` layout for the subset we need.
    ///
    /// Real C definition:
    ///
    /// ```c
    /// struct ifreq {
    ///     char ifr_name[IFNAMSIZ];
    ///     union {
    ///         short ifr_flags;
    ///         ...
    ///     };
    /// };
    /// ```
    ///
    /// On Linux, `IFNAMSIZ` is 16 and the union is large enough to make
    /// the whole struct 40 bytes on common architectures.
    ///
    /// We only need `ifr_name` and `ifr_flags`.
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct IfReq {
        ifr_name: [libc::c_char; libc::IFNAMSIZ],
        ifr_flags: libc::c_short,

        // Padding for the rest of the ifreq union.
        //
        // sizeof(union ifr_ifru) is commonly 24 bytes.
        // We already used 2 bytes for ifr_flags, so keep 22 bytes.
        _padding: [u8; 22],
    }

    impl IfReq {
        fn new(name: &str, flags: libc::c_short) -> io::Result<Self> {
            validate_interface_name(name)?;

            let mut ifreq = Self {
                ifr_name: [0; libc::IFNAMSIZ],
                ifr_flags: flags,
                _padding: [0; 22],
            };

            for (dst, src) in ifreq.ifr_name.iter_mut().zip(name.bytes()) {
                *dst = src as libc::c_char;
            }

            Ok(ifreq)
        }
    }

    fn validate_interface_name(name: &str) -> io::Result<()> {
        if name.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TUN interface name cannot be empty",
            ));
        }

        if name.as_bytes().contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TUN interface name cannot contain NUL bytes",
            ));
        }

        // Linux IFNAMSIZ includes the trailing NUL byte.
        if name.len() >= libc::IFNAMSIZ {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "TUN interface name is too long: {name:?}; maximum is {} bytes",
                    libc::IFNAMSIZ - 1
                ),
            ));
        }

        Ok(())
    }

    fn ifreq_name_to_string(name: &[libc::c_char; libc::IFNAMSIZ]) -> String {
        let nul_pos = name.iter().position(|&c| c == 0).unwrap_or(name.len());

        let bytes: Vec<u8> = name[..nul_pos].iter().map(|&c| c as u8).collect();

        String::from_utf8_lossy(&bytes).into_owned()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn rejects_empty_interface_name() {
            assert!(IfReq::new("", 0).is_err());
        }

        #[test]
        fn rejects_interface_name_with_nul() {
            assert!(IfReq::new("tun\0bad", 0).is_err());
        }

        #[test]
        fn rejects_too_long_interface_name() {
            let name = "a".repeat(libc::IFNAMSIZ);

            assert!(IfReq::new(&name, 0).is_err());
        }

        #[test]
        fn accepts_maximum_valid_interface_name_length() {
            let name = "a".repeat(libc::IFNAMSIZ - 1);

            let ifreq = IfReq::new(&name, 123).unwrap();

            assert_eq!(ifreq_name_to_string(&ifreq.ifr_name), name);
            assert_eq!(ifreq.ifr_flags, 123);
        }

        #[test]
        fn ifreq_stores_name_and_flags() {
            let flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;

            let ifreq = IfReq::new("tun144", flags).unwrap();

            assert_eq!(ifreq_name_to_string(&ifreq.ifr_name), "tun144");
            assert_eq!(ifreq.ifr_flags, flags);
        }

        #[test]
        fn ifreq_size_matches_common_linux_layout() {
            assert_eq!(std::mem::size_of::<IfReq>(), 40);
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(not(target_os = "linux"))]
mod unsupported {
    use std::io;

    use bytes::Bytes;

    use crate::ipv4_datagram::Ipv4Datagram;

    pub const DEFAULT_TUN_NAME: &str = "tun144";
    pub const MAX_IPV4_PACKET_SIZE: usize = 65_535;

    #[derive(Debug)]
    pub struct TunDevice;

    impl TunDevice {
        pub fn create(_name: &str) -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "TUN devices are supported by this implementation only on Linux",
            ))
        }

        pub fn name(&self) -> &str {
            "unsupported"
        }

        pub fn read_packet(&mut self) -> io::Result<Vec<u8>> {
            Err(unsupported())
        }

        pub fn read_packet_into(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(unsupported())
        }

        pub fn read_ipv4_datagram(&mut self) -> io::Result<Ipv4Datagram> {
            Err(unsupported())
        }

        pub fn write_packet(&mut self, _packet: &[u8]) -> io::Result<()> {
            Err(unsupported())
        }

        pub fn write_ipv4_datagram(&mut self, _datagram: &Ipv4Datagram) -> io::Result<()> {
            Err(unsupported())
        }

        pub fn set_nonblocking(&self, _nonblocking: bool) -> io::Result<()> {
            Err(unsupported())
        }

        pub fn try_clone(&self) -> io::Result<Self> {
            Err(unsupported())
        }

        pub fn write_bytes(&mut self, _packet: Bytes) -> io::Result<()> {
            Err(unsupported())
        }
    }

    fn unsupported() -> io::Error {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "TUN devices are supported by this implementation only on Linux",
        )
    }
}

#[cfg(not(target_os = "linux"))]
pub use unsupported::*;
