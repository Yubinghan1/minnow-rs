#[cfg(target_os = "linux")]
mod linux {
    use std::fs::{File, OpenOptions};
    use std::io::{self, Read, Write};
    use std::os::fd::{AsRawFd, RawFd};
    use std::path::Path;

    use bytes::Bytes;

    pub const DEFAULT_TAP_NAME: &str = "tap144";
    pub const MAX_ETHERNET_FRAME_SIZE: usize = 65_535;

    const DEV_NET_TUN: &str = "/dev/net/tun";
    const TUNSETIFF: libc::c_ulong = 0x4004_54ca;

    #[derive(Debug)]
    pub struct TapDevice {
        file: File,
        name: String,
    }

    impl TapDevice {
        pub fn create(name: &str) -> io::Result<Self> {
            validate_interface_name(name)?;

            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(Path::new(DEV_NET_TUN))?;

            let flags = (libc::IFF_TAP | libc::IFF_NO_PI) as libc::c_short;
            let mut ifreq = IfReq::new(name, flags)?;
            let rc = unsafe { libc::ioctl(file.as_raw_fd(), TUNSETIFF, &mut ifreq) };

            if rc < 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(Self {
                file,
                name: ifreq_name_to_string(&ifreq.ifr_name),
            })
        }

        pub fn name(&self) -> &str {
            &self.name
        }

        pub fn read_frame(&mut self) -> io::Result<Vec<u8>> {
            let mut buffer = vec![0u8; MAX_ETHERNET_FRAME_SIZE];
            let len = self.file.read(&mut buffer)?;

            buffer.truncate(len);

            Ok(buffer)
        }

        pub fn write_frame(&mut self, frame: &[u8]) -> io::Result<()> {
            if frame.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "cannot write an empty frame to TAP",
                ));
            }

            self.file.write_all(frame)
        }

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

        pub fn try_clone(&self) -> io::Result<Self> {
            Ok(Self {
                file: self.file.try_clone()?,
                name: self.name.clone(),
            })
        }

        pub fn write_bytes(&mut self, frame: Bytes) -> io::Result<()> {
            self.write_frame(&frame)
        }
    }

    impl AsRawFd for TapDevice {
        fn as_raw_fd(&self) -> RawFd {
            self.file.as_raw_fd()
        }
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct IfReq {
        ifr_name: [libc::c_char; libc::IFNAMSIZ],
        ifr_flags: libc::c_short,
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
                "TAP interface name cannot be empty",
            ));
        }

        if name.as_bytes().contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TAP interface name cannot contain NUL bytes",
            ));
        }

        if name.len() >= libc::IFNAMSIZ {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "TAP interface name is too long: {name:?}; maximum is {} bytes",
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
        fn ifreq_uses_tap_flags() {
            let flags = (libc::IFF_TAP | libc::IFF_NO_PI) as libc::c_short;
            let ifreq = IfReq::new("tap144", flags).unwrap();

            assert_eq!(ifreq_name_to_string(&ifreq.ifr_name), "tap144");
            assert_eq!(ifreq.ifr_flags, flags);
        }

        #[test]
        fn rejects_invalid_interface_names() {
            assert!(IfReq::new("", 0).is_err());
            assert!(IfReq::new("tap\0bad", 0).is_err());
            assert!(IfReq::new(&"a".repeat(libc::IFNAMSIZ), 0).is_err());
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(not(target_os = "linux"))]
mod unsupported {
    use std::io;

    use bytes::Bytes;

    pub const DEFAULT_TAP_NAME: &str = "tap144";
    pub const MAX_ETHERNET_FRAME_SIZE: usize = 65_535;

    #[derive(Debug)]
    pub struct TapDevice;

    impl TapDevice {
        pub fn create(_name: &str) -> io::Result<Self> {
            Err(unsupported())
        }

        pub fn name(&self) -> &str {
            "unsupported"
        }

        pub fn read_frame(&mut self) -> io::Result<Vec<u8>> {
            Err(unsupported())
        }

        pub fn write_frame(&mut self, _frame: &[u8]) -> io::Result<()> {
            Err(unsupported())
        }

        pub fn set_nonblocking(&self, _nonblocking: bool) -> io::Result<()> {
            Err(unsupported())
        }

        pub fn try_clone(&self) -> io::Result<Self> {
            Err(unsupported())
        }

        pub fn write_bytes(&mut self, _frame: Bytes) -> io::Result<()> {
            Err(unsupported())
        }
    }

    fn unsupported() -> io::Error {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "TAP devices are supported by this implementation only on Linux",
        )
    }
}

#[cfg(not(target_os = "linux"))]
pub use unsupported::*;
