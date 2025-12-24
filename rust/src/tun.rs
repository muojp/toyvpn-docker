use anyhow::{Context, Result};
use nix::libc;
use std::fs::File;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use tokio::io::unix::AsyncFd;

const TUNSETIFF: libc::c_ulong = 0x400454ca;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;

#[repr(C)]
struct IfReq {
    ifr_name: [u8; libc::IF_NAMESIZE],
    ifr_flags: libc::c_short,
    _padding: [u8; 24 - std::mem::size_of::<libc::c_short>()],
}

/// TUN device interface
pub struct TunDevice {
    file: AsyncFd<File>,
    name: String,
}

impl TunDevice {
    /// Create a new TUN device with the given name
    pub fn new(name: &str) -> Result<Self> {
        unsafe {
            let fd = libc::open(
                b"/dev/net/tun\0".as_ptr() as *const libc::c_char,
                libc::O_RDWR | libc::O_NONBLOCK,
            );

            if fd < 0 {
                anyhow::bail!("Cannot open /dev/net/tun");
            }

            let mut ifr = IfReq {
                ifr_name: [0u8; libc::IF_NAMESIZE],
                ifr_flags: IFF_TUN | IFF_NO_PI,
                _padding: [0u8; 24 - std::mem::size_of::<libc::c_short>()],
            };

            let name_bytes = name.as_bytes();
            let copy_len = std::cmp::min(name_bytes.len(), libc::IF_NAMESIZE - 1);
            ifr.ifr_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

            if libc::ioctl(fd, TUNSETIFF, &ifr) < 0 {
                libc::close(fd);
                anyhow::bail!("Cannot get TUN interface");
            }

            let file = File::from_raw_fd(fd);
            let async_fd = AsyncFd::new(file).context("Failed to create AsyncFd for TUN device")?;

            Ok(Self {
                file: async_fd,
                name: name.to_string(),
            })
        }
    }

    /// Read a packet from the TUN interface
    pub async fn read_packet(&self, buf: &mut [u8]) -> Result<usize> {
        loop {
            let mut guard = self.file.readable().await?;

            match guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                unsafe {
                    let n = libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len());
                    if n < 0 {
                        Err(std::io::Error::last_os_error())
                    } else {
                        Ok(n as usize)
                    }
                }
            }) {
                Ok(result) => return result.context("Failed to read from TUN device"),
                Err(_would_block) => continue,
            }
        }
    }

    /// Write a packet to the TUN interface
    pub async fn write_packet(&self, data: &[u8]) -> Result<usize> {
        loop {
            let mut guard = self.file.writable().await?;

            match guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                unsafe {
                    let n = libc::write(fd, data.as_ptr() as *const libc::c_void, data.len());
                    if n < 0 {
                        Err(std::io::Error::last_os_error())
                    } else {
                        Ok(n as usize)
                    }
                }
            }) {
                Ok(result) => return result.context("Failed to write to TUN device"),
                Err(_would_block) => continue,
            }
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    #[allow(dead_code)]
    pub fn raw_fd(&self) -> RawFd {
        self.file.get_ref().as_raw_fd()
    }
}
