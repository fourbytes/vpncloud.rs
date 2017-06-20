// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2016  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use std::os::unix::io::{AsRawFd, RawFd, FromRawFd};
use std::io::{self, Error as IoError, Read, Write};
use std::fs;
use std::fmt;
use std::ffi::CString;

use mio::{Poll, Token, Ready, PollOpt};
use mio::event::Evented;
use mio::unix::EventedFd;

use super::types::Error;

extern {
    fn setup_tap_device(fd: i32, ifname: *mut i8) -> i32;
    fn setup_tun_device(fd: i32, ifname: *mut i8) -> i32;
}


/// The type of a tun/tap device
#[derive(Deserialize, Debug, Clone, Copy, PartialEq)]
pub enum Type {
    /// Tun interface: This interface transports IP packets.
    #[serde(rename = "tun")]
    Tun,
    /// Tap interface: This insterface transports Ethernet frames.
    #[serde(rename = "tap")]
    Tap
}

impl fmt::Display for Type {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            Type::Tun => write!(formatter, "tun"),
            Type::Tap => write!(formatter, "tap"),
        }
    }
}


/// Represents a tun/tap device
pub struct Device {
    fd: fs::File,
    ifname: String,
    type_: Type,
}

impl Device {
    /// Creates a new tun/tap device
    ///
    /// This method creates a new device of the `type_` kind with the name `ifname`.
    ///
    /// The `ifname` must be an interface name not longer than 31 bytes. It can contain the string
    /// `%d` which will be replaced with the next free index number that guarantees that the
    /// interface name will be free. In this case, the `ifname()` method can be used to obtain the
    /// final interface name.
    ///
    /// # Errors
    /// This method will return an error when the underlying system call fails. Common cases are:
    /// - The special device file `/dev/net/tun` does not exist or is not accessible by the current
    ///   user.
    /// - The interface name is invalid or already in use.
    /// - The current user does not have enough permissions to create tun/tap devices (this
    ///   requires root permissions).
    ///
    /// # Panics
    /// This method panics if the interface name is longer than 31 bytes.
    #[cfg(any(target_os = "bitrig", target_os = "dragonfly",
        target_os = "freebsd", target_os = "ios", target_os = "macos",
        target_os = "netbsd", target_os = "openbsd"))]
    pub fn new(ifname: &str, type_: Type) -> io::Result<Self> {
        let ifname_c = CString::new(ifname).unwrap();
        assert!(ifname_c.to_bytes().len() <= 32);
        let ifname_ptr = ifname_c.into_raw();

        let res = match type_ {
            Type::Tun => unsafe { setup_tun_device(-1, ifname_ptr) },
            Type::Tap => unsafe { setup_tap_device(-1, ifname_ptr) }
        };
        match res {
            res if res > 0 => {
                let fd = unsafe { fs::File::from_raw_fd(res) };
                let ifname_c = unsafe { CString::from_raw(ifname_ptr) };

                Ok(Device{fd: fd, ifname: ifname_c.to_str().unwrap().to_string(), type_: type_})
            },
            _ => Err(IoError::last_os_error())
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn new(ifname: &str, type_: Type) -> io::Result<Self> {
        let fd = try!(fs::OpenOptions::new().read(true).write(true).open("/dev/net/tun"));

        let ifname_c = CString::new(ifname).unwrap();
        assert!(ifname_c.to_bytes().len() <= 32);
        let ifname_ptr = ifname_c.into_raw();
        let res = match type_ {
            Type::Tun => unsafe { setup_tun_device(fd.as_raw_fd(), ifname_ptr) },
            Type::Tap => unsafe { setup_tap_device(fd.as_raw_fd(), ifname_ptr) }
        };
        match res {
            res if res > 0 => {
                let fd = unsafe { fs::File::from_raw_fd(res) };
                let ifname_c = unsafe { CString::from_raw(ifname_ptr) };

                Ok(Device{fd: fd, ifname: ifname_c.to_str().unwrap().to_string(), type_: type_})
            },
            _ => Err(IoError::last_os_error())
        }
    }

    /// Returns the interface name of this device.
    #[inline]
    pub fn ifname(&self) -> &str {
        &self.ifname
    }

    /// Returns the type of this device
    #[allow(dead_code)]
    #[inline]
    pub fn get_type(&self) -> Type {
        self.type_
    }

    /// Creates a dummy device based on an existing file
    ///
    /// This method opens a regular or special file and reads from it to receive packets and
    /// writes to it to send packets. This method does not use a networking device and therefore
    /// can be used for testing.
    ///
    /// The parameter `path` is the file that should be used. Special files like `/dev/null`,
    /// named pipes and unix sockets can be used with this method.
    ///
    /// Both `ifname` and `type_` parameters have no effect.
    ///
    /// # Errors
    /// This method will return an error if the file can not be opened for reading and writing.
    #[allow(dead_code)]
    pub fn dummy(ifname: &str, path: &str, type_: Type) -> io::Result<Self> {
        Ok(Device{
            fd: try!(fs::OpenOptions::new().create(true).read(true).write(true).open(path)),
            ifname: ifname.to_string(),
            type_: type_
        })
    }

    /// Reads a packet/frame from the device
    ///
    /// This method reads one packet or frame (depending on the device type) into the `buffer`.
    /// The `buffer` must be large enough to hold a packet/frame of maximum size, otherwise the
    /// packet/frame will be split.
    /// The method will block until a packet/frame is ready to be read.
    /// On success, the method will return the starting position and the amount of bytes read into
    /// the buffer.
    ///
    /// # Errors
    /// This method will return an error if the underlying read call fails.
    #[inline]
    pub fn read(&mut self, mut buffer: &mut [u8]) -> Result<(usize, usize), Error> {
        let read = try!(self.fd.read(&mut buffer).map_err(|e| Error::TunTapDev("Read error", e)));
        let (start, read) = self.correct_data_after_read(&mut buffer, 0, read);
        Ok((start, read))
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[allow(unused_variables)]
    #[inline]
    fn correct_data_after_read(&mut self, _buffer: &mut [u8], start: usize, read: usize) -> (usize, usize) {
        (start, read)
    }

    #[cfg(any(target_os = "bitrig", target_os = "dragonfly",
        target_os = "freebsd", target_os = "ios", target_os = "macos",
        target_os = "netbsd", target_os = "openbsd"))]
    #[allow(unused_variables)]
    #[inline]
    fn correct_data_after_read(&mut self, buffer: &mut [u8], start: usize, read: usize) -> (usize, usize) {
        if self.type_ == Type::Tun {
            // BSD-based systems add a 4-byte header containing the Ethertype for TUN
            assert!(read>=4);
            (start+4, read-4)
        } else {
            (start, read)
        }
    }

    /// Writes a packet/frame to the device
    ///
    /// This method writes one packet or frame (depending on the device type) from `data` to the
    /// device. The data starts at the position `start` in the buffer. The buffer should have at
    /// least 4 bytes of space before the start of the packet.
    /// The method will block until the packet/frame has been written.
    ///
    /// # Errors
    /// This method will return an error if the underlying read call fails.
    #[inline]
    pub fn write(&mut self, mut data: &mut [u8], start: usize) -> Result<(), Error> {
        let start = self.correct_data_before_write(&mut data, start);
        match self.fd.write_all(&data[start..]) {
            Ok(_) => self.fd.flush().map_err(|e| Error::TunTapDev("Flush error", e)),
            Err(e) => Err(Error::TunTapDev("Write error", e))
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[inline]
    fn correct_data_before_write(&mut self, _buffer: &mut [u8], start: usize) -> usize {
        start
    }

    #[cfg(any(target_os = "bitrig", target_os = "dragonfly",
        target_os = "freebsd", target_os = "ios", target_os = "macos",
        target_os = "netbsd", target_os = "openbsd"))]
    #[inline]
    fn correct_data_before_write(&mut self, buffer: &mut [u8], start: usize) -> usize {
        if self.type_ == Type::Tun {
            // BSD-based systems add a 4-byte header containing the Ethertype for TUN
            assert!(start>=4);
            match buffer[start] >> 4 { // IP version
                4 => buffer[start-4..start].copy_from_slice(&[0x00, 0x00, 0x08, 0x00]),
                6 => buffer[start-4..start].copy_from_slice(&[0x00, 0x00, 0x86, 0xdd]),
                _ => unreachable!()
            }
            start-4
        } else {
            start
        }
    }
}

impl AsRawFd for Device {
    #[inline]
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl Evented for Device {
    fn register(&self, poll: &Poll, token: Token, interest: Ready, opts: PollOpt)
        -> io::Result<()>
    {
        EventedFd(&self.as_raw_fd()).register(poll, token, interest, opts)
    }

    fn reregister(&self, poll: &Poll, token: Token, interest: Ready, opts: PollOpt)
        -> io::Result<()>
    {
        EventedFd(&self.as_raw_fd()).reregister(poll, token, interest, opts)
    }

    fn deregister(&self, poll: &Poll) -> io::Result<()> {
        EventedFd(&self.as_raw_fd()).deregister(poll)
    }
}
