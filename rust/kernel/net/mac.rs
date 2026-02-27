// SPDX-License-Identifier: GPL-2.0

//! Network address types.
//!
//! This module provides types for IP and MAC addresses, with helpers like
//! formatting and parsing.

use kernel::fmt;
use kernel::prelude::*;

/// A MAC address.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct MacAddr(pub [u8; Self::ALEN]);

impl MacAddr {
    /// MAC address length in bytes.
    pub const ALEN: usize = 6;
    /// MAC broadcast address (E.g. 'ff:ff:ff:ff:ff:ff').
    pub const BROADCAST: MacAddr = MacAddr([0xff; Self::ALEN]);

    /// Creates a new MAC address from a byte array.
    pub const fn new(bytes: [u8; Self::ALEN]) -> Self {
        Self(bytes)
    }

    /// Parses a MAC address from a byte slice.
    ///
    /// ```rust
    /// use kernel::net::MacAddr;
    ///
    /// let addr = MacAddr::parse_ascii(b"aa:bb:cc:11:22:33").unwrap();
    /// assert_eq!(MacAddr::new([0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33]), addr);
    ///
    /// let addr = MacAddr::parse_ascii(b"aa-bb-cc-11-22-33").unwrap();
    /// assert_eq!(MacAddr::new([0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33]), addr);
    ///
    /// # Ok::<(), Error>(())
    /// ```
    pub fn parse_ascii(bytes: &[u8]) -> Result<Self> {
        let trimmed = trim_newline(bytes);
        if trimmed.len() < 17 {
            return Err(EINVAL);
        }

        let mut mac = [0u8; Self::ALEN];
        let mut i = 0;
        let mut byte_idx = 0;

        while byte_idx < Self::ALEN && i + 1 < trimmed.len() {
            let hi = hex_digit(trimmed[i])?;
            let lo = hex_digit(trimmed[i + 1])?;
            mac[byte_idx] = (hi << 4) | lo;
            byte_idx += 1;
            i += 2;
            if byte_idx < Self::ALEN && i < trimmed.len() {
                if trimmed[i] == b':' || trimmed[i] == b'-' {
                    i += 1;
                }
            }
        }

        if byte_idx != Self::ALEN {
            return Err(EINVAL);
        }

        // Reject trailing input beyond the expected 17 characters.
        if i != trimmed.len() {
            return Err(EINVAL);
        }

        Ok(Self::new(mac))
    }

    /// Formats the MAC address into a byte buffer as colon-separated hex.
    ///
    /// Returns the number of bytes written. The buffer must be at least 17 bytes
    /// (for "xx:xx:xx:xx:xx:xx").
    ///
    /// ```rust
    /// use kernel::net::MacAddr;
    ///
    /// let addr = MacAddr::new([
    ///     0xab, 0xcd, 0xef, 0x12, 0x34, 0x56,
    /// ]);
    /// let mut buf = [0u8; 20];
    /// let len = addr.format_into(&mut buf);
    ///
    /// assert_eq!(b"ab:cd:ef:12:34:56", &buf[..len]);
    ///
    /// # Ok::<(), Error>(())
    /// ```
    pub fn format_into(&self, buf: &mut [u8]) -> usize {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut pos = 0;

        for (i, &byte) in self.0.iter().enumerate() {
            if i > 0 {
                buf[pos] = b':';
                pos += 1;
            }
            buf[pos] = HEX[(byte >> 4) as usize];
            buf[pos + 1] = HEX[(byte & 0xf) as usize];
            pos += 2;
        }
        pos
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Length: "xx:xx:xx:xx:xx:xx" = 17 bytes
        let mut buf = [0u8; 17];
        let len = self.format_into(&mut buf);
        // SAFETY: format_into only writes ASCII hex digits and colons
        let s = unsafe { core::str::from_utf8_unchecked(&buf[..len]) };
        f.write_str(s)
    }
}

impl core::ops::Deref for MacAddr {
    type Target = [u8; Self::ALEN];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl core::ops::DerefMut for MacAddr {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Convert a hex digit to its value.
fn hex_digit(c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(EINVAL),
    }
}

/// Trim trailing newline from a byte slice.
fn trim_newline(s: &[u8]) -> &[u8] {
    let mut len = s.len();
    while len > 0 && (s[len - 1] == b'\n' || s[len - 1] == b'\r') {
        len -= 1;
    }
    &s[..len]
}

#[kunit_tests(rust_kernel_net_addrs)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_roundtrip() {
        for addr in [
            "aa:bb:cc:11:22:33",
            "00:00:00:00:00:01",
        ] {
            let parsed = MacAddr::parse_ascii(addr.as_bytes()).unwrap();
            let mut buf = [0u8; 17];
            parsed.format_into(&mut buf);
            assert_eq!(addr.as_bytes(), &buf[..]);
        }

        for addr in [
            // error cases
            "aa:bb:cc:11",
            "aa:bb:cc:11:22:33:44",
        ] {
            assert!(MacAddr::parse_ascii(addr.as_bytes()).is_err());
        }
    }
}
