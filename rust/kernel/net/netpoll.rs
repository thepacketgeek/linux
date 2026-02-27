// SPDX-License-Identifier: GPL-2.0

//! Network polling for console/debug output.
//!
//! This module provides safe Rust wrappers for the kernel's netpoll subsystem,
//! which enables IRQ-safe UDP packet transmission for network console logging.
//!
//! C header: [`include/linux/netpoll.h`](srctree/include/linux/netpoll.h)

use core::net::Ipv4Addr;
use core::net::Ipv6Addr;
use core::net::IpAddr;
use crate::{
    bindings,
    error::{
        to_result,
        Result, //
    },
    net::MacAddr,
    prelude::*,
    str::CStr,
    types::Opaque,
};

/// Maximum size of a device name (IFNAMSIZ in C).
pub const IFNAMSIZ: usize = 16;

/// A netpoll instance for UDP transmission.
///
/// This wraps the kernel's `struct netpoll` and provides safe access
/// to netpoll functionality for sending UDP packets in IRQ context.
///
/// # Invariants
///
/// - `inner` contains a valid, initialized `netpoll` structure.
/// - When enabled, the netpoll has been set up via `netpoll_setup`.
#[pin_data(PinnedDrop)]
pub struct Netpoll {
    #[pin]
    inner: Opaque<bindings::netpoll>,
    /// Whether the netpoll has been successfully set up.
    enabled: bool,
}

// SAFETY: Netpoll can be sent between threads.
unsafe impl Send for Netpoll {}

// SAFETY: Netpoll operations are synchronized by the caller.
unsafe impl Sync for Netpoll {}

impl Netpoll {
    /// Creates a builder for configuring a new netpoll.
    pub fn builder() -> NetpollBuilder {
        NetpollBuilder::new()
    }

    /// Sends a UDP packet with the given message.
    ///
    /// This function is IRQ-safe and can be called from any context.
    /// Returns the result of the transmission.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `self` has been properly set up
    /// (i.e., `enabled` is true).
    pub fn send_udp(&self, msg: &[u8]) -> Result<i32> {
        if !self.enabled {
            return Err(ENODEV);
        }

        // SAFETY: We have verified that the netpoll is enabled.
        // The inner pointer is valid per the type invariants.
        let ret = unsafe {
            bindings::netpoll_send_udp(self.inner.get(), msg.as_ptr().cast(), msg.len() as i32)
        };

        if ret < 0 {
            Err(Error::from_errno(ret))
        } else {
            Ok(ret)
        }
    }

    /// Returns the device name.
    pub fn dev_name(&self) -> &CStr {
        // SAFETY: The inner pointer is valid and dev_name is a fixed-size array.
        unsafe {
            let np = self.inner.get();
            CStr::from_char_ptr((*np).dev_name.as_ptr())
        }
    }

    /// Returns the local port number.
    pub fn local_port(&self) -> u16 {
        // SAFETY: The inner pointer is valid.
        unsafe { (*self.inner.get()).local_port }
    }

    /// Returns the remote port number.
    pub fn remote_port(&self) -> u16 {
        // SAFETY: The inner pointer is valid.
        unsafe { (*self.inner.get()).remote_port }
    }

    /// Returns whether the netpoll is using IPv6.
    pub fn is_ipv6(&self) -> bool {
        // SAFETY: The inner pointer is valid.
        unsafe { (*self.inner.get()).ipv6 }
    }

    /// Returns whether the netpoll is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Returns a pointer to the underlying netpoll struct.
    pub fn as_ptr(&self) -> *mut bindings::netpoll {
        self.inner.get()
    }
}

#[pinned_drop]
impl PinnedDrop for Netpoll {
    fn drop(self: Pin<&mut Self>) {
        if self.enabled {
            // SAFETY: We only call cleanup if the netpoll was successfully set up.
            unsafe { bindings::netpoll_cleanup(self.inner.get()) };
        }
    }
}

/// Builder for creating and configuring a [`Netpoll`] instance.
pub struct NetpollBuilder {
    name: Option<&'static CStr>,
    dev_name: [u8; IFNAMSIZ],
    local_port: u16,
    remote_port: u16,
    local_ip: IpAddr,
    remote_ip: IpAddr,
    remote_mac: MacAddr,
    ipv6: bool,
}

impl NetpollBuilder {
    /// Creates a new builder with default values.
    pub fn new() -> Self {
        // Set broadcast MAC address as default.
        let remote_mac = MacAddr::BROADCAST;

        Self {
            name: None,
            dev_name: [0u8; IFNAMSIZ],
            local_port: 6665,
            remote_port: 6666,
            local_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            remote_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            remote_mac,
            ipv6: false,
        }
    }

    /// Sets the name of this netpoll instance.
    pub fn name(mut self, name: &'static CStr) -> Self {
        self.name = Some(name);
        self
    }

    /// Sets the network device name.
    pub fn dev_name(mut self, name: &CStr) -> Result<Self> {
        let bytes = name.to_bytes_with_nul();
        if bytes.len() > IFNAMSIZ {
            return Err(EINVAL);
        }
        self.dev_name[..bytes.len()].copy_from_slice(bytes);
        Ok(self)
    }

    /// Sets the network device name from a byte slice.
    pub fn dev_name_bytes(mut self, name: &[u8]) -> Result<Self> {
        if name.len() >= IFNAMSIZ {
            return Err(EINVAL);
        }
        self.dev_name[..name.len()].copy_from_slice(name);
        self.dev_name[name.len()] = 0; // Null terminate
        Ok(self)
    }

    /// Sets the local port number.
    pub fn local_port(mut self, port: u16) -> Self {
        self.local_port = port;
        self
    }

    /// Sets the remote port number.
    pub fn remote_port(mut self, port: u16) -> Self {
        self.remote_port = port;
        self
    }

    /// Sets the local IP address.
    pub fn local_ip(self, addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(addr) => self.local_ip_v4(addr),
            IpAddr::V6(addr) => self.local_ip_v6(addr),
        }
    }

    /// Sets the local IPv4 address.
    pub fn local_ip_v4(mut self, addr: Ipv4Addr) -> Self {
        self.local_ip = IpAddr::V4(addr);
        self.ipv6 = false;
        self
    }

    /// Sets the local IPv6 address.
    pub fn local_ip_v6(mut self, addr: Ipv6Addr) -> Self {
        self.local_ip = IpAddr::V6(addr);
        self.ipv6 = true;
        self
    }

    /// Sets the remote IP address.
    pub fn remote_ip(self, addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(addr) => self.remote_ip_v4(addr),
            IpAddr::V6(addr) => self.remote_ip_v6(addr),
        }
    }

    /// Sets the remote IPv4 address.
    pub fn remote_ip_v4(mut self, addr: Ipv4Addr) -> Self {
        self.remote_ip = IpAddr::V4(addr);
        self.ipv6 = false;
        self
    }

    /// Sets the remote IPv6 address.
    pub fn remote_ip_v6(mut self, addr: Ipv6Addr) -> Self {
        self.remote_ip = IpAddr::V6(addr);
        self.ipv6 = true;
        self
    }

    /// Sets the remote MAC address.
    pub fn remote_mac(mut self, mac: MacAddr) -> Self {
        self.remote_mac = mac;
        self
    }

    /// Builds and sets up the netpoll.
    ///
    /// This performs the actual netpoll setup with the kernel.
    pub fn setup(self) -> impl PinInit<Netpoll, Error> {
        try_pin_init!(Netpoll {
            inner <- Opaque::try_ffi_init(move |slot: *mut bindings::netpoll| {
                // SAFETY: `slot` is valid for writing.
                unsafe {
                    // Zero-initialize the struct.
                    core::ptr::write_bytes(slot, 0, 1);

                    // Set the name pointer.
                    if let Some(name) = self.name {
                        (*slot).name = name.as_char_ptr();
                    } else {
                        (*slot).name = c"netconsole".as_char_ptr();
                    }

                    // Copy device name.
                    let dev_name_ptr = (*slot).dev_name.as_mut_ptr();
                    core::ptr::copy_nonoverlapping(
                        self.dev_name.as_ptr().cast(),
                        dev_name_ptr,
                        IFNAMSIZ,
                    );

                    // Set ports.
                    (*slot).local_port = self.local_port;
                    (*slot).remote_port = self.remote_port;

                    // Set IP addresses.
                    (*slot).ipv6 = self.ipv6;
                    match self.local_ip {
                        IpAddr::V4(addr) => {
                            (*slot).local_ip.ip = u32::from(addr).to_be();
                        }
                        IpAddr::V6(addr) => {
                            (*slot).local_ip.in6.in6_u.u6_addr8 = addr.octets();
                        }
                    }
                    match self.remote_ip {
                        IpAddr::V4(addr) => {
                            (*slot).remote_ip.ip = u32::from(addr).to_be();
                        }
                        IpAddr::V6(addr) => {
                            (*slot).remote_ip.in6.in6_u.u6_addr8 = addr.octets();
                        }
                    }

                    // Set remote MAC.
                    core::ptr::copy_nonoverlapping(
                        self.remote_mac.as_ptr(),
                        (*slot).remote_mac.as_mut_ptr(),
                        MacAddr::ALEN,
                    );

                    // Call netpoll_setup.
                    let ret = bindings::netpoll_setup(slot);
                    to_result(ret)
                }
            }),
            enabled: true,
        })
    }

    /// Creates a netpoll without calling setup.
    ///
    /// The netpoll will need to be set up later before use.
    pub fn build_uninitialized(self) -> impl PinInit<Netpoll, Error> {
        try_pin_init!(Netpoll {
            inner <- Opaque::try_ffi_init(move |slot: *mut bindings::netpoll| {
                // SAFETY: `slot` is valid for writing.
                unsafe {
                    // Zero-initialize the struct.
                    core::ptr::write_bytes(slot, 0, 1);

                    // Set the name pointer.
                    if let Some(name) = self.name {
                        (*slot).name = name.as_char_ptr();
                    } else {
                        (*slot).name = c"netconsole".as_char_ptr();
                    }

                    // Copy device name.
                    let dev_name_ptr = (*slot).dev_name.as_mut_ptr();
                    core::ptr::copy_nonoverlapping(
                        self.dev_name.as_ptr().cast(),
                        dev_name_ptr,
                        IFNAMSIZ,
                    );

                    // Set ports.
                    (*slot).local_port = self.local_port;
                    (*slot).remote_port = self.remote_port;

                    // Set IP addresses.
                    (*slot).ipv6 = self.ipv6;
                    match self.local_ip {
                        IpAddr::V4(addr) => {
                            (*slot).local_ip.ip = u32::from(addr).to_be();
                        }
                        IpAddr::V6(addr) => {
                            (*slot).local_ip.in6.in6_u.u6_addr8 = addr.octets();
                        }
                    }
                    match self.remote_ip {
                        IpAddr::V4(addr) => {
                            (*slot).remote_ip.ip = u32::from(addr).to_be();
                        }
                        IpAddr::V6(addr) => {
                            (*slot).remote_ip.in6.in6_u.u6_addr8 = addr.octets();
                        }
                    }

                    // Set remote MAC.
                    core::ptr::copy_nonoverlapping(
                        self.remote_mac.as_ptr(),
                        (*slot).remote_mac.as_mut_ptr(),
                        MacAddr::ALEN,
                    );
                }
                Ok::<(), Error>(())
            }),
            enabled: false,
        })
    }
}

impl Default for NetpollBuilder {
    fn default() -> Self {
        Self::new()
    }
}
