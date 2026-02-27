// SPDX-License-Identifier: GPL-2.0

//! Networking.

pub mod mac;
pub use mac::MacAddr;

#[cfg(CONFIG_NETPOLL)]
pub mod netpoll;

#[cfg(CONFIG_RUST_PHYLIB_ABSTRACTIONS)]
pub mod phy;
