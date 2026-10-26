//! PortGlass Relay.
//!
//! For a probe and a technician that cannot reach each other (both behind NAT, no VPN), both dial
//! out to a relay. The relay's whole capability: let listed probes register, pair a controller
//! with a registered probe that lists it, and copy bytes between the two connections. It does not
//! terminate, inspect or log the PortGlass connection inside, cannot reach any network a probe
//! can, and holds no key that either end trusts for anything but reaching the relay itself.

pub mod config;
pub mod server;

pub use config::RelayConfig;
pub use server::{start, RelayHandle};
