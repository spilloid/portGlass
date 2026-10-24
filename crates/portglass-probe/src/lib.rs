//! PortGlass Probe.
//!
//! The probe's whole capability: accept mutually authenticated connections from listed
//! controllers, and forward TCP to destinations listed in its own configuration, one session at
//! a time per destination, for a bounded time. It does not execute commands, launch programs,
//! transfer files, scan networks, install persistence, or forward anywhere it was not told to.

pub mod config;
pub mod policy;
pub mod server;

pub use config::ProbeConfig;
pub use server::{start, ProbeHandle};
