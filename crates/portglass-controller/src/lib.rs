//! PortGlass Controller.
//!
//! Connects to a pinned probe, asks it for a session to one destination, exposes that session on
//! a 127.0.0.1-only port, and opens a dedicated Chrome window through it.

pub mod browser;
pub mod client;
pub mod config;
pub mod diag;
pub mod failure;
pub mod session;
pub mod ui;
