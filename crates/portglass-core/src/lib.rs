//! Shared building blocks for the PortGlass controller and probe.
//!
//! * [`identity`] — self-signed device identities and their SHA-256 fingerprints.
//! * [`tls`] — TLS 1.3 mutual authentication pinned to those fingerprints (the SSH
//!   `known_hosts` / `authorized_keys` model, carried by rustls instead of a custom protocol).
//! * [`bridge`] — the bidirectional byte pump used on both ends of a forwarded connection.
//! * [`audit`] — append-only JSON-lines audit log. Never receives payload bytes.

pub mod audit;
pub mod bridge;
pub mod identity;
pub mod tls;

/// Current UTC time as RFC 3339, for audit records and UI timestamps.
pub fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "unknown".into())
}

/// Random bytes from the operating system CSPRNG.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    use ring::rand::SecureRandom;
    let mut out = [0u8; N];
    ring::rand::SystemRandom::new()
        .fill(&mut out)
        .expect("operating system random number generator failed");
    out
}

/// Constant-time equality for secrets of equal, public length.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    #[test]
    fn ct_eq_behaves() {
        assert!(super::ct_eq(b"abc", b"abc"));
        assert!(!super::ct_eq(b"abc", b"abd"));
        assert!(!super::ct_eq(b"abc", b"ab"));
    }
}
