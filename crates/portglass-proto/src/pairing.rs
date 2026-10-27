//! The pairing code a probe prints for technicians: everything the controller's *Add probe* needs
//! (name, address, fingerprint, and the relay route if any) in one line to copy and paste.
//!
//! `portglass:probe?name=front-office&addr=10.0.5.20:47100&fp=sha256:6F59:...`
//!
//! It carries nothing secret and grants nothing: it is the same information the probe prints
//! field by field, so it must still travel by a channel the technician trusts, like the
//! fingerprint always has. The controller validates every field exactly as if it had been typed.

const PREFIX: &str = "portglass:probe?";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PairingCode {
    pub name: String,
    /// host:port of the probe. May be empty when `relay` is set.
    pub address: String,
    pub fingerprint: String,
    /// (relay host:port, relay fingerprint)
    pub relay: Option<(String, String)>,
}

impl PairingCode {
    pub fn encode(&self) -> String {
        let mut out = String::from(PREFIX);
        let mut field = |k: &str, v: &str| {
            if !out.ends_with('?') {
                out.push('&');
            }
            out.push_str(k);
            out.push('=');
            out.push_str(&escape(v));
        };
        field("name", &self.name);
        if !self.address.is_empty() {
            field("addr", &self.address);
        }
        field("fp", &self.fingerprint);
        if let Some((addr, fp)) = &self.relay {
            field("relay", addr);
            field("relay_fp", fp);
        }
        out
    }

    /// Parse a pasted code. Whitespace anywhere is ignored, because consoles wrap long lines and
    /// some copy the wrap as a line break; the name's own spaces are escaped.
    pub fn parse(input: &str) -> Result<PairingCode, String> {
        let compact: String = input.chars().filter(|c| !c.is_whitespace()).collect();
        let query = compact
            .strip_prefix(PREFIX)
            .ok_or("a pairing code starts with portglass:probe?")?;
        let mut code = PairingCode::default();
        let (mut relay, mut relay_fp) = (None, None);
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (k, v) = pair.split_once('=').ok_or("the code is cut short")?;
            let v = unescape(v).ok_or("the code is damaged")?;
            match k {
                "name" => code.name = v,
                "addr" => code.address = v,
                "fp" => code.fingerprint = v,
                "relay" => relay = Some(v),
                "relay_fp" => relay_fp = Some(v),
                // Unknown fields come from a newer probe; ignore them rather than refuse.
                _ => {}
            }
        }
        code.relay = match (relay, relay_fp) {
            (Some(a), Some(f)) => Some((a, f)),
            (None, None) => None,
            _ => return Err("the code has half of a relay route".into()),
        };
        if code.name.is_empty() || code.fingerprint.is_empty() {
            return Err("the code is cut short".into());
        }
        if code.address.is_empty() && code.relay.is_none() {
            return Err("the code has no address".into());
        }
        Ok(code)
    }
}

fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~:[]".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn unescape(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = std::str::from_utf8(bytes.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PairingCode {
        PairingCode {
            name: "Front office & co".into(),
            address: "10.0.5.20:47100".into(),
            fingerprint: "sha256:6F59:29C4".into(),
            relay: Some(("relay.example.com:47200".into(), "sha256:AB:CD".into())),
        }
    }

    #[test]
    fn round_trips_and_survives_console_wrapping() {
        let code = sample().encode();
        assert!(!code.contains(' '), "{code}");
        assert_eq!(PairingCode::parse(&code).unwrap(), sample());
        let (a, b) = code.split_at(40);
        let wrapped = format!("  {a}\r\n{b}\n");
        assert_eq!(PairingCode::parse(&wrapped).unwrap(), sample());
    }

    #[test]
    fn relay_only_and_direct_only() {
        let direct = PairingCode {
            relay: None,
            ..sample()
        };
        assert_eq!(PairingCode::parse(&direct.encode()).unwrap(), direct);
        let relayed = PairingCode {
            address: String::new(),
            ..sample()
        };
        assert_eq!(PairingCode::parse(&relayed.encode()).unwrap(), relayed);
    }

    #[test]
    fn refuses_damaged_codes() {
        for bad in [
            "sha256:6F59:29C4",
            "portglass:probe?name=x",
            "portglass:probe?name=x&fp=sha256:1",
            "portglass:probe?name=x&addr=1.2.3.4:1&fp=sha256:1&relay=r:1",
            "portglass:probe?name=%ZZ&addr=1.2.3.4:1&fp=sha256:1",
            "portglass:probe?name=x&addr=1.2.3.4:1&fp=sha256:1%2",
        ] {
            assert!(PairingCode::parse(bad).is_err(), "{bad}");
        }
    }
}
