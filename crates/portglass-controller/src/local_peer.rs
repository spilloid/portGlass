//! Who is connecting to the tunnel endpoint?
//!
//! The tunnel listens on 127.0.0.1, which every process on this computer can reach — another
//! user's session, local malware, or a web page in the technician's everyday browser. PortGlass
//! therefore admits a local connection only if the process that owns its client socket belongs to
//! the session browser (see [`crate::browser::ProcessScope`]).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// The process id owning the client end of a loopback TCP connection to `listener_port`.
#[cfg(windows)]
pub fn owning_pid(listener_port: u16, peer: SocketAddr) -> Option<u32> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_CONNECTIONS,
    };
    use windows_sys::Win32::Networking::WinSock::AF_INET;

    let IpAddr::V4(peer_ip) = peer.ip() else {
        return None;
    };
    if peer_ip != Ipv4Addr::LOCALHOST {
        return None;
    }
    let loopback = u32::from_ne_bytes(Ipv4Addr::LOCALHOST.octets());
    let mut size: u32 = 0;
    // SAFETY: first call with a null buffer only reports the required size.
    unsafe {
        GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_CONNECTIONS,
            0,
        );
    }
    for _ in 0..4 {
        // u32 elements keep the buffer aligned for the table's u32 fields.
        let mut buf = vec![0u32; (size as usize).div_ceil(4) + 64];
        let mut len = (buf.len() * 4) as u32;
        // SAFETY: `buf` is writable for `len` bytes and suitably aligned.
        let rc = unsafe {
            GetExtendedTcpTable(
                buf.as_mut_ptr().cast(),
                &mut len,
                0,
                AF_INET as u32,
                TCP_TABLE_OWNER_PID_CONNECTIONS,
                0,
            )
        };
        if rc == 122 {
            // ERROR_INSUFFICIENT_BUFFER: connections were added meanwhile; retry larger.
            size = len;
            continue;
        }
        if rc != 0 {
            return None;
        }
        // SAFETY: on success the buffer holds a MIB_TCPTABLE_OWNER_PID with dwNumEntries rows.
        unsafe {
            let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
            let rows =
                std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);
            let port = |p: u32| u16::from_be((p & 0xffff) as u16);
            return rows
                .iter()
                .find(|r| {
                    r.dwLocalAddr == loopback
                        && port(r.dwLocalPort) == peer.port()
                        && r.dwRemoteAddr == loopback
                        && port(r.dwRemotePort) == listener_port
                })
                .map(|r| r.dwOwningPid);
        }
    }
    None
}

/// macOS: ask `lsof` which process holds the client end of this exact socket pair. (The
/// kernel's per-socket `proc_pidfdinfo` structures are not exposed by the `libc` crate.)
#[cfg(target_os = "macos")]
pub fn owning_pid(listener_port: u16, peer: SocketAddr) -> Option<u32> {
    if peer.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) {
        return None;
    }
    let out = std::process::Command::new("/usr/sbin/lsof")
        .args(["-nP", "-a", "-sTCP:ESTABLISHED", "-Fpn"])
        .arg(format!("-iTCP@127.0.0.1:{}", peer.port()))
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    parse_lsof(
        &String::from_utf8_lossy(&out.stdout),
        listener_port,
        peer.port(),
    )
}

#[cfg(not(any(windows, target_os = "macos")))]
pub fn owning_pid(_listener_port: u16, _peer: SocketAddr) -> Option<u32> {
    None
}

/// Find the process whose socket is `127.0.0.1:<peer_port> -> 127.0.0.1:<listener_port>` in
/// `lsof -Fpn` output (`p<pid>` lines followed by that process's `n<name>` lines).
#[cfg_attr(not(any(test, target_os = "macos")), allow(dead_code))]
fn parse_lsof(text: &str, listener_port: u16, peer_port: u16) -> Option<u32> {
    let wanted = format!("127.0.0.1:{peer_port}->127.0.0.1:{listener_port}");
    let mut pid = None;
    for line in text.lines() {
        if let Some(p) = line.strip_prefix('p') {
            pid = p.trim().parse::<u32>().ok();
        } else if let Some(name) = line.strip_prefix('n') {
            if name.trim() == wanted {
                return pid;
            }
        }
    }
    None
}

#[cfg(test)]
mod parse_tests {
    #[test]
    fn picks_the_client_end_not_the_listener_end() {
        let out = "p100\nf5\nn127.0.0.1:50000->127.0.0.1:61000\np200\nf9\nn127.0.0.1:61000->127.0.0.1:50000\n";
        // Client 127.0.0.1:61000 connected to the tunnel listening on 50000.
        assert_eq!(super::parse_lsof(out, 50000, 61000), Some(200));
        assert_eq!(super::parse_lsof(out, 50000, 61001), None);
        assert_eq!(super::parse_lsof("", 1, 2), None);
    }
}

#[cfg(all(test, any(windows, target_os = "macos")))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn finds_this_process_as_the_owner_of_its_own_connection() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let _client = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let (_server, peer) = l.accept().await.unwrap();
        assert_eq!(owning_pid(port, peer), Some(std::process::id()));
        assert_eq!(owning_pid(port.wrapping_add(1), peer), None);
    }
}
