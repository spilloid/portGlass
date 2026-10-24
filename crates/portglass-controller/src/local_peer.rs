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

#[cfg(not(windows))]
pub fn owning_pid(_listener_port: u16, _peer: SocketAddr) -> Option<u32> {
    None
}

#[cfg(all(test, windows))]
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
