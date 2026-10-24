//! Bidirectional byte forwarding between two streams.
//!
//! * Binary-safe and protocol-agnostic: bytes are copied, never inspected or logged.
//! * Backpressure: each direction awaits its write before reading more, so a slow reader
//!   throttles the sender through TCP flow control instead of buffering without bound.
//! * Half-close: EOF in one direction shuts down the write side of the other stream and the
//!   opposite direction keeps flowing until it ends too.
//! * Ends on: both directions finished, an I/O error in either direction, the idle timeout, or
//!   cancellation (session closed, expired or revoked).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

const BUF_SIZE: usize = 32 * 1024;

/// Byte counters shared by every connection in a session. `up` is client -> target.
#[derive(Debug, Default)]
pub struct Counters {
    pub up: AtomicU64,
    pub down: AtomicU64,
}

impl Counters {
    pub fn snapshot(&self) -> (u64, u64) {
        (
            self.up.load(Ordering::Relaxed),
            self.down.load(Ordering::Relaxed),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeEnd {
    /// Both directions reached EOF.
    Completed,
    /// One side failed (reset, aborted, TLS error).
    Error,
    /// No bytes in either direction for the idle timeout.
    IdleTimeout,
    /// The session was closed, expired or revoked.
    Cancelled,
}

impl BridgeEnd {
    pub fn as_str(self) -> &'static str {
        match self {
            BridgeEnd::Completed => "completed",
            BridgeEnd::Error => "error",
            BridgeEnd::IdleTimeout => "idle_timeout",
            BridgeEnd::Cancelled => "cancelled",
        }
    }
}

/// Forward `client` <-> `target` until one of the end conditions above.
pub async fn bridge<C, T>(
    client: C,
    target: T,
    idle_timeout: Duration,
    cancel: CancellationToken,
    counters: Arc<Counters>,
) -> BridgeEnd
where
    C: AsyncRead + AsyncWrite + Send,
    T: AsyncRead + AsyncWrite + Send,
{
    let (mut cr, mut cw) = tokio::io::split(client);
    let (mut tr, mut tw) = tokio::io::split(target);
    let start = Instant::now();
    let last = AtomicU64::new(0);

    let up = pump(&mut cr, &mut tw, &counters.up, &last, start);
    let down = pump(&mut tr, &mut cw, &counters.down, &last, start);
    let both = async { tokio::try_join!(up, down) };

    let idle = async {
        loop {
            let since = Duration::from_millis(last.load(Ordering::Relaxed));
            let deadline = start + since + idle_timeout;
            if Instant::now() >= deadline {
                return;
            }
            tokio::time::sleep_until(deadline.into()).await;
        }
    };

    tokio::select! {
        r = both => match r {
            Ok(_) => BridgeEnd::Completed,
            Err(_) => BridgeEnd::Error,
        },
        _ = idle => BridgeEnd::IdleTimeout,
        _ = cancel.cancelled() => BridgeEnd::Cancelled,
    }
}

async fn pump<R, W>(
    r: &mut R,
    w: &mut W,
    counter: &AtomicU64,
    last: &AtomicU64,
    start: Instant,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; BUF_SIZE];
    loop {
        let n = match r.read(&mut buf).await {
            Ok(n) => n,
            // A peer that closes TCP without a TLS close_notify is an ordinary close here: the
            // forwarded application protocol (HTTP etc.) carries its own framing.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => 0,
            Err(e) => return Err(e),
        };
        if n == 0 {
            // Propagate the half-close. The other direction keeps running.
            let _ = w.shutdown().await;
            return Ok(());
        }
        w.write_all(&buf[..n]).await?;
        w.flush().await?;
        counter.fetch_add(n as u64, Ordering::Relaxed);
        last.store(start.elapsed().as_millis() as u64, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::{TcpListener, TcpStream};

    async fn pair() -> (TcpStream, TcpStream) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let (a, b) = tokio::join!(TcpStream::connect(addr), l.accept());
        (a.unwrap(), b.unwrap().0)
    }

    #[tokio::test]
    async fn binary_safe_and_half_close() {
        // user <-> [a1 | bridge | b1] <-> server
        let (mut user, a1) = pair().await;
        let (b1, mut server) = pair().await;
        let counters = Arc::new(Counters::default());
        let task = tokio::spawn(bridge(
            a1,
            b1,
            Duration::from_secs(5),
            CancellationToken::new(),
            counters.clone(),
        ));

        let payload: Vec<u8> = (0..=255u8).cycle().take(1 << 20).collect();
        user.write_all(&payload).await.unwrap();
        user.shutdown().await.unwrap(); // half-close: user is done sending

        let mut got = Vec::new();
        server.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, payload, "every byte, in order, unmodified");

        // The other direction still works after the half-close.
        server.write_all(b"reply after half-close").await.unwrap();
        server.shutdown().await.unwrap();
        let mut reply = Vec::new();
        user.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, b"reply after half-close");

        assert_eq!(task.await.unwrap(), BridgeEnd::Completed);
        assert_eq!(counters.snapshot(), (1 << 20, 22));
    }

    #[tokio::test]
    async fn idle_timeout_and_cancellation_end_the_bridge() {
        let (_user, a1) = pair().await;
        let (b1, _server) = pair().await;
        let end = bridge(
            a1,
            b1,
            Duration::from_millis(150),
            CancellationToken::new(),
            Arc::new(Counters::default()),
        )
        .await;
        assert_eq!(end, BridgeEnd::IdleTimeout);

        let (_user, a1) = pair().await;
        let (b1, _server) = pair().await;
        let cancel = CancellationToken::new();
        let c2 = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            c2.cancel();
        });
        let end = bridge(
            a1,
            b1,
            Duration::from_secs(30),
            cancel,
            Arc::new(Counters::default()),
        )
        .await;
        assert_eq!(end, BridgeEnd::Cancelled);
    }

    #[tokio::test]
    async fn backpressure_bounds_buffering() {
        // The server never reads. The bridge must stall rather than buffer everything.
        let (mut user, a1) = pair().await;
        let (b1, _server) = pair().await;
        let counters = Arc::new(Counters::default());
        tokio::spawn(bridge(
            a1,
            b1,
            Duration::from_secs(30),
            CancellationToken::new(),
            counters.clone(),
        ));
        let chunk = vec![7u8; 64 * 1024];
        let sent = async {
            let mut total = 0usize;
            loop {
                if user.write_all(&chunk).await.is_err() {
                    break;
                }
                total += chunk.len();
            }
            total
        };
        let _ = tokio::time::timeout(Duration::from_millis(1500), sent).await;
        let forwarded = counters.snapshot().0;
        assert!(
            forwarded < 64 * 1024 * 1024,
            "bridge forwarded {forwarded} bytes to a peer that never reads"
        );
    }
}
