//! Relay mode end to end: a real relay, a real probe that registers with it, a controller whose
//! only route to the probe is the relay, and a mock device — all on loopback.

use std::sync::Arc;
use std::time::Duration;

use portglass_controller::client::ProbeLink;
use portglass_controller::config::{ControllerConfig, ProbeEntry, RelayRoute};
use portglass_controller::diag::SchemePref;
use portglass_controller::failure::FailureKind;
use portglass_controller::session::{ConnectRequest, Controller, Options, Phase, Snapshot};
use portglass_core::audit::AuditLog;
use portglass_core::identity::Identity;
use portglass_probe::config::{ProbeConfig, ProbeConfigFile};
use portglass_probe::ProbeHandle;
use portglass_proto::relay as relay_proto;
use portglass_proto::{read_frame, write_frame, TargetSpec};
use portglass_relay::config::{RelayConfig, RelayConfigFile};
use portglass_relay::RelayHandle;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

struct Harness {
    relay: RelayHandle,
    relay_id: Identity,
    probe: ProbeHandle,
    probe_id: Identity,
    ctl_id: Identity,
    mock: std::net::SocketAddr,
    dir: tempfile::TempDir,
}

fn relay_config(probes: &[&Identity]) -> RelayConfig {
    let mut text = String::from(
        "[relay]\nname = 'test-relay'\nlisten = '127.0.0.1:0'\n\
         [limits]\nanswer_timeout_secs = 5\n",
    );
    for (i, p) in probes.iter().enumerate() {
        text.push_str(&format!(
            "[[probe]]\nname = 'probe-{i}'\nfingerprint = '{}'\n",
            p.fingerprint
        ));
    }
    let file: RelayConfigFile = toml::from_str(&text).unwrap();
    RelayConfig::from_file(file, std::path::Path::new(".")).unwrap()
}

fn probe_config(ctl: &Identity, mock: u16, relay: &str, relay_id: &Identity) -> ProbeConfig {
    let text = format!(
        "[probe]\nname = 'test-probe'\nlisten = '127.0.0.1:0'\n\
         [limits]\nmax_session_ttl_secs = 600\ncontrol_timeout_secs = 10\n\
         [[controller]]\nname = 'alice'\nfingerprint = '{}'\n\
         [[allow]]\nnetwork = '127.0.0.1/32'\nports = [{mock}]\n\
         [relay]\naddress = '{relay}'\nfingerprint = '{}'\n",
        ctl.fingerprint, relay_id.fingerprint
    );
    let file: ProbeConfigFile = toml::from_str(&text).unwrap();
    ProbeConfig::from_file(file, std::path::Path::new(".")).unwrap()
}

impl Harness {
    /// `authorize_probe`: whether the relay lists the probe.
    async fn new(authorize_probe: bool) -> Harness {
        let mock_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mock = mock_listener.local_addr().unwrap();
        tokio::spawn(portglass_mock_target::serve_http(mock_listener));
        let (relay_id, _, _) = Identity::generate("relay", "test-relay").unwrap();
        let (probe_id, _, _) = Identity::generate("probe", "test-probe").unwrap();
        let (ctl_id, _, _) = Identity::generate("controller", "alice").unwrap();
        let dir = tempfile::tempdir().unwrap();

        let listed: Vec<&Identity> = if authorize_probe {
            vec![&probe_id]
        } else {
            vec![]
        };
        let relay_audit = Arc::new(AuditLog::open(&dir.path().join("relay-audit.jsonl")).unwrap());
        let relay = portglass_relay::start(relay_config(&listed), relay_id.clone(), relay_audit)
            .await
            .unwrap();
        let cfg = probe_config(&ctl_id, mock.port(), &relay.addr.to_string(), &relay_id);
        let probe_audit = Arc::new(AuditLog::open(&dir.path().join("probe-audit.jsonl")).unwrap());
        let probe = portglass_probe::start(cfg, probe_id.clone(), probe_audit)
            .await
            .unwrap();
        let h = Harness {
            relay,
            relay_id,
            probe,
            probe_id,
            ctl_id,
            mock,
            dir,
        };
        if authorize_probe {
            h.wait_registered(true).await;
        }
        h
    }

    async fn wait_registered(&self, want: bool) {
        for _ in 0..100 {
            if self.relay.registered().is_empty() != want {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("relay registration never became {want}");
    }

    /// A probe entry whose only route is the relay: no direct address at all.
    fn entry(&self) -> ProbeEntry {
        ProbeEntry {
            name: "lab".into(),
            address: String::new(),
            fingerprint: self.probe_id.fingerprint,
            relay: Some(RelayRoute {
                address: self.relay.addr.to_string(),
                fingerprint: self.relay_id.fingerprint,
            }),
        }
    }

    fn controller(&self) -> Arc<Controller> {
        let toml = format!(
            "operator = 'alice'\naudit_log = '{}'\n",
            self.dir
                .path()
                .join("controller-audit.jsonl")
                .display()
                .to_string()
                .replace('\\', "/")
        );
        let mut cfg: ControllerConfig = toml::from_str(&toml).unwrap();
        cfg.probes = vec![self.entry()];
        let audit = Arc::new(AuditLog::open(&cfg.audit_log).unwrap());
        Controller::new(
            cfg,
            self.ctl_id.clone(),
            audit,
            Options {
                launch_browser: false,
                ..Options::default()
            },
        )
    }

    fn relay_audit(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("relay-audit.jsonl")).unwrap_or_default()
    }
}

async fn wait_for(ctrl: &Controller, pred: impl Fn(&Snapshot) -> bool) -> Snapshot {
    let mut rx = ctrl.subscribe();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let s = rx.borrow_and_update().clone();
        if pred(&s) {
            return s;
        }
        tokio::select! {
            r = rx.changed() => r.unwrap(),
            _ = tokio::time::sleep_until(deadline) => panic!("timed out; last phase {:?}, failure {:?}", s.phase, s.failure),
        }
    }
}

async fn get(addr: std::net::SocketAddr, host: &str, path: &str) -> (String, Vec<u8>) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    let split = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&buf[..split]).to_string();
    (head, buf[split + 4..].to_vec())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_through_the_relay_forwards_like_a_direct_one() {
    let h = Harness::new(true).await;
    let ctrl = h.controller();
    let host = format!("127.0.0.1:{}", h.mock.port());
    ctrl.connect(ConnectRequest {
        probe: "lab".into(),
        target: host.clone(),
        scheme: SchemePref::Auto,
        ttl_mins: Some(5),
    })
    .await
    .unwrap();
    let s = wait_for(&ctrl, |s| matches!(s.phase, Phase::Ready | Phase::Failed)).await;
    assert_eq!(s.phase, Phase::Ready, "failure: {:?}", s.failure);
    let local: std::net::SocketAddr = s.session.unwrap().local_addr.unwrap().parse().unwrap();

    // Several sequential connections, each its own relay pairing.
    for _ in 0..3 {
        let (head, body) = get(local, &host, "/").await;
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        assert!(String::from_utf8_lossy(&body).contains("MockJet 9000"));
    }
    // A large binary download arrives intact through two layers of TLS and the splice.
    let (head, body) = get(local, &host, "/big").await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(body.len(), 8 << 20);
    assert!(body.iter().enumerate().all(|(i, b)| *b == (i % 251) as u8));

    ctrl.disconnect().await;
    let s = wait_for(&ctrl, |s| s.phase == Phase::Disconnected).await;
    assert!(s.failure.is_none());
    // The probe ends the session when CloseSession arrives, a moment after the controller is done.
    for _ in 0..40 {
        if h.probe.active_sessions() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(h.probe.active_sessions(), 0);

    // The relay records metadata about pairings, never payload.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let audit = h.relay_audit();
    assert!(audit.contains("probe_registered") && audit.contains("pair_ended"));
    assert!(!audit.contains("MockJet"));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_relay_pairs_only_controllers_the_probe_lists() {
    let h = Harness::new(true).await;
    let (stranger, _, _) = Identity::generate("controller", "mallory").unwrap();
    let err = ProbeLink::connect(&h.entry(), &stranger, "mallory")
        .await
        .err()
        .expect("an unlisted controller must not be paired");
    assert_eq!(err.kind, FailureKind::ProbeUnreachable, "{err:?}");
    assert!(
        err.title.contains("isn't available through the relay"),
        "{err:?}"
    );
    // The listed controller still gets through.
    assert!(ProbeLink::connect(&h.entry(), &h.ctl_id, "alice")
        .await
        .is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn removing_a_controller_at_the_probe_updates_the_relay() {
    let h = Harness::new(true).await;
    let link = ProbeLink::connect(&h.entry(), &h.ctl_id, "alice")
        .await
        .unwrap();
    // The administrator removes alice at the probe.
    let mut cfg = (*h.probe.config()).clone();
    cfg.controllers.clear();
    h.probe.apply_config(cfg);
    // The probe drops her live connection itself...
    tokio::time::timeout(Duration::from_secs(5), link.closed().cancelled())
        .await
        .expect("revoked controller's control connection must close");
    // ...and within a few seconds the relay stops pairing her at all.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let err = ProbeLink::connect(&h.entry(), &h.ctl_id, "alice")
        .await
        .err()
        .expect("revoked controller must not be paired");
    assert!(
        err.title.contains("isn't available through the relay"),
        "{err:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unlisted_probe_cannot_register() {
    let h = Harness::new(false).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(h.relay.registered().is_empty());
    let err = ProbeLink::connect(&h.entry(), &h.ctl_id, "alice")
        .await
        .err()
        .unwrap();
    assert_eq!(err.kind, FailureKind::ProbeUnreachable, "{err:?}");
    assert!(h.relay_audit().contains("probe_rejected"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_relay_with_the_wrong_identity_is_refused() {
    let h = Harness::new(true).await;
    let (imposter, _, _) = Identity::generate("relay", "imposter").unwrap();
    let mut entry = h.entry();
    entry.relay.as_mut().unwrap().fingerprint = imposter.fingerprint;
    let err = ProbeLink::connect(&entry, &h.ctl_id, "alice")
        .await
        .err()
        .unwrap();
    assert_eq!(err.kind, FailureKind::AuthFailed, "{err:?}");
    assert!(
        err.title.contains("relay presented the wrong identity"),
        "{err:?}"
    );
}

/// A relay that is pinned by the controller but malicious: it answers `Connected` for whatever
/// probe is asked for and splices the controller to `elsewhere` instead.
async fn mispairing_relay(
    identity: Identity,
    elsewhere: std::net::SocketAddr,
) -> std::net::SocketAddr {
    #[derive(Debug)]
    struct Anyone;
    impl portglass_core::tls::ControllerAllowlist for Anyone {
        fn is_allowed(&self, _: &portglass_core::identity::Fingerprint) -> bool {
            true
        }
    }
    let config = portglass_core::tls::server_config(
        &identity,
        Arc::new(Anyone),
        &[relay_proto::ALPN_CONNECT],
    )
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let mut tls = acceptor.accept(tcp).await.unwrap();
                let _: relay_proto::Connect = read_frame(&mut tls).await.unwrap();
                write_frame(&mut tls, &relay_proto::ConnectReply::Connected)
                    .await
                    .unwrap();
                let mut other = TcpStream::connect(elsewhere).await.unwrap();
                let _ = tokio::io::copy_bidirectional(&mut tls, &mut other).await;
            });
        }
    });
    addr
}

#[tokio::test(flavor = "multi_thread")]
async fn a_malicious_relay_cannot_substitute_another_probe() {
    // The controller pins the relay and probe A. The relay is hostile and splices it to a real
    // probe B (which even authorizes this controller). The inner handshake must fail on A's pin.
    let h = Harness::new(true).await;
    let (probe_a, _, _) = Identity::generate("probe", "the-one-you-pinned").unwrap();
    let (evil_id, _, _) = Identity::generate("relay", "evil").unwrap();
    let evil = mispairing_relay(evil_id.clone(), h.probe.addr).await;
    let entry = ProbeEntry {
        name: "lab".into(),
        address: String::new(),
        fingerprint: probe_a.fingerprint,
        relay: Some(RelayRoute {
            address: evil.to_string(),
            fingerprint: evil_id.fingerprint,
        }),
    };
    let err = ProbeLink::connect(&entry, &h.ctl_id, "alice")
        .await
        .err()
        .expect("a substituted probe must be refused");
    assert_eq!(err.kind, FailureKind::AuthFailed, "{err:?}");
    assert!(
        err.title.contains("presented the wrong identity"),
        "{err:?}"
    );
    // Control: with B pinned, the same hostile relay "works", so the refusal above came from
    // the end-to-end pin and not from the relay failing.
    let mut b = entry.clone();
    b.fingerprint = h.probe_id.fingerprint;
    assert!(ProbeLink::connect(&b, &h.ctl_id, "alice").await.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_relay_cannot_pair_a_controller_with_an_unregistered_probe() {
    let h = Harness::new(true).await;
    let (other_probe, _, _) = Identity::generate("probe", "other").unwrap();
    let mut entry = h.entry();
    entry.fingerprint = other_probe.fingerprint;
    let err = ProbeLink::connect(&entry, &h.ctl_id, "alice")
        .await
        .err()
        .unwrap();
    assert_eq!(err.kind, FailureKind::ProbeUnreachable, "{err:?}");
    assert!(
        err.title.contains("isn't available through the relay"),
        "{err:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_probe_revoked_while_registering_is_not_registered() {
    // Review finding: authorization was checked before `Register` arrived, then the registration
    // was published without a recheck. Drive that interleaving with a raw registration.
    let h = Harness::new(true).await;
    let (late, _, _) = Identity::generate("probe", "late").unwrap();
    h.relay.apply_config(relay_config(&[&h.probe_id, &late]));
    let mut reg = portglass_core::relay::dial(
        &h.relay.addr.to_string(),
        h.relay_id.fingerprint,
        &late,
        relay_proto::ALPN_REGISTER,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    // Listed at the handshake; revoked before `Register` is sent.
    tokio::time::sleep(Duration::from_millis(200)).await;
    h.relay.apply_config(relay_config(&[&h.probe_id]));
    write_frame(
        &mut reg,
        &relay_proto::ProbeRequest::Register {
            protocol: relay_proto::RELAY_PROTOCOL_VERSION,
            controllers: vec![h.ctl_id.fingerprint.to_string()],
        },
    )
    .await
    .unwrap();
    let reply = read_frame::<_, relay_proto::ProbeEvent>(&mut reg).await;
    assert!(
        matches!(reply, Ok(relay_proto::ProbeEvent::Refused { .. }) | Err(_)),
        "{reply:?}"
    );
    assert_eq!(h.relay.registered(), vec!["probe-0".to_string()]);
}

#[tokio::test(flavor = "multi_thread")]
async fn dropping_a_probe_at_the_relay_ends_its_relayed_connections() {
    let h = Harness::new(true).await;
    let link = ProbeLink::connect(&h.entry(), &h.ctl_id, "alice")
        .await
        .unwrap();
    let grant = link
        .open_session(
            &TargetSpec {
                host: "127.0.0.1".into(),
                port: h.mock.port(),
            },
            60,
        )
        .await
        .unwrap();
    // A live, idle data stream through the relay, not just the control connection.
    let mut stream = link
        .open_stream(&grant.session_id, &grant.stream_token)
        .await
        .unwrap();
    h.relay.apply_config(relay_config(&[]));
    tokio::time::timeout(Duration::from_secs(5), link.closed().cancelled())
        .await
        .expect("connections spliced through a dropped registration must close");
    let mut buf = [0u8; 1];
    let r = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("an open data stream must end too, not hang");
    assert!(matches!(r, Ok(0) | Err(_)), "{r:?}");
    assert!(h.relay.registered().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn one_address_cannot_hold_every_unpaired_slot() {
    // Review finding: after the handshake, any certificate could hold CONNECT sockets without
    // sending a frame. An attacker on 127.0.0.2 fills its per-address budget; the next one is
    // dropped, and a technician on 127.0.0.1 still gets through.
    //
    // Needs a second loopback address: Windows and Linux route all of 127/8, macOS only
    // configures 127.0.0.1 unless an alias is added.
    let probe_sock = tokio::net::TcpSocket::new_v4().unwrap();
    if probe_sock.bind("127.0.0.2:0".parse().unwrap()).is_err() {
        eprintln!("skipped: 127.0.0.2 is not available on this host");
        return;
    }
    drop(probe_sock);
    let h = Harness::new(true).await;
    let (stranger, _, _) = Identity::generate("controller", "mallory").unwrap();
    let cfg = portglass_core::tls::client_config(
        &stranger,
        h.relay_id.fingerprint,
        relay_proto::ALPN_CONNECT,
    )
    .unwrap();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let mut held = Vec::new();
    for _ in 0..33 {
        let sock = tokio::net::TcpSocket::new_v4().unwrap();
        sock.bind("127.0.0.2:0".parse().unwrap()).unwrap();
        let tcp = sock.connect(h.relay.addr).await.unwrap();
        held.push(
            connector
                .connect(portglass_core::tls::server_name(), tcp)
                .await
                .unwrap(),
        );
        // The relay takes the slot once the handshake completes on its side.
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let mut buf = [0u8; 1];
    let last = tokio::time::timeout(Duration::from_secs(3), held[32].read(&mut buf)).await;
    assert!(
        matches!(last, Ok(Ok(0)) | Ok(Err(_))),
        "the 33rd connection from one address must be dropped: {last:?}"
    );
    let first = tokio::time::timeout(Duration::from_millis(500), held[0].read(&mut buf)).await;
    assert!(
        first.is_err(),
        "earlier connections are still held: {first:?}"
    );
    assert!(ProbeLink::connect(&h.entry(), &h.ctl_id, "alice")
        .await
        .is_ok());
}

/// Open `n` relay connections as `who` speaking `alpn`, sending nothing.
async fn hold(
    h: &Harness,
    who: &Identity,
    alpn: &[u8],
    n: usize,
) -> Vec<tokio_rustls::client::TlsStream<TcpStream>> {
    let mut held = Vec::new();
    for _ in 0..n {
        held.push(
            portglass_core::relay::dial(
                &h.relay.addr.to_string(),
                h.relay_id.fingerprint,
                who,
                alpn,
                Duration::from_secs(5),
            )
            .await
            .unwrap(),
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    held
}

/// Whether the relay dropped this connection (rather than holding it open).
async fn dropped(s: &mut tokio_rustls::client::TlsStream<TcpStream>, wait: Duration) -> bool {
    let mut buf = [0u8; 1];
    matches!(
        tokio::time::timeout(wait, s.read(&mut buf)).await,
        Ok(Ok(0)) | Ok(Err(_))
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn one_listed_probe_cannot_starve_the_others() {
    // Re-review finding: the registration and answer pools had no per-probe share, so one
    // listed probe's key could hold them all. Probe "greedy" exceeds its shares; the overflow
    // is dropped while its in-budget connections stay held, and the real probe still works.
    let h = Harness::new(true).await;
    let (greedy, _, _) = Identity::generate("probe", "greedy").unwrap();
    h.relay.apply_config(relay_config(&[&h.probe_id, &greedy]));

    let mut regs = hold(&h, &greedy, relay_proto::ALPN_REGISTER, 5).await;
    assert!(
        dropped(&mut regs[4], Duration::from_secs(3)).await,
        "5th registration"
    );
    assert!(
        !dropped(&mut regs[0], Duration::from_millis(300)).await,
        "1st registration"
    );

    // max_waiting_per_probe defaults to 32.
    let mut answers = hold(&h, &greedy, relay_proto::ALPN_ACCEPT, 33).await;
    assert!(
        dropped(&mut answers[32], Duration::from_secs(3)).await,
        "33rd answer"
    );
    assert!(
        !dropped(&mut answers[0], Duration::from_millis(300)).await,
        "1st answer"
    );

    let link = ProbeLink::connect(&h.entry(), &h.ctl_id, "alice")
        .await
        .expect("another probe still registers and answers");
    assert_eq!(link.hello.probe_name, "test-probe");
}
