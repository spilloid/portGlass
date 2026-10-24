//! TLS 1.3 with mutual authentication pinned to certificate fingerprints.
//!
//! rustls performs the handshake, encryption and signature verification. The only PortGlass
//! decision is *which* certificates are trusted: the controller trusts exactly the fingerprint it
//! pinned for a probe, and the probe trusts exactly the controller fingerprints in its
//! allowlist. Possession of the matching private key is still proven by the TLS 1.3
//! CertificateVerify signature, which is checked with rustls' own verifier.

use std::fmt;
use std::sync::Arc;

use anyhow::Result;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls13_signature, CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, DistinguishedName, Error, ServerConfig,
    SignatureScheme,
};

use crate::identity::{Fingerprint, Identity};

/// The name a controller presents in SNI. Pinning makes it carry no authority.
pub const PROBE_SERVER_NAME: &str = "portglass-probe";

pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Decides whether a controller certificate may connect. Implemented by the probe's live
/// configuration so an allowlist change takes effect on the next handshake.
pub trait ControllerAllowlist: Send + Sync + fmt::Debug {
    fn is_allowed(&self, fingerprint: &Fingerprint) -> bool;
}

/// Controller-side configuration for connecting to one specific probe.
pub fn client_config(
    identity: &Identity,
    expected_probe: Fingerprint,
    alpn: &[u8],
) -> Result<ClientConfig> {
    let provider = provider();
    let verifier = PinnedServerVerifier {
        expected: expected_probe,
        algorithms: provider.signature_verification_algorithms,
    };
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_client_auth_cert(vec![identity.cert.clone()], identity.key.clone_key())?;
    config.alpn_protocols = vec![alpn.to_vec()];
    Ok(config)
}

/// Probe-side configuration. Client certificates are mandatory.
pub fn server_config(
    identity: &Identity,
    allowlist: Arc<dyn ControllerAllowlist>,
    alpn: &[&[u8]],
) -> Result<ServerConfig> {
    let provider = provider();
    let verifier = AllowlistClientVerifier {
        allowlist,
        algorithms: provider.signature_verification_algorithms,
    };
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(Arc::new(verifier))
        .with_single_cert(vec![identity.cert.clone()], identity.key.clone_key())?;
    config.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    // No session resumption: a resumed TLS session skips the client-certificate verifier, and the
    // allowlist must be consulted on every connection so revocation is immediate.
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    Ok(config)
}

pub fn server_name() -> ServerName<'static> {
    ServerName::try_from(PROBE_SERVER_NAME).expect("static server name is valid")
}

/// Fingerprint of the peer's end-entity certificate after a completed handshake.
pub fn peer_fingerprint(conn: &rustls::CommonState) -> Option<Fingerprint> {
    conn.peer_certificates()
        .and_then(|certs| certs.first())
        .map(|c| Fingerprint::of(c))
}

#[derive(Debug)]
struct PinnedServerVerifier {
    expected: Fingerprint,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if crate::ct_eq(&Fingerprint::of(end_entity).0, &self.expected.0) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("PortGlass accepts TLS 1.3 only".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

#[derive(Debug)]
struct AllowlistClientVerifier {
    allowlist: Arc<dyn ControllerAllowlist>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ClientCertVerifier for AllowlistClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        if self.allowlist.is_allowed(&Fingerprint::of(end_entity)) {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("PortGlass accepts TLS 1.3 only".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    #[derive(Debug)]
    struct List(Mutex<Vec<Fingerprint>>);
    impl ControllerAllowlist for List {
        fn is_allowed(&self, fp: &Fingerprint) -> bool {
            self.0.lock().unwrap().contains(fp)
        }
    }

    async fn handshake(
        probe: &Identity,
        allow: Vec<Fingerprint>,
        controller: &Identity,
        pinned: Fingerprint,
    ) -> (bool, bool) {
        let server = server_config(
            probe,
            Arc::new(List(Mutex::new(allow))),
            &[portglass_proto::ALPN_CONTROL],
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server));
        let srv = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            match acceptor.accept(tcp).await {
                Ok(mut tls) => {
                    let mut b = [0u8; 4];
                    tls.read_exact(&mut b).await.is_ok()
                }
                Err(_) => false,
            }
        });
        let client = client_config(controller, pinned, portglass_proto::ALPN_CONTROL).unwrap();
        let tcp = TcpStream::connect(addr).await.unwrap();
        let ok_client = match TlsConnector::from(Arc::new(client))
            .connect(server_name(), tcp)
            .await
        {
            Ok(mut tls) => {
                // TLS 1.3 client auth failures surface on first read/write after the handshake.
                tls.write_all(b"ping").await.is_ok() && tls.flush().await.is_ok()
            }
            Err(_) => false,
        };
        (ok_client, srv.await.unwrap())
    }

    #[tokio::test]
    async fn mutual_pinning_accepts_only_the_right_pair() {
        let (probe, _, _) = Identity::generate("probe", "p").unwrap();
        let (ctl, _, _) = Identity::generate("controller", "c").unwrap();
        let (imposter, _, _) = Identity::generate("probe", "evil").unwrap();

        let (_, server_ok) =
            handshake(&probe, vec![ctl.fingerprint], &ctl, probe.fingerprint).await;
        assert!(server_ok, "authorized pair must connect");

        let (_, server_ok) = handshake(&probe, vec![], &ctl, probe.fingerprint).await;
        assert!(!server_ok, "probe must refuse an unlisted controller");

        let (client_ok, server_ok) =
            handshake(&imposter, vec![ctl.fingerprint], &ctl, probe.fingerprint).await;
        assert!(
            !client_ok && !server_ok,
            "controller must refuse a probe with the wrong key"
        );
    }
}
