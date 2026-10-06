//! Shared rustls client configurations.
//!
//! Certificates are checked against the bundled Mozilla root store (same trust model as the
//! Python original, which used `certifi`) so results do not depend on the Windows cert store.

use std::sync::{Arc, OnceLock};

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, ring};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, ClientConfig, DigitallySignedStruct, Error, RootCertStore, SignatureScheme};

fn provider() -> Arc<CryptoProvider> {
    static P: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
    P.get_or_init(|| Arc::new(ring::default_provider())).clone()
}

fn roots() -> Arc<RootCertStore> {
    static R: OnceLock<Arc<RootCertStore>> = OnceLock::new();
    R.get_or_init(|| {
        let mut store = RootCertStore::empty();
        store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Arc::new(store)
    })
    .clone()
}

/// Which TLS versions a client config may negotiate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsVersions {
    /// TLS 1.2 and 1.3
    Any,
    /// TLS 1.2 only
    Tls12,
    /// TLS 1.3 only
    Tls13,
}

fn build(versions: TlsVersions, verify_hostname: bool, alpn: &[&[u8]]) -> Arc<ClientConfig> {
    let versions_list: &[&'static rustls::SupportedProtocolVersion] = match versions {
        TlsVersions::Any => &[&rustls::version::TLS13, &rustls::version::TLS12],
        TlsVersions::Tls12 => &[&rustls::version::TLS12],
        TlsVersions::Tls13 => &[&rustls::version::TLS13],
    };
    let builder = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(versions_list)
        .expect("valid protocol versions");

    let mut cfg = if verify_hostname {
        builder.with_root_certificates(roots()).with_no_client_auth()
    } else {
        let inner = WebPkiServerVerifier::builder_with_provider(roots(), provider())
            .build()
            .expect("webpki verifier");
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(IgnoreNameVerifier(inner)))
            .with_no_client_auth()
    };
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(cfg)
}

/// Standard verification (chain + host name), TLS 1.2/1.3, no ALPN.
pub fn client_config() -> Arc<ClientConfig> {
    static C: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    C.get_or_init(|| build(TlsVersions::Any, true, &[])).clone()
}

/// Standard verification, offering only HTTP/2 via ALPN (Telegram media over Cloudflare).
pub fn client_config_h2() -> Arc<ClientConfig> {
    static C: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    C.get_or_init(|| build(TlsVersions::Any, true, &[b"h2"])).clone()
}

/// Verifies the certificate *chain* but not the host name. Used for domain fronting, where the
/// SNI deliberately differs from the host that is being reached.
pub fn client_config_fronting() -> Arc<ClientConfig> {
    static C: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    C.get_or_init(|| build(TlsVersions::Any, false, &[])).clone()
}

/// Standard verification, forcing a single TLS version (used by the strategy tests).
pub fn client_config_versioned(versions: TlsVersions) -> Arc<ClientConfig> {
    static C: OnceLock<[Arc<ClientConfig>; 3]> = OnceLock::new();
    let all = C.get_or_init(|| {
        [
            build(TlsVersions::Any, true, &[]),
            build(TlsVersions::Tls12, true, &[]),
            build(TlsVersions::Tls13, true, &[]),
        ]
    });
    match versions {
        TlsVersions::Any => all[0].clone(),
        TlsVersions::Tls12 => all[1].clone(),
        TlsVersions::Tls13 => all[2].clone(),
    }
}

#[derive(Debug)]
struct IgnoreNameVerifier(Arc<WebPkiServerVerifier>);

impl ServerCertVerifier for IgnoreNameVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        match self.0.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now) {
            Err(Error::InvalidCertificate(
                CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. },
            )) => Ok(ServerCertVerified::assertion()),
            other => other,
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.0.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.0.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}
