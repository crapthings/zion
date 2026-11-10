//! Mutual TLS configuration requires explicit trust roots and role-specific certificates.

use super::wire::ALPN;
use anyhow::{Context, ensure};
use quinn::{
    TransportConfig,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use std::{
    fs,
    io::{BufReader, Write},
    path::Path,
    sync::Arc,
    time::Duration,
};

/// Loaded credentials contain the identity and trust anchors for one tunnel role.
pub struct Identity {
    certificates: Vec<CertificateDer<'static>>,
    key: Option<PrivateKeyDer<'static>>,
    roots: RootCertStore,
}

/// Identity operations load PEM files without weakening certificate verification.
impl Identity {
    /// Load a role's certificate, private key, and shared CA from a credential directory.
    pub fn load(directory: &Path, role: &str) -> anyhow::Result<Self> {
        ensure!(matches!(role, "client" | "server"), "unknown identity role");
        let certificates = load_certificates(&directory.join(format!("{role}.pem")))?;
        ensure!(
            !certificates.is_empty(),
            "identity certificate chain is empty"
        );
        let key_file = fs::File::open(directory.join(format!("{role}.key")))?;
        let key = rustls_pemfile::private_key(&mut BufReader::new(key_file))?
            .context("missing private key")?;
        let mut roots = RootCertStore::empty();
        for certificate in load_certificates(&directory.join("ca.pem"))? {
            roots.add(certificate)?;
        }
        ensure!(!roots.is_empty(), "CA trust store is empty");
        Ok(Self {
            certificates,
            key: Some(key),
            roots,
        })
    }

    /// Load a client identity with explicit or public CA trust and an optional certificate pair.
    pub fn client_from_files(
        ca: Option<&Path>,
        cert: Option<&Path>,
        key: Option<&Path>,
    ) -> anyhow::Result<Self> {
        ensure!(
            cert.is_some() == key.is_some(),
            "cert and key must be supplied together"
        );
        let roots = match ca {
            Some(path) => load_roots(path)?,
            None => RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            },
        };
        let (certificates, key) = match (cert, key) {
            (Some(cert), Some(key)) => (load_certificates(cert)?, Some(load_key(key)?)),
            _ => (Vec::new(), None),
        };
        ensure!(
            cert.is_none() || !certificates.is_empty(),
            "identity certificate chain is empty"
        );
        Ok(Self {
            certificates,
            key,
            roots,
        })
    }

    /// Load transient PEM credentials passed by a native host without requiring shared private-key files.
    pub fn client_from_pem(
        ca: Option<&[u8]>,
        cert: Option<&[u8]>,
        key: Option<&[u8]>,
    ) -> anyhow::Result<Self> {
        ensure!(
            cert.is_some() == key.is_some(),
            "cert and key must be supplied together"
        );
        let mut roots = RootCertStore::empty();
        if let Some(ca) = ca {
            for certificate in rustls_pemfile::certs(&mut std::io::Cursor::new(ca)) {
                roots.add(certificate?)?;
            }
            ensure!(!roots.is_empty(), "CA trust store is empty");
        } else {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
        let certificates = match cert {
            Some(cert) => rustls_pemfile::certs(&mut std::io::Cursor::new(cert))
                .collect::<Result<Vec<_>, _>>()?,
            None => vec![],
        };
        ensure!(
            cert.is_none() || !certificates.is_empty(),
            "identity certificate chain is empty"
        );
        let key = match key {
            Some(key) => Some(
                rustls_pemfile::private_key(&mut std::io::Cursor::new(key))?
                    .context("missing private key")?,
            ),
            None => None,
        };
        Ok(Self {
            roots,
            certificates,
            key,
        })
    }

    /// Load server TLS material and optionally require certificates from a client CA.
    pub fn server_from_files(
        cert: &Path,
        key: &Path,
        client_ca: Option<&Path>,
    ) -> anyhow::Result<Self> {
        let certificates = load_certificates(cert)?;
        ensure!(
            !certificates.is_empty(),
            "server certificate chain is empty"
        );
        let roots = client_ca
            .map(load_roots)
            .transpose()?
            .unwrap_or_else(RootCertStore::empty);
        Ok(Self {
            certificates,
            key: Some(load_key(key)?),
            roots,
        })
    }

    /// Report whether this identity can present a certificate during a client handshake.
    pub(crate) fn has_certificate(&self) -> bool {
        self.key.is_some() && !self.certificates.is_empty()
    }

    /// Report whether a server identity enforces certificate authentication for clients.
    pub(crate) fn verifies_clients(&self) -> bool {
        !self.roots.is_empty()
    }

    /// Configure a client that validates the server and presents its own certificate.
    pub fn client(self) -> anyhow::Result<quinn::ClientConfig> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(self.roots);
        let mut tls = match self.key {
            Some(key) => builder.with_client_auth_cert(self.certificates, key)?,
            None => builder.with_no_client_auth(),
        };
        tls.alpn_protocols = vec![ALPN.to_vec()];
        tls.enable_early_data = false;
        let mut config = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls)?));
        config.transport_config(Arc::new(transport()));
        Ok(config)
    }

    /// Configure a server that requires a client certificate signed by its trusted CA.
    pub fn server(self) -> anyhow::Result<quinn::ServerConfig> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])?;
        let builder = if self.roots.is_empty() {
            builder.with_no_client_auth()
        } else {
            let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
                Arc::new(self.roots),
                provider,
            )
            .build()?;
            builder.with_client_cert_verifier(verifier)
        };
        let mut tls = builder.with_single_cert(
            self.certificates,
            self.key.context("missing server private key")?,
        )?;
        tls.alpn_protocols = vec![ALPN.to_vec()];
        tls.max_early_data_size = 0;
        let mut config =
            quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?));
        config.transport_config(Arc::new(transport()));
        Ok(config)
    }
}

/// Transport limits bound stream counts and buffering for each isolated session.
fn transport() -> TransportConfig {
    let mut config = TransportConfig::default();
    config.max_concurrent_bidi_streams(1u8.into());
    config.max_concurrent_uni_streams(0u8.into());
    config.keep_alive_interval(Some(Duration::from_secs(15)));
    config.max_idle_timeout(Some(
        Duration::from_secs(45).try_into().expect("valid timeout"),
    ));
    config.datagram_receive_buffer_size(Some(256 * 1024));
    config.datagram_send_buffer_size(256 * 1024);
    config
}

/// Read a PEM certificate chain using the maintained Rustls parser.
fn load_certificates(path: &Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    Ok(
        rustls_pemfile::certs(&mut BufReader::new(fs::File::open(path)?))
            .collect::<Result<_, _>>()?,
    )
}

/// Read a private key with the maintained Rustls PEM parser.
fn load_key(path: &Path) -> anyhow::Result<PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(&mut BufReader::new(fs::File::open(path)?))?
        .context("missing private key")
}

/// Build a nonempty trust store from an explicit CA file.
fn load_roots(path: &Path) -> anyhow::Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for certificate in load_certificates(path)? {
        roots.add(certificate)?;
    }
    ensure!(!roots.is_empty(), "CA trust store is empty");
    Ok(roots)
}

/// Issue a fresh local CA and role-specific identities into a new private directory.
pub fn generate(directory: &Path, server_name: &str) -> anyhow::Result<()> {
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa,
        KeyPair, KeyUsagePurpose,
    };
    let mut ca = CertificateParams::new(Vec::<String>::new())?;
    ca.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let issuer = CertifiedIssuer::self_signed(ca, KeyPair::generate()?)?;
    let mut files = vec![("ca.pem".to_owned(), issuer.pem())];
    for (role, usage) in [
        ("server", ExtendedKeyUsagePurpose::ServerAuth),
        ("client", ExtendedKeyUsagePurpose::ClientAuth),
    ] {
        let key = KeyPair::generate()?;
        let names = if role == "server" {
            vec![server_name.to_owned()]
        } else {
            vec![]
        };
        let mut params = CertificateParams::new(names)?;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![usage];
        let certificate = params.signed_by(&key, &issuer)?;
        files.push((format!("{role}.pem"), certificate.pem()));
        files.push((format!("{role}.key"), key.serialize_pem()));
    }
    create_private_directory(directory)?;
    for (name, contents) in files {
        write_private(&directory.join(name), contents.as_bytes())?;
    }
    Ok(())
}

/// Create a fresh credential directory without exposing its contents on Unix.
fn create_private_directory(path: &Path) -> std::io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

/// Create a credential file exclusively with restrictive Unix permissions.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(bytes)
}
