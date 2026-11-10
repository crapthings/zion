//! Password proofs bind a shared secret to one verified TLS connection and request.

use super::wire::Request;
use anyhow::{Context, ensure};
use quinn::Connection;
use ring::hmac;
use serde::{Deserialize, Deserializer};
use std::{fmt, sync::Arc};
use zeroize::Zeroizing;

/// A password stores a reusable HMAC key while keeping debug output redacted.
#[derive(Clone)]
pub struct Password(Arc<hmac::Key>);

/// Password operations use Ring for signing and constant-time verification.
impl Password {
    /// Validate a password and discard its temporary plaintext after constructing the key.
    pub fn new(value: impl Into<String>) -> anyhow::Result<Self> {
        let value = Zeroizing::new(value.into());
        ensure!(
            !value.is_empty() && value.len() <= 1024,
            "password must contain 1 to 1024 bytes"
        );
        Ok(Self(Arc::new(hmac::Key::new(
            hmac::HMAC_SHA256,
            value.as_bytes(),
        ))))
    }

    /// Create a proof bound to this connection and the unsigned command fields.
    pub(crate) fn prove(
        &self,
        connection: &Connection,
        request: &Request,
    ) -> anyhow::Result<[u8; 32]> {
        let binding = binding(connection, request)?;
        Ok(self.sign_binding(&binding))
    }

    /// Verify a request's proof without comparing secret bytes in application code.
    pub(crate) fn verify(&self, connection: &Connection, request: &Request) -> anyhow::Result<()> {
        self.verify_binding(&binding(connection, request)?, request)
    }

    /// Sign an exporter value supplied by either verified TLS transport.
    pub(crate) fn sign_binding(&self, binding: &[u8; 32]) -> [u8; 32] {
        hmac::sign(&self.0, binding)
            .as_ref()
            .try_into()
            .expect("HMAC-SHA256 has 32 bytes")
    }

    /// Verify a transport-derived exporter proof with Ring's constant-time verification API.
    pub(crate) fn verify_binding(
        &self,
        binding: &[u8; 32],
        request: &Request,
    ) -> anyhow::Result<()> {
        let proof = request
            .auth
            .as_ref()
            .context("password authentication is required")?;
        hmac::verify(&self.0, binding, proof)
            .map_err(|_| anyhow::anyhow!("password authentication failed"))
    }
}

/// Debug formatting never exposes the password or its derived HMAC key.
impl fmt::Debug for Password {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Password([redacted])")
    }
}

/// Password deserialization accepts strings without adding a serialization capability.
impl<'de> Deserialize<'de> for Password {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Derive a request-specific TLS exporter value without enabling replayable early data.
fn binding(connection: &Connection, request: &Request) -> anyhow::Result<[u8; 32]> {
    let context = serde_json::to_vec(&(request.version, &request.operation))?;
    let mut binding = [0; 32];
    connection
        .export_keying_material(&mut binding, b"EXPORTER-zion-password-v1", &context)
        .map_err(|_| anyhow::anyhow!("cannot derive tunnel authentication binding"))?;
    Ok(binding)
}
