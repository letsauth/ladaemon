use crate::agents::SignJws;
use crate::bridges::oidc::ProviderKey;
use crate::config::Config;
use crate::email_address::EmailAddress;
use crate::utils::{base64url, keys::SignError, unix_duration, SecureRandom};
use ring::{
    digest,
    error::Unspecified,
    signature::{self, UnparsedPublicKey},
};
use serde_json as json;
use serde_json::{json, Error as JsonError, Value};
use std::fmt;
use std::iter::Iterator;
use thiserror::Error;

type RsaPublicKey = signature::RsaPublicKeyComponents<Vec<u8>>;

/// Token signing algorithms we support.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SigningAlgorithm {
    EdDsa,
    Rs256,
}

impl SigningAlgorithm {
    /// Get the JWA string representation.
    pub fn as_str(self) -> &'static str {
        use SigningAlgorithm::*;
        match self {
            EdDsa => "EdDSA",
            Rs256 => "RS256",
        }
    }

    /// Format a list of algorithms for display.
    pub fn format_list(list: &[Self]) -> String {
        list.iter()
            .map(|alg| alg.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

impl fmt::Display for SigningAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for SigningAlgorithm {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<SigningAlgorithm, &'static str> {
        use SigningAlgorithm::*;
        match s {
            "EdDSA" => Ok(EdDsa),
            "RS256" => Ok(Rs256),
            _ => Err("unsupported value"),
        }
    }
}

serde_from_str!(SigningAlgorithm);
serde_display!(SigningAlgorithm);

/// The types of public keys we support.
pub enum SupportedPublicKey {
    Ed25519(UnparsedPublicKey<Vec<u8>>),
    Rsa(RsaPublicKey),
}

impl SupportedPublicKey {
    /// Verify a message signature.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Unspecified> {
        use SupportedPublicKey::*;
        match self {
            Ed25519(ref inner) => inner.verify(message, signature),
            Rsa(ref inner) => {
                inner.verify(&signature::RSA_PKCS1_2048_8192_SHA256, message, signature)
            }
        }
    }
}

/// Helper function to build a session ID for a login attempt.
///
/// Put the email address, the client ID (RP origin) and some randomness into
/// a SHA256 hash, and encode it with URL-safe bas64 encoding. This is used
/// as the key in Redis, as well as the state for OAuth authentication.
pub async fn session_id(email: &EmailAddress, client_id: &str, rng: &SecureRandom) -> String {
    let rand_bytes = rng.generate_async(16).await;
    let mut ctx = digest::Context::new(&digest::SHA256);
    ctx.update(email.as_str().as_bytes());
    ctx.update(client_id.as_bytes());
    ctx.update(&rand_bytes);
    base64url::encode(&ctx.finish())
}

/// Helper function to create a secure nonce.
pub async fn nonce(rng: &SecureRandom) -> String {
    let rand_bytes = rng.generate_async(16).await;
    base64url::encode(&rand_bytes)
}

/// Helper function to create a random string consisting of
/// characters from the z-base-32 set.
pub async fn random_zbase32(len: usize, rng: &SecureRandom) -> String {
    const CHARSET: &[u8] = b"13456789abcdefghijkmnopqrstuwxyz";
    let rand_bytes = rng.generate_async(len).await;
    String::from_utf8(
        rand_bytes
            .into_iter()
            .map(|v| CHARSET[v as usize % CHARSET.len()])
            .collect(),
    )
    .expect("failed to build one-time pad")
}

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("the token must consist of three dot-separated parts")]
    IncorrectFormat,
    #[error("token part {index} contained invalid base64: {reason}")]
    InvalidPartBase64 {
        index: usize,
        reason: base64::DecodeError,
    },
    #[error("the token header contained invalid JSON: {0}")]
    InvalidHeaderJson(JsonError),
    #[error("did not find a string 'kid' property in the token header")]
    KidMissing,
    #[error("the token 'kid' could not be found in the JWKs document: {kid}")]
    KidNotMatched { kid: String },
    #[error(
        "the '{}' field of the matching JWK contains invalid base64: {}",
        property,
        reason
    )]
    InvalidJwkBase64 {
        property: &'static str,
        reason: base64::DecodeError,
    },
    #[error("the matching JWK is of an unsupported type")]
    UnsupportedKeyType,
    #[error("the token signature did not validate using the matching JWK")]
    BadSignature,
    #[error("the token payload contained invalid JSON: {0}")]
    InvalidPayloadJson(JsonError),
}

/// Verify a JWS signature, returning the payload as a `Value` if successful.
pub fn verify_jws(
    jws: &str,
    key_set: &[ProviderKey],
    signing_alg: SigningAlgorithm,
) -> Result<json::Value, VerifyError> {
    // Split the token up in parts and decode them.
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 {
        return Err(VerifyError::IncorrectFormat);
    }
    let decoded = parts
        .iter()
        .enumerate()
        .map(|(idx, s)| {
            base64url::decode(s).map_err(|reason| VerifyError::InvalidPartBase64 {
                index: idx + 1,
                reason,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Parse the header and find the key ID.
    let jwt_header: json::Value =
        json::from_slice(&decoded[0]).map_err(VerifyError::InvalidHeaderJson)?;
    let kid = jwt_header
        .get("kid")
        .and_then(Value::as_str)
        .ok_or(VerifyError::KidMissing)?;

    // Look for they key ID in the JWKs.
    let matched_keys: Vec<&ProviderKey> = key_set
        .iter()
        .filter(|key| key.use_ == "sig" && key.kid == kid)
        .collect();

    // Verify that we found exactly one key matching the key ID.
    if matched_keys.len() != 1 {
        return Err(VerifyError::KidNotMatched {
            kid: kid.to_owned(),
        });
    }
    let key = matched_keys.first().unwrap();

    // Then, use the data to build a public key object for verification.
    let pub_key = match (signing_alg, key.alg.as_str(), key.crv.as_str()) {
        (SigningAlgorithm::EdDsa, "EdDSA", "Ed25519") => {
            let x = base64url::decode(&key.x).map_err(|reason| VerifyError::InvalidJwkBase64 {
                property: "x",
                reason,
            })?;
            let key = UnparsedPublicKey::new(&signature::ED25519, x);
            SupportedPublicKey::Ed25519(key)
        }
        (SigningAlgorithm::Rs256, "RS256", _) => {
            let n = base64url::decode(&key.n).map_err(|reason| VerifyError::InvalidJwkBase64 {
                property: "n",
                reason,
            })?;
            let e = base64url::decode(&key.e).map_err(|reason| VerifyError::InvalidJwkBase64 {
                property: "e",
                reason,
            })?;
            let key = RsaPublicKey { n, e };
            SupportedPublicKey::Rsa(key)
        }
        _ => return Err(VerifyError::UnsupportedKeyType),
    };

    // Verify the signature using the public key.
    let message_len = parts[0].len() + parts[1].len() + 1;
    pub_key
        .verify(jws[..message_len].as_bytes(), &decoded[2])
        .map_err(|_err| VerifyError::BadSignature)?;

    // Return the payload.
    json::from_slice(&decoded[1]).map_err(VerifyError::InvalidPayloadJson)
}

/// Helper method to create a JWT for a given email address and audience.
///
/// Builds the JSON payload, then signs it using the last key provided in the configuration object.
///
/// Currently, the only possible failure here is that we accepted a signing algorithm from the RP
/// that suddenly disappeared from our config. The caller may treat this as an internal error.
pub async fn create_jwt(
    app: &Config,
    email: &str,
    email_addr: &EmailAddress,
    aud: &str,
    nonce: &str,
    signing_alg: SigningAlgorithm,
) -> Result<String, SignError> {
    let now = unix_duration();
    app.key_manager
        .send(SignJws {
            payload: json!({
                "aud": aud,
                "email": email_addr.as_str(),
                "email_verified": true,
                "email_original": email,
                "exp": (now + app.token_ttl).as_secs(),
                "iat": now.as_secs(),
                "iss": &app.public_url,
                "sub": email_addr.as_str(),
                "nonce": nonce,
            }),
            signing_alg,
        })
        .await
}
