extern crate openssl;
extern crate rand;
extern crate rustc_serialize;
extern crate serde;
extern crate toml;

use emailaddress::EmailAddress;
use self::openssl::bn::BigNum;
use self::openssl::crypto::hash;
use self::openssl::crypto::pkey::PKey;
use self::openssl::crypto::rsa::RSA;
use self::rand::{OsRng, Rng};
use self::rustc_serialize::base64::{self, FromBase64, ToBase64};
use serde_json::builder::ObjectBuilder;
use serde_json::de::from_slice;
use serde_json::value::Value;
use super::chrono::{DateTime, UTC};
use super::serde_json;
use std;
use std::error::Error;
use std::fmt::{self, Display};
use std::fs::File;
use std::io::{Read, Write};

include!(concat!(env!("OUT_DIR"), "/crypto_serde.rs"));


/// Union of all possible error types seen while parsing.
#[derive(Debug)]
pub enum CryptoError {
    Custom(String),
    Io(std::io::Error),
}

impl Error for CryptoError {
    fn description(&self) -> &str {
        match *self {
            CryptoError::Custom(ref string) => string,
            CryptoError::Io(ref err) => err.description(),
        }
    }
}

impl Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self{
            CryptoError::Custom(ref string) => string.fmt(f),
            CryptoError::Io(ref err) => write!(f, "IO error: {}", err),
        }
    }
}

macro_rules! from_error {
    ( $orig:ty, $enum_type:ident ) => {
        impl From<$orig> for CryptoError {
            fn from(err: $orig) -> CryptoError {
                CryptoError::$enum_type(err)
            }
        }
    }
}

from_error!(String, Custom);
from_error!(std::io::Error, Io);


/// A named key pair, for use in JWS signing.
#[derive(Clone)]
pub struct NamedKey {
    id: String,
    key: PKey,
    valid_from: Option<DateTime<UTC>>,
}


impl NamedKey {
    /// Creates a NamedKey by reading a `file` path and generating an `id`.
    pub fn from_file(filename: &str) -> Result<NamedKey, CryptoError> {
        let mut file = File::open(filename)?;
        let mut pem = String::new();
        file.read_to_string(&mut pem)?;

        let pkey = PKey::private_key_from_pem(&mut pem.as_bytes())
            .map_err(|err| format!("failed to parse key '{}': {}", filename, err))?;

        let meta = Self::meta_from_pem(&pem)
            .map_err(|err| format!("failed to parse key '{}': {}", filename, err))?;

        let mut key = NamedKey::from_pkey(pkey)?;
        key.valid_from = meta.valid_from;
        Ok(key)
    }

    /// Creates a NamedKey from a PEM-encoded str.
    pub fn from_pem_str(pem: &str) -> Result<NamedKey, CryptoError> {
        let pkey = PKey::private_key_from_pem(&mut pem.as_bytes())
            .map_err(|err| format!("failed to parse key: {}", err))?;

        let meta = Self::meta_from_pem(pem)
            .map_err(|err| format!("failed to parse key: {}", err))?;

        let mut key = NamedKey::from_pkey(pkey)?;
        key.valid_from = meta.valid_from;
        Ok(key)
    }

    /// Parses metadata from a PEM file.
    fn meta_from_pem(pem: &str) -> Result<PrivateKeyMetadata, String> {
        toml::decode_str(
            &pem.lines()
                .skip_while(|&line| line != "-----BEGIN PORTIER METADATA-----")
                .skip(1)
                .take_while(|&line| line != "-----END PORTIER METADATA-----")
                .collect::<Vec<&str>>()
                .join("\n")
        ).ok_or("unable to parse metadata".to_string())
    }

    /// Creates a NamedKey from a PKey
    pub fn from_pkey(pkey: PKey) -> Result<NamedKey, CryptoError> {
        let e = pkey.get_rsa().e().expect("unable to retrieve key's e value");
        let n = pkey.get_rsa().n().expect("unable to retrieve key's n value");

        let mut hasher = hash::Hasher::new(hash::Type::SHA256);
        hasher.write(e.to_vec().as_slice()).expect("pubkey hashing failed");
        hasher.write(b".").expect("pubkey hashing failed");
        hasher.write(n.to_vec().as_slice()).expect("pubkey hashing failed");
        let name = hasher.finish().to_base64(base64::URL_SAFE);

        Ok(NamedKey { id: name, key: pkey, valid_from: None })
    }

    /// Create a JSON Web Signature (JWS) for the given JSON structure.
    pub fn sign_jws(&self, payload: &Value) -> String {
        let header = serde_json::to_string(
            &ObjectBuilder::new()
                .insert("kid", &self.id)
                .insert("alg", "RS256")
                .build()
            ).expect("unable to coerce jwt header into string");

        let payload = serde_json::to_string(&payload)
            .expect("unable to coerce jwt payload into string");
        let mut input = Vec::<u8>::new();
        input.extend(header.as_bytes().to_base64(base64::URL_SAFE).into_bytes());
        input.push(b'.');
        input.extend(payload.as_bytes().to_base64(base64::URL_SAFE).into_bytes());

        let sha256 = hash::hash(hash::Type::SHA256, &input);
        let sig = self.key.sign(&sha256);
        input.push(b'.');
        input.extend(sig.to_base64(base64::URL_SAFE).into_bytes());
        String::from_utf8(input).expect("unable to coerce jwt into string")
    }

    /// Return JSON represenation of the public key for use in JWK key sets.
    pub fn public_jwk(&self) -> Value {
        fn json_big_num(n: &BigNum) -> String {
            n.to_vec().to_base64(base64::URL_SAFE)
        }
        let n = self.key.get_rsa().n().expect("unable to retrieve key's n value");
        let e = self.key.get_rsa().e().expect("unable to retrieve key's e value");
        ObjectBuilder::new()
            .insert("kty", "RSA")
            .insert("alg", "RS256")
            .insert("use", "sig")
            .insert("kid", &self.id)
            .insert("n", json_big_num(&n))
            .insert("e", json_big_num(&e))
            .build()
    }

    // Check if the key is valid at the given time.
    pub fn is_valid_at(&self, time: &DateTime<UTC>) -> bool {
        match self.valid_from {
            Some(ref valid_from) => time >= valid_from,
            None => true
        }
    }
}


/// Helper function to build a session ID for a login attempt.
///
/// Put the email address, the client ID (RP origin) and some randomness into
/// a SHA256 hash, and encode it with URL-safe bas64 encoding. This is used
/// as the key in Redis, as well as the state for OAuth authentication.
pub fn session_id(email: &EmailAddress, client_id: &str) -> String {
    let mut rng = OsRng::new().expect("unable to create rng");
    let rand_bytes: Vec<u8> = (0..16).map(|_| rng.gen()).collect();

    let mut hasher = hash::Hasher::new(hash::Type::SHA256);
    hasher.write(email.to_string().as_bytes()).expect("session hashing failed");
    hasher.write(client_id.as_bytes()).expect("session hashing failed");
    hasher.write(&rand_bytes).expect("session hashing failed");
    hasher.finish().to_base64(base64::URL_SAFE)
}


/// Helper function to deserialize key from JWK Key Set.
///
/// Searches the provided JWK Key Set Value for the key matching the given
/// id. Returns a usable public key if exactly one key is found.
pub fn jwk_key_set_find(set: &Value, kid: &str) -> Result<PKey, ()> {
    let key_objs = set.find("keys").and_then(|v| v.as_array()).ok_or(())?;
    let matching = key_objs.iter()
        .filter(|key_obj| {
            key_obj.find("kid").and_then(|v| v.as_str()) == Some(kid) &&
            key_obj.find("use").and_then(|v| v.as_str()) == Some("sig")
        })
        .collect::<Vec<&Value>>();

    // Verify that we found exactly one key matching the key ID.
    if matching.len() != 1 {
        return Err(());
    }

    // Then, use the data to build a public key object for verification.
    let n = matching[0].find("n").and_then(|v| v.as_str()).ok_or(())
                .and_then(|data| data.from_base64().map_err(|_| ()))
                .and_then(|data| BigNum::new_from_slice(&data).map_err(|_| ()))?;
    let e = matching[0].find("e").and_then(|v| v.as_str()).ok_or(())
                .and_then(|data| data.from_base64().map_err(|_| ()))
                .and_then(|data| BigNum::new_from_slice(&data).map_err(|_| ()))?;
    let rsa = RSA::from_public_components(n, e).map_err(|_| ())?;
    let mut pub_key = PKey::new();
    pub_key.set_rsa(&rsa);
    Ok(pub_key)
}


/// Verify a JWS signature, returning the payload as Value if successful.
pub fn verify_jws(jws: &str, key_set: &Value) -> Result<Value, ()> {
    // Extract the header from the JWT structure. Determine what key was used
    // to sign the token, so we can then verify the signature.
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 {
        return Err(());
    }
    let decoded = parts.iter().map(|s| s.from_base64())
                    .collect::<Result<Vec<_>, _>>().map_err(|_| ())?;
    let jwt_header: Value = from_slice(&decoded[0]).map_err(|_| ())?;
    let kid = jwt_header.find("kid").and_then(|v| v.as_str()).ok_or(())?;
    let pub_key = jwk_key_set_find(key_set, kid)?;

    // Verify the identity token's signature.
    let message_len = parts[0].len() + parts[1].len() + 1;
    let sha256 = hash::hash(hash::Type::SHA256, jws[..message_len].as_bytes());
    if !pub_key.verify(&sha256, &decoded[2]) {
        return Err(());
    }

    Ok(from_slice(&decoded[1]).map_err(|_| ())?)
}
