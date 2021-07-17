use crate::agents::key_manager::rotating::{KeySet, RotatingKeys};
use crate::config::LimitInput;
use crate::crypto::SigningAlgorithm;
use crate::utils::agent::{Addr, Message, Sender};
use crate::utils::BoxError;
use crate::web::{Session, SessionData};
use prometheus::Histogram;
use std::collections::HashSet;
use url::Url;

/// Message requesting a session be saved.
pub struct SaveSession {
    /// The session ID.
    pub session_id: String,
    /// Session data to save.
    pub data: Session,
}
impl Message for SaveSession {
    type Reply = Result<(), BoxError>;
}

/// Message requesting a session be fetched.
pub struct GetSession {
    /// The session ID.
    pub session_id: String,
}
impl Message for GetSession {
    type Reply = Result<Option<Session>, BoxError>;
}

/// Message requesting a session be deleted.
pub struct DeleteSession {
    /// The session ID.
    pub session_id: String,
}
impl Message for DeleteSession {
    type Reply = Result<(), BoxError>;
}

/// Message requesting an authorization code by saved.
pub struct SaveAuthCode {
    /// The authorization code.
    pub code: String,
    /// Session data to save.
    pub data: SessionData,
}
impl Message for SaveAuthCode {
    type Reply = Result<(), BoxError>;
}

/// Message requesting an authorization code be retrieved and deleted.
pub struct ConsumeAuthCode {
    /// The authorization code.
    pub code: String,
}
impl Message for ConsumeAuthCode {
    type Reply = Result<Option<SessionData>, BoxError>;
}

/// Message requesting a URL be fetched, possibly from cache.
pub struct FetchUrlCached {
    /// The URL to fetch.
    pub url: Url,
    /// Latency metric to use on cache miss.
    pub metric: &'static Histogram,
}
impl Message for FetchUrlCached {
    type Reply = Result<String, BoxError>;
}

/// Message requesting rate limits be increased and tested.
///
/// The configured rate limits are passed to the store when it is created. The store should always
/// increment all rate limits, even if only the first one fails, for example. The result is `true`
/// if none of the rate limits were hit.
pub struct IncrAndTestLimits {
    pub input: LimitInput,
}
impl Message for IncrAndTestLimits {
    type Reply = Result<bool, BoxError>;
}

/// Message requesting rate limits be decreased.
///
/// Rate limits are decreased when authentication was successfully completed, but only for rate
/// limits that have the `decr_complete` flag set.
pub struct DecrLimits {
    pub input: LimitInput,
}
impl Message for DecrLimits {
    type Reply = Result<(), BoxError>;
}

/// Message requesting rotating keys be enabled.
///
/// The store should retrieve the current key sets for each signing algorithm and send `UpdateKeys`
/// messages to the key manager, and subscribe to changes from other workers (if applicable).
pub struct EnableRotatingKeys {
    /// The key manager to send updates to.
    pub key_manager: Addr<RotatingKeys>,
    /// Signing algorithms enabled in configuration.
    pub signing_algs: HashSet<SigningAlgorithm>,
}
impl Message for EnableRotatingKeys {
    type Reply = ();
}

/// Message requesting keys be rotated with an exclusive lock.
///
/// This message is sent by the key manager when it has detected that some keys have expired.
///
/// The store should acquire an exclusive lock, then send `RotateKeys` back to the key manager with
/// the current key set. If the key manager returns an new key set, the store should save it, then
/// send `UpdateKeys` to the key manager to install the new key set.
///
/// (The store is also responsible for notifying other workers of key updates, if applicable.)
pub struct RotateKeysLocked(pub SigningAlgorithm);
impl Message for RotateKeysLocked {
    type Reply = ();
}

/// Write a new key set, and notify other workers if possible.
///
/// This is used to implement `--import-key`.
pub struct ImportKeySet(pub KeySet);
impl Message for ImportKeySet {
    type Reply = ();
}

/// Store abstraction. Combines all message types.
///
/// Downside of this is that it needs to be implemented on the agent side as:
/// `impl StoreSender for Addr<FoobarStore> {}`
pub trait StoreSender:
    Sender<SaveSession>
    + Sender<GetSession>
    + Sender<DeleteSession>
    + Sender<SaveAuthCode>
    + Sender<ConsumeAuthCode>
    + Sender<FetchUrlCached>
    + Sender<IncrAndTestLimits>
    + Sender<DecrLimits>
    + Sender<EnableRotatingKeys>
    + Sender<RotateKeysLocked>
    + Sender<ImportKeySet>
{
}

pub mod memory;
pub use self::memory::MemoryStore;

#[cfg(feature = "redis")]
pub mod redis;
#[cfg(feature = "redis")]
pub use self::redis::RedisStore;

#[cfg(feature = "rusqlite")]
pub mod rusqlite;
#[cfg(feature = "rusqlite")]
pub use self::rusqlite::RusqliteStore;
