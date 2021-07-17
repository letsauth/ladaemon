use crate::agents::*;
use crate::config::LimitConfig;
use crate::crypto::SigningAlgorithm;
use crate::utils::agent::*;
use crate::web::{Session, SessionData};
use std::collections::hash_map::{Entry, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use url::Url;

/// Combines any type with an `Instant` expiry time.
struct Expiring<T> {
    value: T,
    expires: Instant,
}

impl<T> Expiring<T> {
    /// Create a value from a duration.
    fn from_duration(value: T, duration: Duration) -> Self {
        let expires = Instant::now() + duration;
        Expiring { value, expires }
    }

    /// Whether this value has not yet expired.
    fn is_alive(&self) -> bool {
        self.expires > Instant::now()
    }
}

/// Message sent at an interval to collect garbage.
struct Gc;
impl Message for Gc {
    type Reply = ();
}

/// A slot in the cache `HashMap`.
///
/// We want to lock these individually while a fetch is in progress, so multiple requests for the
/// same URL result in only one fetch. Therefore, we use an `Arc<Mutex<_>>` to carry slots around,
/// and within an `Option` which indicates whether cache is actually present (despite the hash map
/// entry existing or not, which does not indicate anything).
type CacheSlot = Arc<Mutex<Option<Expiring<String>>>>;

/// A slot in the keys `HashMap`.
///
/// It's technically not necessary for us to lock keys, because the key manager is our only client,
/// but we do so any ways to ensure correct behavior.
type KeysSlot = Arc<Mutex<KeySet>>;

/// Store implementation using memory.
pub struct MemoryStore {
    /// TTL of session keys
    expire_sessions: Duration,
    /// TTL of auth code keys
    expire_auth_codes: Duration,
    /// TTL of cache keys
    expire_cache: Duration,
    /// Rate limit configuration.
    limit_configs: Vec<LimitConfig>,
    /// The agent used for fetching on cache miss.
    fetcher: Addr<FetchAgent>,
    /// Key manager if rotating keys are enabled.
    key_manager: Option<Addr<RotatingKeys>>,
    /// Session storage.
    sessions: HashMap<String, Expiring<Session>>,
    /// Auth code storage.
    auth_codes: HashMap<String, Expiring<SessionData>>,
    /// Cache storage.
    cache: HashMap<Url, CacheSlot>,
    /// Rate limit storage.
    limits: HashMap<String, Expiring<usize>>,
    /// Keys storage.
    keys: HashMap<SigningAlgorithm, KeysSlot>,
}

impl MemoryStore {
    pub fn new(
        expire_sessions: Duration,
        expire_auth_codes: Duration,
        expire_cache: Duration,
        limit_configs: Vec<LimitConfig>,
        fetcher: Addr<FetchAgent>,
    ) -> Self {
        log::warn!("Storing sessions and keys in memory.");
        log::warn!("Note that these will be lost on restart!");

        MemoryStore {
            expire_sessions,
            expire_auth_codes,
            expire_cache,
            limit_configs,
            fetcher,
            key_manager: None,
            sessions: HashMap::new(),
            auth_codes: HashMap::new(),
            cache: HashMap::new(),
            limits: HashMap::new(),
            keys: HashMap::new(),
        }
    }
}

impl Agent for MemoryStore {
    fn started(&mut self, cx: Context<Self, AgentStarted>) {
        // Start the garbage collection loop.
        let addr = cx.addr().clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            // Ignore the first (immediate) tick, because we'll always be empty.
            interval.tick().await;
            loop {
                interval.tick().await;
                addr.send(Gc).await;
            }
        });
        cx.reply(());
    }
}

impl Handler<Gc> for MemoryStore {
    fn handle(&mut self, _message: Gc, cx: Context<Self, Gc>) {
        self.sessions = self
            .sessions
            .drain()
            .filter(|(_, ref entry)| entry.is_alive())
            .collect();
        self.auth_codes = self
            .auth_codes
            .drain()
            .filter(|(_, ref entry)| entry.is_alive())
            .collect();
        self.cache = self
            .cache
            .drain()
            .filter(|(_, ref slot)| {
                // For cache items, only remove if we have the sole reference. Otherwise, a fetch
                // might still be in progress. Locking should be immediate if true.
                if let Ok(maybe_entry) = slot.try_lock() {
                    Arc::strong_count(slot) > 1
                        || maybe_entry
                            .as_ref()
                            .filter(|entry| entry.is_alive())
                            .is_some()
                } else {
                    true
                }
            })
            .collect();
        self.limits = self
            .limits
            .drain()
            .filter(|(_, ref entry)| entry.is_alive())
            .collect();
        cx.reply(())
    }
}

impl Handler<SaveSession> for MemoryStore {
    fn handle(&mut self, message: SaveSession, cx: Context<Self, SaveSession>) {
        self.sessions.insert(
            message.session_id,
            Expiring::from_duration(message.data, self.expire_sessions),
        );
        cx.reply(Ok(()))
    }
}

impl Handler<GetSession> for MemoryStore {
    fn handle(&mut self, message: GetSession, cx: Context<Self, GetSession>) {
        let data = self
            .sessions
            .get(&message.session_id)
            .filter(|entry| entry.is_alive())
            .map(|entry| entry.value.clone());
        cx.reply(Ok(data))
    }
}

impl Handler<DeleteSession> for MemoryStore {
    fn handle(&mut self, message: DeleteSession, cx: Context<Self, DeleteSession>) {
        self.sessions.remove(&message.session_id);
        cx.reply(Ok(()))
    }
}

impl Handler<SaveAuthCode> for MemoryStore {
    fn handle(&mut self, message: SaveAuthCode, cx: Context<Self, SaveAuthCode>) {
        self.auth_codes.insert(
            message.code,
            Expiring::from_duration(message.data, self.expire_auth_codes),
        );
        cx.reply(Ok(()))
    }
}

impl Handler<ConsumeAuthCode> for MemoryStore {
    fn handle(&mut self, message: ConsumeAuthCode, cx: Context<Self, ConsumeAuthCode>) {
        cx.reply(Ok(self
            .auth_codes
            .remove(&message.code)
            .filter(Expiring::is_alive)
            .map(|entry| entry.value)))
    }
}

impl Handler<FetchUrlCached> for MemoryStore {
    fn handle(&mut self, message: FetchUrlCached, cx: Context<Self, FetchUrlCached>) {
        let fetcher = self.fetcher.clone();
        let slot = self.cache.entry(message.url.clone()).or_default().clone();
        let expire_cache = self.expire_cache;
        cx.reply_later(async move {
            let mut slot = slot.lock().await;
            if let Some(entry) = slot.as_ref().filter(|entry| entry.is_alive()) {
                return Ok(entry.value.clone());
            }
            let result = fetcher
                .send(FetchUrl::get(&message.url, message.metric))
                .await?;
            let ttl = std::cmp::max(expire_cache, result.max_age);
            *slot = Some(Expiring::from_duration(result.data.clone(), ttl));
            Ok(result.data)
        });
    }
}

impl Handler<IncrAndTestLimits> for MemoryStore {
    fn handle(&mut self, message: IncrAndTestLimits, cx: Context<Self, IncrAndTestLimits>) {
        let mut ok = true;
        for config in &self.limit_configs {
            let key = message.input.build_key(&config, "", "|");
            let count = match self.limits.entry(key) {
                Entry::Occupied(mut entry) => {
                    let mut expiring = entry.get_mut();
                    let now = Instant::now();
                    if expiring.expires <= now {
                        *expiring = Expiring::from_duration(1, config.window);
                        1
                    } else {
                        if config.extend_window {
                            expiring.expires = now + config.window;
                        }
                        expiring.value = expiring.value.saturating_add(1);
                        expiring.value
                    }
                }
                Entry::Vacant(entry) => {
                    entry.insert(Expiring::from_duration(1, config.window));
                    1
                }
            };
            ok = ok && count <= config.max_count;
        }
        cx.reply(Ok(ok));
    }
}

impl Handler<DecrLimits> for MemoryStore {
    fn handle(&mut self, message: DecrLimits, cx: Context<Self, DecrLimits>) {
        for config in &self.limit_configs {
            if !config.decr_complete {
                continue;
            }
            let key = message.input.build_key(&config, "", "|");
            if let Entry::Occupied(mut entry) = self.limits.entry(key) {
                let Expiring { expires, value } = *entry.get();
                let now = Instant::now();
                if expires <= now || value <= 1 {
                    entry.remove();
                } else {
                    entry.get_mut().value -= 1;
                }
            };
        }
        cx.reply(Ok(()));
    }
}

impl Handler<EnableRotatingKeys> for MemoryStore {
    fn handle(&mut self, message: EnableRotatingKeys, cx: Context<Self, EnableRotatingKeys>) {
        self.key_manager = Some(message.key_manager.clone());
        let mut update_msgs = Vec::with_capacity(message.signing_algs.len());
        for signing_alg in &message.signing_algs {
            let key_set = KeySet::empty(*signing_alg);
            update_msgs.push(UpdateKeys(key_set.clone()));
            self.keys
                .insert(*signing_alg, Arc::new(Mutex::new(key_set)));
        }
        cx.reply_later(async move {
            for update_msg in update_msgs {
                message.key_manager.send(update_msg).await;
            }
        });
    }
}

impl Handler<RotateKeysLocked> for MemoryStore {
    fn handle(&mut self, message: RotateKeysLocked, cx: Context<Self, RotateKeysLocked>) {
        let slot_rc = self.keys[&message.0].clone();
        let key_manager = self.key_manager.as_ref().unwrap().clone();
        cx.reply_later(async move {
            let mut slot = slot_rc
                .try_lock()
                .expect("Keys lock should never be locked twice");
            if let Some(key_set) = key_manager.send(RotateKeys(slot.clone())).await {
                *slot = key_set.clone();
                key_manager.send(UpdateKeys(key_set)).await;
            }
        });
    }
}

impl Handler<ImportKeySet> for MemoryStore {
    fn handle(&mut self, _message: ImportKeySet, _cx: Context<Self, ImportKeySet>) {
        panic!("Importing keys into a memory store has no effect");
    }
}

impl StoreSender for Addr<MemoryStore> {}
