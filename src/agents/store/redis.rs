use crate::agents::*;
use crate::config::LimitConfig;
use crate::crypto::SigningAlgorithm;
use crate::utils::{
    agent::*,
    redis::{locking, pubsub},
    BoxError, SecureRandom,
};
use ::redis::{
    aio::MultiplexedConnection as RedisConn, pipe, AsyncCommands, Client as RedisClient,
    IntoConnectionInfo, RedisResult, Script,
};
use futures_util::future;
use std::{convert::identity, sync::Arc, time::Duration};

/// Internal message used to lock a key set.
struct LockKeys(SigningAlgorithm);
impl Message for LockKeys {
    type Reply = locking::LockGuard;
}

/// Internal message used to fetch a key set.
struct FetchKeys(SigningAlgorithm);
impl Message for FetchKeys {
    type Reply = RedisResult<KeySet>;
}

/// Internal message used to save a key set.
struct SaveKeys(KeySet);
impl Message for SaveKeys {
    type Reply = RedisResult<()>;
}

/// Internal message used to fetch keys and send an update to the key manager.
struct UpdateKeysLocked(SigningAlgorithm);
impl Message for UpdateKeysLocked {
    type Reply = ();
}

/// Store implementation using Redis.
pub struct RedisStore {
    /// A random unique ID for ourselves.
    id: Arc<[u8]>,
    /// The connection.
    conn: RedisConn,
    /// Pubsub client.
    pubsub: pubsub::Subscriber,
    /// Locking client.
    locking: locking::LockClient,
    /// TTL of session keys
    expire_sessions: Duration,
    /// TTL of auth code keys
    expire_auth_codes: Duration,
    /// TTL of cache keys
    expire_cache: Duration,
    /// The agent used for fetching on cache miss.
    fetcher: Addr<FetchAgent>,
    /// Key manager if rotating keys are enabled.
    key_manager: Option<Addr<RotatingKeys>>,
    /// Script used to increment a limit.
    incr_limit_script: Arc<Script>,
    /// Script used to decrement a limit.
    decr_limit_script: Arc<Script>,
    /// Rate limit configuration.
    limit_configs: Vec<LimitConfig>,
}

impl RedisStore {
    pub async fn new(
        mut url: String,
        expire_sessions: Duration,
        expire_auth_codes: Duration,
        expire_cache: Duration,
        limit_configs: Vec<LimitConfig>,
        fetcher: Addr<FetchAgent>,
        rng: SecureRandom,
    ) -> RedisResult<Self> {
        if url.starts_with("http://") {
            url = url.replace("http://", "redis://");
        } else if !url.starts_with("redis://") {
            url = format!("redis://{}", &url);
        }
        let id = rng.generate_async(16).await.into();
        let info = url.as_str().into_connection_info()?;
        let pubsub = pubsub::connect(&info).await?;
        let conn = RedisClient::open(info)?
            .get_multiplexed_tokio_connection()
            .await?;
        let locking = locking::LockClient::new(conn.clone(), pubsub.clone(), rng);

        log::warn!("Storing sessions and keys in Redis at {}", url);
        log::warn!("Please always double check this Redis and the connection to it are secure!");
        log::warn!("(This warning can't be fixed; it's a friendly reminder.)");

        let incr_limit_script = Arc::new(Script::new(
            r"
            local count = redis.call('incr', KEYS[1])
            if count == 1 or ARGV[2] == 'true' then
                redis.call('expire', KEYS[1], ARGV[1])
            end
            return count
            ",
        ));

        let decr_limit_script = Arc::new(Script::new(
            r"
            local count = redis.call('decr', KEYS[1])
            if count <= 0 then
                redis.call('del', KEYS[1])
            end
            ",
        ));

        Ok(RedisStore {
            id,
            conn,
            pubsub,
            locking,
            expire_sessions,
            expire_auth_codes,
            expire_cache,
            fetcher,
            key_manager: None,
            incr_limit_script,
            decr_limit_script,
            limit_configs,
        })
    }

    fn format_session_key(session_id: &str) -> String {
        format!("session:{}", session_id)
    }

    fn format_auth_code_key(code: &str) -> String {
        format!("auth_code:{}", code)
    }
}

impl Agent for RedisStore {
    fn started(&mut self, cx: Context<Self, AgentStarted>) {
        // Ping Redis at an interval.
        let mut conn = self.conn.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(20));
            // Ignore the first (immediate) tick.
            interval.tick().await;
            loop {
                interval.tick().await;
                let _res: String = ::redis::cmd("PING")
                    .query_async(&mut conn)
                    .await
                    .expect("Redis ping failed");
            }
        });
        cx.reply(());
    }
}

impl Handler<SaveSession> for RedisStore {
    fn handle(&mut self, message: SaveSession, cx: Context<Self, SaveSession>) {
        let mut conn = self.conn.clone();
        let ttl = self.expire_sessions;
        cx.reply_later(async move {
            let key = Self::format_session_key(&message.session_id);
            let data = serde_json::to_string(&message.data)?;
            conn.set_ex(&key, data, ttl.as_secs() as usize).await?;
            Ok(())
        });
    }
}

impl Handler<GetSession> for RedisStore {
    fn handle(&mut self, message: GetSession, cx: Context<Self, GetSession>) {
        let mut conn = self.conn.clone();
        cx.reply_later(async move {
            let key = Self::format_session_key(&message.session_id);
            let data: Option<String> = conn.get(&key).await?;
            if let Some(data) = data {
                Ok(Some(serde_json::from_str(&data)?))
            } else {
                Ok(None)
            }
        });
    }
}

impl Handler<DeleteSession> for RedisStore {
    fn handle(&mut self, message: DeleteSession, cx: Context<Self, DeleteSession>) {
        let mut conn = self.conn.clone();
        cx.reply_later(async move {
            let key = Self::format_session_key(&message.session_id);
            conn.del(&key).await?;
            Ok(())
        });
    }
}

impl Handler<SaveAuthCode> for RedisStore {
    fn handle(&mut self, message: SaveAuthCode, cx: Context<Self, SaveAuthCode>) {
        let mut conn = self.conn.clone();
        let ttl = self.expire_auth_codes;
        cx.reply_later(async move {
            let key = Self::format_auth_code_key(&message.code);
            let data = serde_json::to_string(&message.data)?;
            conn.set_ex(&key, data, ttl.as_secs() as usize).await?;
            Ok(())
        });
    }
}

impl Handler<ConsumeAuthCode> for RedisStore {
    fn handle(&mut self, message: ConsumeAuthCode, cx: Context<Self, ConsumeAuthCode>) {
        let mut conn = self.conn.clone();
        cx.reply_later(async move {
            let key = Self::format_auth_code_key(&message.code);
            let data: (Option<String>,) = pipe()
                .atomic()
                .get(&key)
                .del(&key)
                .ignore()
                .query_async(&mut conn)
                .await?;
            if let (Some(data),) = data {
                Ok(Some(serde_json::from_str(&data)?))
            } else {
                Ok(None)
            }
        });
    }
}

impl Handler<FetchUrlCached> for RedisStore {
    fn handle(&mut self, message: FetchUrlCached, cx: Context<Self, FetchUrlCached>) {
        let mut conn = self.conn.clone();
        let mut locking = self.locking.clone();
        let fetcher = self.fetcher.clone();
        let expire_cache = self.expire_cache;
        cx.reply_later(async move {
            let key = format!("cache:{}", message.url);
            let _lock = locking.lock(format!("lock:{}", key).as_bytes()).await;
            if let Some(data) = conn.get(key).await? {
                Ok(data)
            } else {
                let key = message.url.as_str().to_owned();
                let result = fetcher
                    .send(FetchUrl::get(&message.url, message.metric))
                    .await?;
                let ttl = std::cmp::max(expire_cache, result.max_age);
                conn.set_ex(key, result.data.clone(), ttl.as_secs() as usize)
                    .await?;
                Ok(result.data)
            }
        });
    }
}

impl Handler<IncrAndTestLimits> for RedisStore {
    fn handle(&mut self, message: IncrAndTestLimits, cx: Context<Self, IncrAndTestLimits>) {
        let conn = self.conn.clone();
        let script = self.incr_limit_script.clone();
        let ops: Vec<_> = self
            .limit_configs
            .iter()
            .map(|config| {
                let key = message.input.build_key(&config, "rate-limit:", "|");
                (config.clone(), key)
            })
            .collect();
        cx.reply_later(async move {
            let results = future::try_join_all(ops.into_iter().map(|(config, key)| {
                let mut conn = conn.clone();
                let script = script.clone();
                async move {
                    let count: usize = script
                        .prepare_invoke()
                        .key(key)
                        .arg(config.window.as_secs())
                        .arg(config.extend_window)
                        .invoke_async(&mut conn)
                        .await?;
                    Ok::<_, BoxError>(count <= config.max_count)
                }
            }))
            .await?;
            Ok(results.into_iter().all(identity))
        });
    }
}

impl Handler<DecrLimits> for RedisStore {
    fn handle(&mut self, message: DecrLimits, cx: Context<Self, DecrLimits>) {
        let conn = self.conn.clone();
        let script = self.decr_limit_script.clone();
        let keys: Vec<_> = self
            .limit_configs
            .iter()
            .filter_map(|config| {
                if config.decr_complete {
                    Some(message.input.build_key(&config, "rate-limit:", "|"))
                } else {
                    None
                }
            })
            .collect();
        cx.reply_later(async move {
            let _unused: Vec<()> = future::try_join_all(keys.into_iter().map(|key| {
                let mut conn = conn.clone();
                let script = script.clone();
                async move {
                    script
                        .prepare_invoke()
                        .key(key)
                        .invoke_async(&mut conn)
                        .await
                }
            }))
            .await?;
            Ok(())
        });
    }
}

impl Handler<EnableRotatingKeys> for RedisStore {
    fn handle(&mut self, message: EnableRotatingKeys, cx: Context<Self, EnableRotatingKeys>) {
        let me = cx.addr().clone();
        let my_id = self.id.clone();
        let mut pubsub = self.pubsub.clone();
        self.key_manager = Some(message.key_manager.clone());
        cx.reply_later(async move {
            for signing_alg in &message.signing_algs {
                let signing_alg = *signing_alg;
                // Listen for key changes by other workers.
                let chan = format!("keys-updated:{}", signing_alg).into_bytes();
                let mut sub = pubsub.subscribe(chan).await;
                let me2 = me.clone();
                let my_id2 = my_id.clone();
                tokio::spawn(async move {
                    loop {
                        let from_id = sub.recv().await.expect("Redis keys subscription failed");
                        if from_id.as_slice() != my_id2.as_ref() {
                            me2.send(UpdateKeysLocked(signing_alg));
                        }
                    }
                });
                // Fetch current keys.
                me.send(UpdateKeysLocked(signing_alg)).await;
            }
        });
    }
}

impl Handler<RotateKeysLocked> for RedisStore {
    fn handle(&mut self, message: RotateKeysLocked, cx: Context<Self, RotateKeysLocked>) {
        let me = cx.addr().clone();
        let key_manager = self.key_manager.as_ref().unwrap().clone();
        cx.reply_later(async move {
            let lock = me.send(LockKeys(message.0)).await;
            let key_set = me
                .send(FetchKeys(message.0))
                .await
                .expect("Failed to fetch keys from Redis");
            if let Some(key_set) = key_manager.send(RotateKeys(key_set)).await {
                me.send(SaveKeys(key_set.clone()))
                    .await
                    .expect("Failed to save keys to Redis");
                drop(lock);
                key_manager.send(UpdateKeys(key_set)).await;
            }
        });
    }
}

impl Handler<ImportKeySet> for RedisStore {
    fn handle(&mut self, message: ImportKeySet, cx: Context<Self, ImportKeySet>) {
        let me = cx.addr().clone();
        cx.reply_later(async move {
            me.send(SaveKeys(message.0))
                .await
                .expect("Failed to save keys to Redis");
        });
    }
}

impl Handler<LockKeys> for RedisStore {
    fn handle(&mut self, message: LockKeys, cx: Context<Self, LockKeys>) {
        let mut locking = self.locking.clone();
        let lock_key = format!("lock:keys:{}", message.0);
        cx.reply_later(async move { locking.lock(lock_key.as_bytes()).await });
    }
}

impl Handler<FetchKeys> for RedisStore {
    fn handle(&mut self, message: FetchKeys, cx: Context<Self, FetchKeys>) {
        let mut conn = self.conn.clone();
        let signing_alg = message.0;
        let db_key = format!("keys:{}", signing_alg);
        cx.reply_later(async move {
            let key_set: Option<String> = conn.get(db_key).await?;
            let key_set = key_set.map_or_else(
                || KeySet::empty(signing_alg),
                |data| serde_json::from_str(&data).expect("Invalid key set JSON in Redis"),
            );
            Ok(key_set)
        })
    }
}

impl Handler<SaveKeys> for RedisStore {
    fn handle(&mut self, message: SaveKeys, cx: Context<Self, SaveKeys>) {
        let mut conn = self.conn.clone();
        let signing_alg = message.0.signing_alg;
        let db_key = format!("keys:{}", signing_alg);
        let data = serde_json::to_string(&message.0).expect("Could not encode key set as JSON");
        let mut pipe = pipe();
        pipe.atomic()
            .set(db_key, data)
            .publish(format!("keys-updated:{}", signing_alg), &self.id[..]);
        cx.reply_later(async move { pipe.query_async(&mut conn).await });
    }
}

impl Handler<UpdateKeysLocked> for RedisStore {
    fn handle(&mut self, message: UpdateKeysLocked, cx: Context<Self, UpdateKeysLocked>) {
        let me = cx.addr().clone();
        let key_manager = self.key_manager.as_ref().unwrap().clone();
        cx.reply_later(async move {
            let key_set = {
                let _lock = me.send(LockKeys(message.0)).await;
                me.send(FetchKeys(message.0))
                    .await
                    .expect("Failed to fetch keys from Redis")
            };
            key_manager.send(UpdateKeys(key_set)).await;
        });
    }
}

impl StoreSender for Addr<RedisStore> {}
