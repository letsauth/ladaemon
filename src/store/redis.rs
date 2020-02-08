use crate::store::{CacheItem, CacheStore, LimitKey, LimitStore, SessionStore, Store};
use crate::utils::{BoxError, BoxFuture, LimitConfig};
use crate::web::Session;
use redis::{aio::MultiplexedConnection as RedisConn, AsyncCommands, RedisError, Script};
use serde_json as json;
use std::sync::Arc;
use std::time::Duration;
use url::Url;

/// Store implementation using Redis.
pub struct RedisStore {
    /// The connection.
    client: RedisConn,
    /// TTL of session keys
    expire_sessions: Duration,
    /// TTL of cache keys
    expire_cache: Duration,
    /// Script used to check a limit.
    limit_script: Arc<Script>,
    /// Configuration for per-email rate limiting.
    limit_per_email_config: LimitConfig,
}

impl RedisStore {
    pub async fn new(
        mut url: String,
        expire_sessions: Duration,
        expire_cache: Duration,
        limit_per_email_config: LimitConfig,
    ) -> Result<Self, RedisError> {
        if url.starts_with("http://") {
            url = url.replace("http://", "redis://");
        } else if !url.starts_with("redis://") {
            url = format!("redis://{}", &url);
        }
        let client = redis::Client::open(url.as_str())?
            .get_multiplexed_tokio_connection()
            .await?;

        log::warn!("Storing sessions in: {}", url);
        log::warn!("Please always double check this Redis and the connection to it are secure!");
        log::warn!("(This warning can't be fixed; it's a friendly reminder.)");

        let limit_script = Arc::new(Script::new(
            r"
            local count = redis.call('incr', KEYS[1])
            if count == 1 then
                redis.call('expire', KEYS[1], ARGV[1])
            end
            return count
            ",
        ));

        Ok(RedisStore {
            client,
            expire_sessions,
            expire_cache,
            limit_script,
            limit_per_email_config,
        })
    }

    fn format_session_key(session_id: &str) -> String {
        format!("session:{}", session_id)
    }
}

impl SessionStore for RedisStore {
    fn store_session(&self, session_id: &str, data: Session) -> BoxFuture<Result<(), BoxError>> {
        let mut client = self.client.clone();
        let ttl = self.expire_sessions;
        let key = Self::format_session_key(session_id);
        Box::pin(async move {
            let data = json::to_string(&data)?;
            client.set_ex(&key, data, ttl.as_secs() as usize).await?;
            Ok(())
        })
    }

    fn get_session(&self, session_id: &str) -> BoxFuture<Result<Option<Session>, BoxError>> {
        let mut client = self.client.clone();
        let key = Self::format_session_key(session_id);
        Box::pin(async move {
            let data: String = client.get(&key).await?;
            let data = json::from_str(&data)?;
            Ok(data)
        })
    }

    fn remove_session(&self, session_id: &str) -> BoxFuture<Result<(), BoxError>> {
        let mut client = self.client.clone();
        let key = Self::format_session_key(session_id);
        Box::pin(async move {
            client.del(&key).await?;
            Ok(())
        })
    }
}

impl CacheStore for RedisStore {
    fn get_cache_item(
        &self,
        url: &Url,
    ) -> BoxFuture<Result<Box<dyn CacheItem + Send + Sync>, BoxError>> {
        let key = url.as_str().to_owned();
        let client = self.client.clone();
        let expire_cache = self.expire_cache;
        Box::pin(async move {
            let item: Box<dyn CacheItem + Send + Sync> =
                Box::new(RedisCacheItem::new(key, client, expire_cache).await?);
            Ok(item)
        })
    }
}

impl LimitStore for RedisStore {
    fn incr_and_test_limit(&self, key: LimitKey<'_>) -> BoxFuture<Result<bool, BoxError>> {
        let (key, config) = match key {
            LimitKey::PerEmail { addr } => (
                format!("ratelimit::addr:{}", addr),
                &self.limit_per_email_config,
            ),
        };
        let LimitConfig {
            max_count,
            duration,
        } = *config;
        let mut client = self.client.clone();
        let script = self.limit_script.clone();
        Box::pin(async move {
            let mut invocation = script.prepare_invoke();
            invocation.key(key).arg(duration.as_secs());
            let count: usize = invocation.invoke_async(&mut client).await?;
            Ok(count <= max_count)
        })
    }
}

impl Store for RedisStore {}

struct RedisCacheItem {
    key: String,
    client: RedisConn,
    expire_cache: Duration,
}

impl RedisCacheItem {
    async fn new(
        key: String,
        client: RedisConn,
        expire_cache: Duration,
    ) -> Result<Self, RedisError> {
        // TODO: Lock
        Ok(RedisCacheItem {
            client,
            key,
            expire_cache,
        })
    }
}

impl Drop for RedisCacheItem {
    fn drop(&mut self) {
        // TODO: Unlock
    }
}

impl CacheItem for RedisCacheItem {
    fn read(&self) -> BoxFuture<Result<Option<String>, BoxError>> {
        let mut client = self.client.clone();
        let key = self.key.clone();
        Box::pin(async move {
            let data = client.get(key).await?;
            Ok(data)
        })
    }

    fn write(&mut self, value: String, max_age: Duration) -> BoxFuture<Result<(), BoxError>> {
        let mut client = self.client.clone();
        let key = self.key.clone();
        let ttl = std::cmp::max(self.expire_cache, max_age);
        Box::pin(async move {
            client
                .set_ex::<_, _, ()>(key, value, ttl.as_secs() as usize)
                .await?;
            Ok(())
        })
    }
}
