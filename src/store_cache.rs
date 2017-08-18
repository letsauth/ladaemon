use error::BrokerError;
use futures::{Future, future};
use config::Config;
use http;
use hyper::StatusCode;
use hyper::header::{CacheControl, CacheDirective};
use redis::Commands;
use serde_json as json;
use std::cmp::max;
use std::rc::Rc;
use std::str::from_utf8;
use url::Url;


/// Represents a Redis key.
pub enum CacheKey<'a> {
    Discovery { acct: &'a str },
    OidcConfig { origin: &'a str },
    OidcKeySet { origin: &'a str },
}

impl<'a> CacheKey<'a> {
    fn to_string(&self) -> String {
        match *self {
            CacheKey::Discovery { acct } => {
                format!("cache:discovery:{}", acct)
            },
            CacheKey::OidcConfig { origin } => {
                format!("cache:configuration:{}", origin)
            },
            CacheKey::OidcKeySet { origin } => {
                format!("cache:key-set:{}", origin)
            }
        }
    }
}


/// Fetch `url` from cache or using a HTTP GET request, and parse the response as JSON. The
/// cache is stored in `app.store` with `key`. The `client` is used to make the HTTP GET request,
/// if necessary.
pub fn fetch_json_url(app: &Rc<Config>, url: &Url, key: &CacheKey)
                      -> Box<Future<Item=json::Value, Error=BrokerError>> {

    // Try to retrieve the result from cache.
    let key_str = key.to_string();
    let data: Option<String> = match app.store.client.get(&key_str) {
        Ok(data) => data,
        Err(e) => return Box::new(future::err(e.into())),
    };

    let f: Box<Future<Item=String, Error=BrokerError>> = if let Some(data) = data {
        Box::new(future::ok(data))
    } else {
        // Cache miss, make a request.
        // TODO: Also cache failed requests, perhaps for a shorter time.
        let hyper_url = url.as_str().parse().expect("failed to convert Url to Hyper Url");
        let f = app.http_client.get(hyper_url).map_err(|err| err.into());

        let url = url.to_string();
        let f = f.and_then(move |res| {
            if res.status() != StatusCode::Ok {
                future::err(BrokerError::Provider(
                    format!("fetch failed ({}): {}", res.status(), url)))
            } else {
                future::ok(res)
            }
        });

        let app = app.clone();
        let f = f.and_then(move |res| {
            // Grab the max-age directive from the Cache-Control header.
            let max_age = res.headers().get().map_or(0, |header: &CacheControl| {
                for dir in header.iter() {
                    if let CacheDirective::MaxAge(seconds) = *dir {
                        return seconds;
                    }
                }
                0
            });

            // Receive the body.
            http::read_body(res.body())
                .map_err(|err| err.into())
                .map(move |chunk| (app, chunk, max_age))
        });

        let f = f.and_then(|(app, chunk, max_age)| {
            let result = from_utf8(&chunk)
                .map_err(|_| BrokerError::Provider("response contained invalid utf-8".to_string()))
                .map(|data| data.to_owned())
                .and_then(move |data| {
                    // Cache the response for at least `expire_cache`, but honor longer `max-age`.
                    let seconds = max(app.store.expire_cache, max_age as usize);
                    app.store.client.set_ex::<_, _, ()>(&key_str, &data, seconds)
                        .map_err(|err| err.into())
                        .map(|_| data)
                });
            future::result(result)
        });

        Box::new(f)
    };

    let f = f.and_then(|data| {
        future::result(json::from_str(&data).map_err(|_| {
            BrokerError::Provider("failed to parse response as JSON".to_string())
        }))
    });

    Box::new(f)
}
