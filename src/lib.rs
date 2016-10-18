extern crate emailaddress;
#[macro_use]
extern crate log;
extern crate hyper;
extern crate iron;
extern crate lettre;
extern crate mustache;
extern crate redis;
extern crate serde;
extern crate serde_json;
extern crate time;
extern crate url;
extern crate urlencoded;

use emailaddress::EmailAddress;
use iron::headers::{ContentType, Location};
use iron::middleware::Handler;
use iron::modifiers;
use iron::method::Method;
use iron::prelude::*;
use iron::status;
use iron::typemap;
use iron::Url;
use serde_json::builder::{ArrayBuilder, ObjectBuilder};
use serde_json::value::Value;
use std::env;
use std::fs::File;
use std::io::{BufReader, Read};
use std::sync::Arc;
use std::error::Error;
use time::now_utc;
use urlencoded::{UrlEncodedBody, UrlEncodedQuery};

pub mod error;
pub mod config;
pub use config::AppConfig;
pub mod crypto;
pub mod email;
pub mod oidc;
pub mod store;
pub mod store_cache;

use error::{BrokerResult, BrokerError};


/// Iron extension key we use to store the redirect_uri.
/// Once set, the error handler will return errors to the RP.
struct RedirectUri;
impl typemap::Key for RedirectUri { type Value = Url; }


/// Macro that creates Handler implementations that log the request,
/// and keep a reference to the AppConfig.
macro_rules! broker_handler {
    ( $name:ident , | $app:ident, $req:ident | $body:block ) => {
        pub struct $name {
            pub app: Arc<AppConfig>,
        }
        impl $name {
            pub fn new(app: &Arc<AppConfig>) -> Self {
                $name { app: app.clone() }
            }
            fn handle_body($app: &AppConfig, $req: &mut Request)
                -> BrokerResult<Response> $body
        }
        impl Handler for $name {
            fn handle(&self, req: &mut Request) -> IronResult<Response> {
                info!("{} {}", req.method, req.url);
                Self::handle_body(&self.app, req)
                    .or_else(|e| handle_error(&self.app, req, e))
            }
        }
    }
}

/// Macro used to extract a parameter from a QueryMap.
///
/// Will return from the caller with a BrokerError if the parameter is missing.
///
/// ```
/// let foo = try_get_param!(params, "foo");
/// ```
macro_rules! try_get_param {
    ( $input:expr , $param:tt ) => {
        try!($input.get($param).map(|list| &list[0]).ok_or_else(|| {
            BrokerError::Input(concat!("missing request parameter ", $param).to_string())
        }))
    }
}


/// Helper function for returning a result to the Relying Party.
///
/// Takes an array of `(name, value)` parameter pairs to send to the relier and
/// embeds them in a form in `tmpl/forward.html`, from where it's POSTed to the
/// RP's `redirect_uri` as soon as the page has loaded.
///
/// The return value is a tuple of response modifiers.
fn return_to_relier(app: &AppConfig, redirect_uri: &str, params: &[(&str, &str)])
    -> (hyper::status::StatusCode, modifiers::Header<ContentType>, String) {
    let data = mustache::MapBuilder::new()
        .insert_str("redirect_uri", redirect_uri)
        .insert_map("params", |mut builder| {
            for &param in params {
                let (name, value) = param;
                builder = builder
                    .insert_str("name", name)
                    .insert_str("value", value);
            }
            builder
        })
        .build();
    (status::Ok,
     modifiers::Header(ContentType::html()),
     app.templates.forward.render_data(&data))
}


/// Handle an BrokerError and create an IronResult.
///
/// The `broker_handler!` macro calls this on error. We don't use a `From`
/// implementation, because this way we get app and request context, and we
/// don't necessarily have to pass the error on to Iron.
fn handle_error(app: &AppConfig, _: &mut Request, err: BrokerError) -> IronResult<Response> {
    match err {
        BrokerError::Input(_) => {
            let obj = ObjectBuilder::new()
                .insert("error", err.description())
                .build();
            let content = serde_json::to_string(&obj).unwrap();
            let content_type = modifiers::Header(ContentType::json());
            Ok(Response::with((status::BadRequest, content_type, content)))
        }
        BrokerError::Provider(_) => {
            // TODO: Redirect to RP with the error description
            Err(IronError::new(err, status::ServiceUnavailable))
        }
        _ => {
            Err(IronError::new(err, (status::InternalServerError,
                                     modifiers::Header(ContentType::html()),
                                     app.templates.error.render(&[]))))
        }
    }
}


/// Helper function for returning an Iron response with JSON data.
///
/// Serializes the argument value to JSON and returns a HTTP 200 response
/// code with the serialized JSON as the body.
fn json_response(obj: &Value) -> BrokerResult<Response> {
    let content = serde_json::to_string(&obj).unwrap();
    Ok(Response::with((status::Ok,
                       modifiers::Header(ContentType::json()),
                       content)))
}


/// Iron handler for the root path, returns human-friendly message.
///
/// This is not actually used in the protocol.
broker_handler!(WelcomeHandler, |_app, _req| {
    json_response(&ObjectBuilder::new()
        .insert("ladaemon", "Welcome")
        .insert("version", env!("CARGO_PKG_VERSION"))
        .build())
});


/// Iron handler for files in .well-known.
///
/// Mainly directed at Let's Encrypt verification. Returns text/plain always.
broker_handler!(WellKnownHandler, |_app, req| {
    let mut file_name = env::current_dir().unwrap();
    file_name.push(req.url.path().join("/"));
    let file_res = File::open(file_name);
    if file_res.is_err() {
        return Ok(Response::with((status::NotFound)));
    }
    let mut bytes = Vec::<u8>::new();
    let mut reader = BufReader::new(file_res.unwrap());
    let _ = reader.read_to_end(&mut bytes).unwrap();
    Ok(Response::with((status::Ok,
                       modifiers::Header(ContentType::plaintext()),
                       bytes)))
});


/// Iron handler to return the OpenID Discovery document.
///
/// Most of this is hard-coded for now, although the URLs are constructed by
/// using the base URL as configured in the `base_url` configuration value.
broker_handler!(OIDConfigHandler, |app, _req| {
    json_response(&ObjectBuilder::new()
        .insert("issuer", &app.base_url)
        .insert("authorization_endpoint",
                format!("{}/auth", app.base_url))
        .insert("jwks_uri", format!("{}/keys.json", app.base_url))
        .insert("scopes_supported", vec!["openid", "email"])
        .insert("claims_supported",
                vec!["aud", "email", "email_verified", "exp", "iat", "iss", "sub"])
        .insert("response_types_supported", vec!["id_token"])
        .insert("response_modes_supported", vec!["form_post"])
        .insert("grant_types_supported", vec!["implicit"])
        .insert("subject_types_supported", vec!["public"])
        .insert("id_token_signing_alg_values_supported", vec!["RS256"])
        .build())
});


/// Iron handler for the JSON Web Key Set document.
///
/// Respond with the JWK key set containing all of the configured keys.
///
/// Relying Parties will need to fetch this data to be able to verify identity
/// tokens issued by this daemon instance.
broker_handler!(KeysHandler, |app, _req| {
    let mut keys = ArrayBuilder::new();
    for key in &app.keys {
        keys = keys.push(key.public_jwk())
    }
    json_response(&ObjectBuilder::new()
                      .insert("keys", keys.build())
                      .build())
});


/// Iron handler for authentication requests from the RP.
///
/// Calls the `oidc::request()` function if the provided email address's
/// domain matches one of the configured famous providers. Otherwise, calls the
/// `email::request()` function to allow authentication through the email loop.
broker_handler!(AuthHandler, |app, req| {
    let params = try!(
        match req.method {
            Method::Get => {
                req.compute::<UrlEncodedQuery>()
                    .map_err(|_| BrokerError::Input("no query string in GET request".to_string()))
            },
            Method::Post => {
                req.compute::<UrlEncodedBody>()
                    .map_err(|_| BrokerError::Input("no query string in POST data".to_string()))
            },
            _ => {
                panic!("Unsupported method: {}", req.method)
            }
        }
    );

    // Per the OAuth2 spec, we may redirect to the RP once we have validated client_id and
    // redirect_uri. In our case, this means we make redirect_uri available to error handling.
    let client_id = try_get_param!(params, "client_id");
    let redirect_uri = try!(
        Url::parse(try_get_param!(params, "redirect_uri"))
            .map_err(|_| BrokerError::Input("redirect_uri is not a valid URL".to_string()))
    );
    req.extensions.insert::<RedirectUri>(redirect_uri.clone());

    let email_addr = try!(
        EmailAddress::new(try_get_param!(params, "login_hint"))
            .map_err(|_| BrokerError::Input("login_hint is not a valid email address".to_string()))
    );
    let nonce = try_get_param!(params, "nonce");
    if app.providers.contains_key(&email_addr.domain) {

        // OIDC authentication. Redirect to the identity provider.
        let auth_url = try!(oidc::request(app, email_addr, client_id, nonce, &redirect_uri));
        Ok(Response::with((status::SeeOther, modifiers::Header(Location(auth_url.to_string())))))

    } else {

        // Email loop authentication. Render a message and form.
        let session_id = try!(email::request(app, email_addr, client_id, nonce, &redirect_uri));
        Ok(Response::with((status::Ok,
                           modifiers::Header(ContentType::html()),
                           app.templates.confirm_email.render(&[
                               ("client_id", &client_id),
                               ("session_id", &session_id),
                           ]))))

    }
});


/// Helper method to create a JWT for a given email address and origin.
///
/// Builds the JSON payload, then signs it using the last key provided in
/// the configuration object.
fn create_jwt(app: &AppConfig, email: &str, origin: &str, nonce: &str) -> String {
    let now = now_utc().to_timespec().sec;
    let payload = &ObjectBuilder::new()
        .insert("aud", origin)
        .insert("email", email)
        .insert("email_verified", email)
        .insert("exp", now + app.token_validity as i64)
        .insert("iat", now)
        .insert("iss", &app.base_url)
        .insert("sub", email)
        .insert("nonce", nonce)
        .build();
    app.keys.last().unwrap().sign_jws(&payload)
}


/// Iron handler for one-time pad email loop confirmation.
///
/// Retrieves the session based session ID and the expected one-time pad.
/// Verify the code and return the resulting token or error to the RP.
broker_handler!(ConfirmHandler, |app, req| {
    let params = try!(
        req.compute::<UrlEncodedQuery>()
            .map_err(|_| BrokerError::Input("no query string in GET request".to_string()))
    );

    let stored = try!(app.store.get_session("email", &try_get_param!(params, "session")));
    req.extensions.insert::<RedirectUri>(Url::parse(&stored["redirect"]).unwrap());

    let code = try_get_param!(params, "code");
    let (jwt, redirect_uri) = try!(email::verify(app, &stored, code));
    Ok(Response::with(return_to_relier(app, &redirect_uri, &[("id_token", &jwt)])))
});


/// Iron handler for OAuth callbacks
///
/// After the user allows or denies the Authentication Request with the famous
/// identity provider, they will be redirected back to the callback handler.
/// Verify the callback data and return the resulting token or error.
broker_handler!(CallbackHandler, |app, req| {
    let params = try!(
        req.compute::<UrlEncodedQuery>()
            .map_err(|_| BrokerError::Input("no query string in GET request".to_string()))
    );

    let stored = try!(app.store.get_session("oidc", &try_get_param!(params, "state")));
    req.extensions.insert::<RedirectUri>(Url::parse(&stored["redirect"]).unwrap());

    let code = try_get_param!(params, "code");
    let (jwt, redirect_uri) = try!(oidc::verify(app, &stored, code));
    Ok(Response::with(return_to_relier(app, &redirect_uri, &[("id_token", &jwt)])))
});
