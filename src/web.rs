use crate::agents::{GetSession, SaveSession};
use crate::bridges::BridgeData;
use crate::config::ConfigRc;
use crate::crypto::{self, SigningAlgorithm};
use crate::email_address::EmailAddress;
use crate::error::{BrokerError, BrokerResult};
use crate::metrics;
use crate::router::router;
use crate::utils::{http::ResponseExt, real_ip, BoxError, BoxFuture};
use bytes::{Bytes, BytesMut};
use futures_util::stream::StreamExt;
use gettext::Catalog;
use headers::{CacheControl, ContentType, Header, StrictTransportSecurity};
use http::{HeaderMap, Method, StatusCode, Uri};
use hyper::server::conn::AddrStream;
use hyper::service::Service as HyperService;
use hyper::Body;
use log::info;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    task::Poll,
    time::Duration,
};
use thiserror::Error;
use url::{form_urlencoded, Url};

/// Error type used within an `io::Error`, to indicate a size limit was exceeded.
#[derive(Debug, Error)]
#[error("size limit exceeded")]
pub struct SizeLimitExceeded;

/// A session as stored in Redis.
#[derive(Clone, Serialize, Deserialize)]
pub struct Session {
    pub data: SessionData,
    pub bridge_data: BridgeData,
}

/// Response types we support.
#[derive(Clone, Copy, Serialize, Deserialize)]
pub enum ResponseType {
    #[serde(rename = "id_token")]
    IdToken,
    // NOTE: This type is outside the Portier spec, but we support it in this implementation for
    // compatibility with other OpenID Connect clients.
    #[serde(rename = "code")]
    Code,
}

impl ResponseType {
    /// Get the default response mode for this response type.
    pub fn default_response_mode(self) -> ResponseMode {
        match self {
            ResponseType::IdToken => ResponseMode::Fragment,
            ResponseType::Code => ResponseMode::Query,
        }
    }
}

/// Response modes we support.
#[derive(Clone, Copy, Serialize, Deserialize)]
pub enum ResponseMode {
    #[serde(rename = "fragment")]
    Fragment,
    #[serde(rename = "form_post")]
    FormPost,
    // NOTE: This mode is outside the Portier spec, but we support it in this implementation for
    // compatibility with other OpenID Connect clients.
    #[serde(rename = "query")]
    Query,
}

impl ResponseMode {
    /// Return the querystring value for this response mode.
    pub fn as_str(&self) -> &str {
        match self {
            ResponseMode::Fragment => "fragment",
            ResponseMode::FormPost => "form_post",
            ResponseMode::Query => "query",
        }
    }
}

/// Parameters used to return to the relying party
#[derive(Clone, Serialize, Deserialize)]
pub struct ReturnParams {
    pub redirect_uri: Url,
    pub response_mode: ResponseMode,
    pub response_errors: bool,
    pub state: String,
}

/// Common session data.
#[derive(Clone, Serialize, Deserialize)]
pub struct SessionData {
    pub original_ip: IpAddr,
    pub return_params: ReturnParams,
    pub email: String,
    pub email_addr: EmailAddress,
    pub response_type: ResponseType,
    pub nonce: String,
    pub signing_alg: SigningAlgorithm,
}

/// Context for a request
pub struct Context {
    /// The application configuration
    pub app: ConfigRc,
    /// The IP address the request came from.
    pub ip: IpAddr,
    /// Request method
    pub method: Method,
    /// Request URI
    pub uri: Uri,
    /// Request headers
    pub headers: HeaderMap,
    /// Request body
    pub body: Bytes,
    /// Session ID
    pub session_id: String,
    /// Session data (must be explicitely loaded)
    pub session_data: Option<SessionData>,
    /// Index into the config catalogs of the language to use
    pub catalog_idx: usize,
    /// Parameters used to return to the relying party
    pub return_params: Option<ReturnParams>,
    /// Whether the response should contain a JSON body
    pub want_json: bool,
}

impl Context {
    /// Get a reference to the language catalog to use
    pub fn catalog(&self) -> &Catalog {
        &self.app.i18n.catalogs[self.catalog_idx].1
    }

    /// Parse the query string into a `HashMap`.
    pub fn query_params(&self) -> HashMap<String, String> {
        self.uri
            .query()
            .map_or(HashMap::new(), |query| parse_form_encoded(query.as_bytes()))
    }

    /// Parse the form-encoded body into a `HashMap`.
    pub fn form_params(&self) -> HashMap<String, String> {
        parse_form_encoded(&self.body)
    }

    /// Start a session by filling out the common part.
    pub async fn start_session(
        &mut self,
        client_id: &str,
        email: &str,
        email_addr: &EmailAddress,
        response_type: ResponseType,
        nonce: &str,
        signing_alg: SigningAlgorithm,
        ip: IpAddr,
    ) {
        assert!(self.session_id.is_empty());
        assert!(self.session_data.is_none());
        let return_params = self
            .return_params
            .as_ref()
            .expect("start_session called without return parameters");
        self.session_id = crypto::session_id(email_addr, client_id, &self.app.rng).await;
        self.session_data = Some(SessionData {
            original_ip: ip,
            return_params: return_params.clone(),
            email: email.to_owned(),
            email_addr: email_addr.clone(),
            response_type,
            nonce: nonce.to_owned(),
            signing_alg,
        });
    }

    /// Try to save the session with the given bridge data.
    ///
    /// Will return `false` if the session was not started, which will also happen if another
    /// provider has already claimed the session.
    pub async fn save_session(&mut self, bridge_data: BridgeData) -> BrokerResult<bool> {
        let data = match self.session_data.take() {
            Some(data) => data,
            None => return Ok(false),
        };
        self.app
            .store
            .send(SaveSession {
                session_id: self.session_id.clone(),
                data: Session { data, bridge_data },
            })
            .await
            .map_err(|e| BrokerError::Internal(format!("could not save a session: {}", e)))?;
        Ok(true)
    }

    /// Load a session from storage.
    pub async fn load_session(&mut self, id: &str) -> BrokerResult<BridgeData> {
        assert!(self.session_id.is_empty());
        assert!(self.session_data.is_none());
        assert!(self.return_params.is_none());
        let Session { data, bridge_data } = self
            .app
            .store
            .send(GetSession {
                session_id: id.to_owned(),
            })
            .await
            .map_err(|e| BrokerError::Internal(format!("could not load a session: {}", e)))?
            .ok_or(BrokerError::SessionExpired)?;
        self.return_params = Some(data.return_params.clone());
        self.session_id = id.to_owned();
        self.session_data = Some(data);
        Ok(bridge_data)
    }
}

/// Standard request type.
pub type Request = hyper::Request<Body>;
/// Standard response type.
pub type Response = hyper::Response<Body>;
/// Result type of handlers
pub type HandlerResult = Result<Response, BrokerError>;

/// HTTP service
pub struct Service {
    /// The application configuration
    app: ConfigRc,
    /// The client address
    remote_addr: SocketAddr,
}

impl Service {
    pub fn new(app: ConfigRc, stream: &AddrStream) -> Self {
        Self {
            app,
            remote_addr: stream.remote_addr(),
        }
    }

    async fn serve(ip: IpAddr, req: Request, app: ConfigRc) -> Result<Response, BoxError> {
        metrics::HTTP_REQUESTS.inc();

        // Handle only simple path requests.
        if req.uri().scheme_str().is_some() || req.uri().host().is_some() {
            let mut response = empty_response(StatusCode::BAD_REQUEST);
            set_headers(&mut response);
            return Ok(response);
        }

        // Read the request body.
        let (parts, mut body) = req.into_parts();
        let body = match parts.method {
            Method::POST => read_body(&mut body).await?,
            _ => Bytes::from(vec![]),
        };

        // Determine the language catalog to use.
        let mut catalog_idx = 0;
        if let Some(user_languages) = parts
            .headers
            .get(hyper::header::ACCEPT_LANGUAGE)
            .and_then(|value| value.to_str().ok())
        {
            'lang: for user_language in &accept_language::parse(user_languages) {
                for (idx, &(ref lang, _)) in app.i18n.catalogs.iter().enumerate() {
                    if lang == user_language {
                        catalog_idx = idx;
                        break 'lang;
                    }
                }
            }
        }

        // Create the request context.
        let want_json = parts
            .headers
            .get(hyper::header::ACCEPT)
            .map_or(false, |accept| accept == "application/json");
        let mut ctx = Context {
            app,
            ip,
            method: parts.method,
            uri: parts.uri,
            headers: parts.headers,
            body,
            session_id: String::default(),
            session_data: None,
            catalog_idx,
            return_params: None,
            want_json,
        };

        // Call the route handler.
        let result = router(&mut ctx).await;

        // Translate broker errors to responses.
        let mut response = match result {
            Ok(response) => response,
            Err(err) => handle_error(&ctx, err).await,
        };

        // Set common response headers.
        set_headers(&mut response);

        // Response status metrics.
        match response.status().as_u16() {
            100..=199 => metrics::HTTP_RESPONSE_STATUS_1XX.inc(),
            200..=299 => metrics::HTTP_RESPONSE_STATUS_2XX.inc(),
            300..=399 => metrics::HTTP_RESPONSE_STATUS_3XX.inc(),
            400..=499 => metrics::HTTP_RESPONSE_STATUS_4XX.inc(),
            500..=599 => metrics::HTTP_RESPONSE_STATUS_5XX.inc(),
            _ => {}
        }

        Ok(response)
    }
}

impl HyperService<Request> for Service {
    type Response = Response;
    type Error = BoxError;
    type Future = BoxFuture<Result<Response, BoxError>>;

    fn poll_ready(&mut self, _cx: &mut std::task::Context) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request) -> Self::Future {
        let ip = real_ip(self.remote_addr, &req, &self.app.trusted_proxies);
        info!("{} - {} {}", ip, req.method(), req.uri());

        // Grab what we need from `self` before creating a future.
        let app = Arc::clone(&self.app);
        Box::pin(Self::serve(ip, req, app))
    }
}

/// Handle a `BrokerError` and create a response.
///
/// Our service calls this on error. We handle all these errors, and always
/// return a response.
///
/// When we handle an error, we want to:
///
///  - Log internal errors and errors related to communcation with providers.
///  - Not log input errors, such as missing parameters.
///
///  - Hide the details of internal errors from the user.
///  - Show a description for input and provider errors.
///
///  - Return the error to the relier via redirect, as per the OAuth2 spec.
///  - Always show something to the user, even if we cannot redirect.
///
/// The large match-statement below handles all these scenario's properly, and
/// sets proper response codes for each category.
async fn handle_error(ctx: &Context, err: BrokerError) -> Response {
    let reference = err.log(Some(&ctx.app.rng)).await;

    if ctx.want_json {
        let mut res = json_response(
            &json!({
                "error": err.oauth_error_code(),
                "error_description": &format!("{}", err),
                "reference": reference,
            }),
            None,
        );
        *res.status_mut() = err.http_status_code();
        return res;
    }

    // Check if we can redirect to the RP. We must have return parameters, and the RP must not have
    // opted out from receiving errors in the redirect response.
    let can_redirect = matches!(
        ctx.return_params,
        Some(ReturnParams {
            response_errors: true,
            ..
        })
    );

    let catalog = ctx.catalog();
    match (err, can_redirect) {
        // Redirects with description.
        (err @ BrokerError::Input(_), true)
        | (err @ BrokerError::Provider(_), true)
        | (err @ BrokerError::ProviderInput(_), true) => return_to_relier(
            ctx,
            &[
                ("error", err.oauth_error_code()),
                ("error_description", &format!("{}", err)),
            ],
        ),
        // Friendly error pages for what we can't redirect.
        (err @ BrokerError::Input(_), false) => {
            let mut res = html_response(ctx.app.templates.error.render(&[
                ("error", &format!("{}", err)),
                ("intro", catalog.gettext("The request is invalid, and could not be completed.")),
                ("reason", catalog.gettext("Technical description")),
                ("explanation", catalog.gettext("This indicates an issue with the site you're trying to login to. Contact the site administrator to get the issue resolved.")),
            ]));
            *res.status_mut() = err.http_status_code();
            res
        }
        (err @ BrokerError::Provider(_), false) | (err @ BrokerError::ProviderInput(_), false) => {
            let mut res = html_response(ctx.app.templates.error.render(&[
                ("error", &format!("{}", err)),
                (
                    "intro",
                    catalog.gettext("Failed to connect with your email domain."),
                ),
                ("reason", catalog.gettext("Technical description")),
                (
                    "explanation",
                    catalog.gettext(
                        "Contact the administrator of your email domain to get the issue resolved.",
                    ),
                ),
            ]));
            *res.status_mut() = err.http_status_code();
            res
        }
        // Friendly error pages for what we will never redirect.
        (err @ BrokerError::Internal(_), _) => {
            let mut res = html_response(ctx.app.templates.error.render(&[
                ("ref", &reference.expect("internal error must have a reference")),
                ("intro", catalog.gettext("Something went wrong, and we cannot complete your request at this time.")),
                ("explanation", catalog.gettext("An internal error occurred, which has been logged with the below reference number.")),
            ]));
            *res.status_mut() = err.http_status_code();
            res
        }
        (err @ BrokerError::RateLimited, _) => {
            let mut res = html_response(ctx.app.templates.error.render(&[
                ("intro", catalog.gettext("Too many login attempts.")),
                ("explanation", catalog.gettext("We've received too many requests in a short amount of time. Please try again later.")),
            ]));
            *res.status_mut() = err.http_status_code();
            res
        }
        (err @ BrokerError::SessionExpired, _) => {
            let mut res = html_response(ctx.app.templates.error.render(&[
                ("intro", catalog.gettext("The session has expired.")),
                ("explanation", catalog.gettext("Your login attempt may have taken too long, or you tried to follow an old link. Please try again.")),
            ]));
            *res.status_mut() = err.http_status_code();
            res
        }
        // Internal status that should never bubble this far
        (BrokerError::ProviderCancelled, _) => unreachable!(),
    }
}

/// Mutate a response to set common headers.
fn set_headers<B>(res: &mut hyper::Response<B>) {
    // Specify a tight content security policy. We need to be able to POST
    // redirect anywhere, and run our own scripts.
    let csp = vec![
        "sandbox allow-scripts allow-forms",
        "default-src 'none'",
        "script-src 'self'",
        "style-src 'self'",
        "form-action *",
    ]
    .join("; ");

    res.typed_header(StrictTransportSecurity::excluding_subdomains(
        Duration::from_secs(31_536_000_u64),
    ));
    res.header(hyper::header::CONTENT_SECURITY_POLICY, csp.clone());
    res.header("x-content-security-policy", csp);
    res.header(hyper::header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_owned());
    res.header(hyper::header::X_XSS_PROTECTION, "1; mode=block".to_owned());
    res.header(hyper::header::X_FRAME_OPTIONS, "DENY".to_owned());

    // Default to disable caching completely.
    if !res.headers().contains_key(CacheControl::name()) {
        res.typed_header(CacheControl::new().with_no_cache().with_no_store());
    }
}

/// Parse a form-encoded string into a `HashMap`.
pub fn parse_form_encoded(input: &[u8]) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for (key, value) in form_urlencoded::parse(input) {
        map.insert(key.into_owned(), value.into_owned());
    }
    map
}

/// Read the request or response body up to a fixed size.
pub async fn read_body(body: &mut Body) -> Result<Bytes, BoxError> {
    let mut acc = BytesMut::new();
    while let Some(result) = body.next().await {
        let chunk = result.map_err(Box::new)?;
        if acc.len() + chunk.len() > 8096 {
            return Err(Box::new(SizeLimitExceeded));
        }
        acc.extend(chunk);
    }
    Ok(acc.freeze())
}

/// Helper function for returning a result to the Relying Party.
///
/// Takes an array of `(name, value)` parameter pairs and returns a response
/// that sends them to the RP's `redirect_uri`. The method used to return to
/// the RP depends on the `response_mode`.
pub fn return_to_relier(ctx: &Context, params: &[(&str, &str)]) -> Response {
    let &ReturnParams {
        ref redirect_uri,
        response_mode,
        ..
    } = ctx
        .return_params
        .as_ref()
        .expect("return_to_relier called without return parameters");

    match response_mode {
        // Add params as fragment parameters and redirect.
        ResponseMode::Fragment => {
            let mut redirect_uri = redirect_uri.clone();
            let fragment = redirect_uri.fragment().unwrap_or("").to_owned();
            let fragment = form_urlencoded::Serializer::for_suffix(fragment, 0)
                .extend_pairs(params)
                .finish();
            redirect_uri.set_fragment(Some(&fragment));

            let mut res = empty_response(StatusCode::SEE_OTHER);
            res.header(hyper::header::LOCATION, String::from(redirect_uri));
            res
        }
        // Render a form that submits a POST request.
        ResponseMode::FormPost => {
            let data = mustache::MapBuilder::new()
                .insert_str("redirect_uri", redirect_uri.to_string())
                .insert_vec("params", |mut builder| {
                    for &param in params {
                        builder = builder.push_map(|builder| {
                            let (name, value) = param;
                            builder.insert_str("name", name).insert_str("value", value)
                        });
                    }
                    builder
                })
                .build();

            html_response(ctx.app.templates.forward.render_data(&data))
        }
        // Add params as query parameters and redirect.
        ResponseMode::Query => {
            let mut redirect_uri = redirect_uri.clone();
            redirect_uri.query_pairs_mut().extend_pairs(params).finish();

            let mut res = empty_response(StatusCode::SEE_OTHER);
            res.header(hyper::header::LOCATION, String::from(redirect_uri));
            res
        }
    }
}

/// Helper function for returning a response with JSON data.
///
/// Serializes the argument value to JSON and returns a HTTP 200 response
/// code with the serialized JSON as the body.
pub fn json_response(obj: &serde_json::Value, max_age: Option<Duration>) -> Response {
    let body = serde_json::to_string_pretty(&obj).expect("unable to coerce JSON Value into string");
    let mut res = Response::new(Body::from(body));
    res.typed_header(ContentType::json());
    if let Some(max_age) = max_age {
        res.typed_header(CacheControl::new().with_public().with_max_age(max_age));
    }
    res
}

/// Create a response with an HTML body.
pub fn html_response(html: String) -> Response {
    let mut res = Response::new(Body::from(html));
    res.typed_header(ContentType::html());
    res
}

/// Create a response with an empty body and a specific status code.
pub fn empty_response(status: StatusCode) -> Response {
    let mut res = Response::new(Body::empty());
    *res.status_mut() = status;
    res
}

#[cfg(test)]
mod tests {
    use super::set_headers;
    use http::Response;

    #[test]
    fn sets_expected_headers() {
        let mut res = Response::new(());
        set_headers(&mut res);

        let headers = res.headers();
        assert!(headers.contains_key("Strict-Transport-Security"));
        assert!(headers.contains_key("Content-Security-Policy"));
        assert!(headers.contains_key("X-Content-Security-Policy"));
        assert!(headers.contains_key("X-Content-Type-Options"));
        assert!(headers.contains_key("X-XSS-Protection"));
        assert!(headers.contains_key("X-Frame-Options"));
        assert!(headers.contains_key("Cache-Control"));
    }
}
