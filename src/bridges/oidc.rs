use crate::agents::FetchUrlCached;
use crate::bridges::{complete_auth, BridgeData};
use crate::crypto::{self, SigningAlgorithm};
use crate::email_address::EmailAddress;
use crate::error::BrokerError;
use crate::utils::{http::ResponseExt, unix_timestamp};
use crate::web::{empty_response, json_response, Context, HandlerResult};
use crate::webfinger::{Link, Relation};
use crate::{metrics, validation};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use url::Url;

/// The origin of the Google identity provider.
pub const GOOGLE_IDP_ORIGIN: &str = "https://accounts.google.com";
/// The leeway allowed when verifying iat & exp claims, in seconds.
pub const LEEWAY: u64 = 30;

/// Data we store in the session.
#[derive(Clone, Serialize, Deserialize)]
pub struct OidcBridgeData {
    pub link: Link,
    pub origin: String,
    pub client_id: String,
    pub nonce: String,
    pub signing_alg: SigningAlgorithm,
}

/// OpenID Connect configuration document.
#[derive(Deserialize)]
struct ProviderConfig {
    authorization_endpoint: Url,
    jwks_uri: Url,
    #[serde(default = "default_response_modes_supported")]
    response_modes_supported: Vec<String>,
    #[serde(default = "default_id_token_signing_alg_values_supported")]
    id_token_signing_alg_values_supported: Vec<String>,
    // NOTE: This field is non-standard.
    #[serde(default)]
    accepts_id_token_signing_alg_query_param: bool,
}

fn default_response_modes_supported() -> Vec<String> {
    vec!["fragment".to_owned()]
}

fn default_id_token_signing_alg_values_supported() -> Vec<String> {
    vec!["RS256".to_owned()]
}

/// OpenID Connect key set document.
#[derive(Deserialize)]
struct ProviderKeys {
    #[serde(default)]
    keys: Vec<ProviderKey>,
}

#[derive(Deserialize)]
pub struct ProviderKey {
    #[serde(default)]
    pub alg: String,
    #[serde(default)]
    pub crv: String,
    #[serde(rename = "use")]
    #[serde(default)]
    pub use_: String,
    #[serde(default)]
    pub kid: String,
    #[serde(default)]
    pub n: String,
    #[serde(default)]
    pub e: String,
    #[serde(default)]
    pub x: String,
}

/// Provide authentication using OpenID Connect.
///
/// Redirect the user agent to the provider authorization endpoint, which we discover by reading
/// the providers configuration document. Included in the request is a nonce which we can later use
/// to definitively match the callback to this request.
///
/// This function handles both Portier providers, which works without registration, as well as
/// the Google provider, for which we have a preregistered `client_id`.
pub async fn auth(ctx: &mut Context, email_addr: &EmailAddress, link: &Link) -> HandlerResult {
    // Generate a nonce for the provider.
    let provider_nonce = crypto::nonce(&ctx.app.rng).await;

    // Determine the parameters to use, based on the webfinger link.
    let provider_origin = validation::parse_oidc_href(&link.href).ok_or_else(|| {
        BrokerError::Provider(format!("invalid href (validation failed): {}", link.href))
    })?;
    let mut bridge_data = match link.rel {
        Relation::Portier => {
            metrics::AUTH_OIDC_REQUESTS_PORTIER.inc();
            #[cfg(not(feature = "insecure"))]
            {
                if link.href.scheme() != "https" {
                    return Err(BrokerError::Provider(format!(
                        "invalid href (not HTTPS): {}",
                        link.href
                    )));
                }
            }
            OidcBridgeData {
                link: link.clone(),
                origin: provider_origin,
                client_id: ctx.app.public_url.clone(),
                nonce: provider_nonce,
                signing_alg: SigningAlgorithm::Rs256,
            }
        }
        // Delegate to the OpenID Connect bridge for Google, if configured.
        Relation::Google => {
            metrics::AUTH_OIDC_REQUESTS_GOOGLE.inc();
            let client_id = ctx
                .app
                .google_client_id
                .as_ref()
                .ok_or(BrokerError::ProviderCancelled)?;
            if provider_origin != GOOGLE_IDP_ORIGIN {
                return Err(BrokerError::Provider(format!(
                    "invalid href: Google provider only supports {}",
                    GOOGLE_IDP_ORIGIN
                )));
            }
            OidcBridgeData {
                link: link.clone(),
                origin: provider_origin,
                client_id: client_id.clone(),
                nonce: provider_nonce,
                signing_alg: SigningAlgorithm::Rs256,
            }
        }
    };

    // Retrieve the provider's configuration.
    let (
        ProviderConfig {
            authorization_endpoint: mut auth_url,
            response_modes_supported: response_modes,
            id_token_signing_alg_values_supported: signing_algs,
            accepts_id_token_signing_alg_query_param: accepts_signing_alg,
            ..
        },
        key_set,
    ) = fetch_config(ctx, &bridge_data).await?;

    {
        // Create the URL to redirect to.
        let mut query = auth_url.query_pairs_mut();
        query.extend_pairs(&[
            ("login_hint", email_addr.as_str()),
            ("scope", "openid email"),
            ("nonce", &bridge_data.nonce),
            ("state", &ctx.session_id),
            ("response_type", "id_token"),
            ("client_id", &bridge_data.client_id),
            ("redirect_uri", &format!("{}/callback", &ctx.app.public_url)),
        ]);

        // Prefer `form_post` response mode, otherwise use `fragment`.
        if response_modes.iter().any(|mode| mode == "form_post") {
            query.append_pair("response_mode", "form_post");
        } else if !response_modes.iter().any(|mode| mode == "fragment") {
            return Err(BrokerError::Provider(format!(
                "neither form_post nor fragment response modes supported by {}'s IdP ",
                email_addr.domain()
            )));
        }

        // NOTE: This query parameter is non-standard.
        // Prefer `Ed25519`, but there is no standard way to select it, so we introduce extra
        // fields, and take care we don't accidentally break the protocol. On top of this,
        // `alg=EdDSA` could also mean Ed448, so we inspect the key set to make sure there are only
        // Ed25519 keys among EdDSA keys.
        if accepts_signing_alg && signing_algs.iter().any(|s| s.as_str() == "EdDSA") {
            let mut found_ed25519 = false;
            let mut found_other_ed_dsa = false;
            for key in &key_set.keys {
                if key.use_ == "sig" && key.alg == "EdDSA" {
                    if key.crv == "Ed25519" {
                        found_ed25519 = true;
                    } else {
                        found_other_ed_dsa = true;
                        break;
                    }
                }
            }
            if found_ed25519 && !found_other_ed_dsa {
                bridge_data.signing_alg = SigningAlgorithm::EdDsa;
                query.append_pair("id_token_signing_alg", "EdDSA");
            }
        }

        query.finish();
    }

    // Save session data, committing the session to this provider.
    // If this fails, another auth mechanism has already claimed the session.
    if !ctx.save_session(BridgeData::Oidc(bridge_data)).await? {
        return Err(BrokerError::ProviderCancelled);
    }

    if ctx.want_json {
        Ok(json_response(
            &json!({
                "result": "redirect_to_provider",
                "url": auth_url.as_str(),
            }),
            None,
        ))
    } else {
        let mut res = empty_response(StatusCode::SEE_OTHER);
        res.header(hyper::header::LOCATION, auth_url.as_str());
        Ok(res)
    }
}

/// Request handler for OpenID Connect callbacks.
///
/// Match the returned email address and nonce against our session data, then extract the identity
/// token returned by the provider and verify it. Return an identity token for the relying party if
/// successful, or an error message otherwise.
pub async fn callback(ctx: &mut Context) -> HandlerResult {
    let mut params = ctx.form_params();
    let session_id = try_get_provider_param!(params, "state");
    let id_token = try_get_provider_param!(params, "id_token");

    #[allow(clippy::match_wildcard_for_single_variants)]
    let bridge_data = match ctx.load_session(&session_id).await? {
        BridgeData::Oidc(bridge_data) => bridge_data,
        _ => return Err(BrokerError::ProviderInput("invalid session".to_owned())),
    };

    // Retrieve the provider's configuration.
    let (_, key_set) = fetch_config(ctx, &bridge_data).await?;

    // Verify the signature.
    let jwt_payload = crypto::verify_jws(&id_token, &key_set.keys, bridge_data.signing_alg)
        .map_err(|err| {
            BrokerError::ProviderInput(format!(
                "could not verify the token received from {}: {}",
                bridge_data.origin, err
            ))
        })?;

    let data = ctx.session_data.as_ref().expect("session vanished");

    // Extract the token claims.
    let descr = format!("{}'s token payload", data.email_addr.domain());
    let iss = try_get_token_field!(jwt_payload, "iss", descr);
    let aud = try_get_token_field!(jwt_payload, "aud", descr);
    let email = try_get_token_field!(jwt_payload, "email", descr);
    let iat = try_get_token_field!(jwt_payload, "iat", Value::as_u64, descr);
    let exp = try_get_token_field!(jwt_payload, "exp", Value::as_u64, descr);
    let nonce = try_get_token_field!(jwt_payload, "nonce", descr);

    // Verify the token claims.
    check_token_field!(iss == bridge_data.origin, "iss", descr);
    check_token_field!(aud == bridge_data.client_id, "aud", descr);
    check_token_field!(nonce == bridge_data.nonce, "nonce", descr);

    let now = unix_timestamp();
    let exp = exp.checked_add(LEEWAY).unwrap_or(u64::min_value());
    let iat = iat.checked_sub(LEEWAY).unwrap_or(u64::max_value());
    check_token_field!(now < exp, "exp", descr);
    check_token_field!(iat <= now, "iat", descr);

    match bridge_data.link.rel {
        Relation::Portier => {
            // `email` should match the normalized email, as we sent it to the IdP.
            check_token_field!(email == data.email_addr.as_str(), "email", descr);
            // `email_original` should not be necessary for Broker -> IdP, but verify it any way.
            if let Some(email_original) = jwt_payload.get("email_original").and_then(Value::as_str)
            {
                check_token_field!(
                    email_original == data.email_addr.as_str(),
                    "email_original",
                    descr
                );
            }
        }
        Relation::Google => {
            // Check `email` after additional Google-specific normalization.
            let email_addr: EmailAddress = email.parse().map_err(|err| {
                BrokerError::ProviderInput(format!("failed to parse email in {}: {}", descr, err))
            })?;
            let google_email_addr = email_addr.normalize_google();
            let expected = data.email_addr.normalize_google();
            check_token_field!(google_email_addr == expected, "email", descr);
        }
    }

    // Everything is okay. Build a new identity token and send it to the relying party.
    metrics::AUTH_OIDC_COMPLETED.inc();
    complete_auth(ctx).await
}

// Retrieve and verify the provider's configuration.
async fn fetch_config(
    ctx: &mut Context,
    bridge_data: &OidcBridgeData,
) -> Result<(ProviderConfig, ProviderKeys), BrokerError> {
    let config_url = format!("{}/.well-known/openid-configuration", bridge_data.origin)
        .parse()
        .expect("could not build the OpenID Connect configuration URL");

    let provider_config = ctx
        .app
        .store
        .send(FetchUrlCached {
            url: config_url,
            metric: &*metrics::AUTH_OIDC_FETCH_CONFIG_DURATION,
        })
        .await
        .map_err(|e| {
            BrokerError::Provider(format!(
                "could not fetch {}'s configuration: {}",
                bridge_data.origin, e
            ))
        })?;
    let provider_config: ProviderConfig = serde_json::from_str(&provider_config).map_err(|e| {
        BrokerError::Provider(format!(
            "could not parse {}'s configuration: {}",
            bridge_data.origin, e
        ))
    })?;

    #[cfg(not(feature = "insecure"))]
    {
        if provider_config.authorization_endpoint.scheme() != "https" {
            return Err(BrokerError::Provider(format!(
                "{}'s authorization_endpoint is not HTTPS",
                bridge_data.origin
            )));
        }
        if provider_config.jwks_uri.scheme() != "https" {
            return Err(BrokerError::Provider(format!(
                "{}'s jwks_uri is not HTTPS",
                bridge_data.origin
            )));
        }
    }

    // Grab the keys from the provider.
    let key_set = ctx
        .app
        .store
        .send(FetchUrlCached {
            url: provider_config.jwks_uri.clone(),
            metric: &*metrics::AUTH_OIDC_FETCH_JWKS_DURATION,
        })
        .await
        .map_err(|e| {
            BrokerError::Provider(format!(
                "could not fetch {}'s keys: {}",
                bridge_data.origin, e
            ))
        })?;
    let key_set: ProviderKeys = serde_json::from_str(&key_set).map_err(|e| {
        BrokerError::Provider(format!(
            "could not parse{}'s keys: {}",
            bridge_data.origin, e
        ))
    })?;

    Ok((provider_config, key_set))
}
