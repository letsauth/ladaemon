use crate::agents::{GetPublicJwks, IncrAndTestLimits};
use crate::config::LimitInput;
use crate::crypto::SigningAlgorithm;
use crate::email_address::EmailAddress;
use crate::error::BrokerError;
use crate::utils::DomainValidationError;
use crate::validation::parse_redirect_uri;
use crate::web::{
    html_response, json_response, Context, HandlerResult, ResponseType, ReturnParams,
};
use crate::webfinger::{self, Relation};
use crate::{bridges, metrics};
use http::Method;
use log::info;
use serde_json::{from_value, json, Value};
use std::collections::HashSet;
use std::time::Duration;

/// Request handler to return the OpenID Discovery document.
///
/// Most of this is hard-coded for now, although the URLs are constructed by
/// using the base URL as configured in the `public_url` configuration value.
pub async fn discovery(ctx: &mut Context) -> HandlerResult {
    let obj = json!({
        "issuer": ctx.app.public_url,
        "authorization_endpoint": format!("{}/auth", ctx.app.public_url),
        "token_endpoint": format!("{}/token", ctx.app.public_url),
        "token_endpoint_auth_methods_supported": ["client_secret_basic"],
        "jwks_uri": format!("{}/keys.json", ctx.app.public_url),
        "scopes_supported": vec!["openid", "email"],
        "claims_supported": vec!["iss", "aud", "exp", "iat", "email"],
        "response_types_supported": vec!["id_token", "code"],
        "response_modes_supported": vec!["form_post", "fragment", "query"],
        "grant_types_supported": vec!["implicit", "authorization_code"],
        "subject_types_supported": vec!["public"],
        "id_token_signing_alg_values_supported": &ctx.app.signing_algs,
        // NOTE: This field is non-standard.
        "accepts_id_token_signing_alg_query_param": true,
    });
    Ok(json_response(&obj, Some(ctx.app.discovery_ttl)))
}

/// Request handler for the JSON Web Key Set document.
///
/// Respond with the JWK key set containing all of the configured keys.
///
/// Relying Parties will need to fetch this data to be able to verify identity
/// tokens issued by this daemon instance.
pub async fn key_set(ctx: &mut Context) -> HandlerResult {
    let obj = json!({
        "keys": ctx.app.key_manager.send(GetPublicJwks).await
    });
    Ok(json_response(&obj, Some(ctx.app.keys_ttl)))
}

/// Request handler for authentication requests from the RP.
///
/// Calls the `oidc::request()` function if the provided email address's
/// domain matches one of the configured famous providers. Otherwise, calls the
/// `email::request()` function to allow authentication through the email loop.
pub async fn auth(ctx: &mut Context) -> HandlerResult {
    let mut params = match ctx.method {
        Method::GET => ctx.query_params(),
        Method::POST => ctx.form_params(),
        _ => unreachable!(),
    };

    let original_params = params.clone();

    let redirect_uri = try_get_input_param!(params, "redirect_uri");
    let client_id = try_get_input_param!(params, "client_id");
    let response_type = try_get_input_param!(params, "response_type");
    let response_errors = try_get_input_param!(params, "response_errors", "true".to_owned());
    let state = try_get_input_param!(params, "state", "".to_owned());

    // Parse response_type and response_mode by wrapping them in a JSON Value.
    // This has minimal overhead, and saves us a separate implementation.
    let response_type: ResponseType = from_value(Value::String(response_type)).map_err(|_err| {
        BrokerError::Input("unsupported response_type, must be id_token or code".to_owned())
    })?;

    let response_mode = try_get_input_param!(
        params,
        "response_mode",
        response_type.default_response_mode().as_str().to_owned()
    );
    let response_mode = from_value(Value::String(response_mode)).map_err(|_err| {
        BrokerError::Input(
            "unsupported response_mode, must be fragment, form_post or query".to_owned(),
        )
    })?;

    let redirect_uri = parse_redirect_uri(&redirect_uri, "redirect_uri")
        .map_err(|e| BrokerError::Input(format!("{}", e)))?;

    if client_id != redirect_uri.origin().ascii_serialization() {
        return Err(BrokerError::Input(
            "the client_id must be the origin of the redirect_uri".to_owned(),
        ));
    }

    // NOTE: This query parameter is non-standard.
    let response_errors = response_errors
        .parse::<bool>()
        .map_err(|_err| BrokerError::Input("response_errors must be true or false".to_owned()))?;

    // Per the OAuth2 spec, we may redirect to the RP once we have validated client_id and
    // redirect_uri. In our case, this means we make redirect_uri available to error handling.
    let redirect_uri_ = redirect_uri.clone();
    ctx.return_params = Some(ReturnParams {
        redirect_uri,
        response_mode,
        response_errors,
        state,
    });

    if let Some(ref whitelist) = ctx.app.allowed_origins {
        if !whitelist.contains(&client_id) {
            return Err(BrokerError::Input(
                "the origin is not whitelisted".to_owned(),
            ));
        }
    }

    let nonce = try_get_input_param!(params, "nonce");

    let scope = try_get_input_param!(params, "scope");
    let mut scope_set: HashSet<&str> = scope.split(' ').collect();
    if !scope_set.remove("openid") {
        return Err(BrokerError::Input(
            "unsupported scope, must contain 'openid'".to_owned(),
        ));
    }

    // NOTE: This query parameter is non-standard.
    let signing_alg = try_get_input_param!(params, "id_token_signing_alg", "RS256".to_owned());
    let signing_alg = signing_alg
        .parse()
        .ok()
        .filter(|alg| ctx.app.signing_algs.contains(alg))
        .ok_or_else(|| {
            BrokerError::Input(format!(
                "unsupported id_token_signing_alg, must be one of: {}",
                SigningAlgorithm::format_list(&*ctx.app.signing_algs)
            ))
        })?;

    let login_hint = try_get_input_param!(params, "login_hint", "".to_string());
    if login_hint.is_empty() && !ctx.want_json {
        let display_origin = redirect_uri_.origin().unicode_serialization();

        let catalog = ctx.catalog();
        let data = mustache::MapBuilder::new()
            .insert_str("display_origin", display_origin)
            .insert_str("title", catalog.gettext("Finish logging in to"))
            .insert_str(
                "explanation",
                catalog.gettext("Login with your email address."),
            )
            .insert_str(
                "use",
                catalog.gettext("Please specify the email you wish to use to login with"),
            )
            .insert_vec("params", |mut builder| {
                for param in &original_params {
                    builder = builder.push_map(|builder| {
                        let (name, value) = param;
                        builder.insert_str("name", name).insert_str("value", value)
                    });
                }
                builder
            })
            .build();

        return Ok(html_response(
            ctx.app.templates.login_hint.render_data(&data),
        ));
    }

    // Verify and normalize the email.
    let email_addr = login_hint.parse::<EmailAddress>().map_err(|err| {
        BrokerError::Input(format!("login_hint is not a valid email address: {}", err))
    })?;

    // Enforce rate limits.
    match ctx
        .app
        .store
        .send(IncrAndTestLimits {
            input: LimitInput {
                email_addr: email_addr.clone(),
                origin: client_id.clone(),
                ip: ctx.ip,
            },
        })
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            metrics::AUTH_LIMITED.inc();
            return Err(BrokerError::RateLimited);
        }
        Err(e) => {
            return Err(BrokerError::Internal(format!(
                "could not test rate limit: {}",
                e
            )))
        }
    }

    // At this point, we've done all the local input verification.
    metrics::AUTH_REQUESTS.inc();

    // Verify the email domain.
    if let Err(err) = ctx.app.domain_validator.validate(email_addr.domain()).await {
        err.apply_metric();
        return Err(BrokerError::Input(
            match err {
                DomainValidationError::Blocked => "the domain of the email address is blocked",
                _ => "the domain of the email address is invalid",
            }
            .to_owned(),
        ));
    }

    // Create the session with common data, but do not yet save it.
    ctx.start_session(
        &client_id,
        &login_hint,
        &email_addr,
        response_type,
        &nonce,
        signing_alg,
        ctx.ip,
    )
    .await;

    // Discover the authentication endpoints based on the email domain.
    let discovery_future = async {
        let links = webfinger::query(&ctx.app, &email_addr).await?;

        // Try to authenticate with the first provider.
        // TODO: Queue discovery of links and process in order, with individual timeouts.
        let link = links.first().ok_or(BrokerError::ProviderCancelled)?;
        match link.rel {
            // Portier and Google providers share an implementation
            Relation::Portier | Relation::Google => {
                bridges::oidc::auth(ctx, &email_addr, link).await
            }
        }
    };

    // Apply a timeout to discovery.
    match tokio::time::timeout(Duration::from_secs(5), discovery_future).await {
        Err(_) => {
            // Timeout causes fall back to email loop auth.
            info!("discovery timed out for {}", email_addr);

            // TODO: We used to (before async) continue discovery in the background, using shared
            // access to Context through RefCell. We could bring that back by decoupling auth
            // mechanisms from Context.
            //
            // (The original idea was also for auth mechanisms to have a 'commit' action, to
            // indicate a side-effect is about the happen. From this side, it'd effectively abort
            // the timeout and bubble all errors. An intermediate AuthContext could provide this.)
            /*
            tokio::spawn(async {
                if let Err(e) = f.await {
                    e.log();
                }
            });
            */
        }
        Ok(Ok(v)) => {
            // Discovery succeeded, simply return the response.
            return Ok(v);
        }
        Ok(Err(e @ BrokerError::Provider(_))) | Ok(Err(e @ BrokerError::ProviderCancelled)) => {
            // Provider errors cause fallback to email loop auth.
            e.log(None).await;
        }
        Ok(Err(e)) => {
            // Other errors during discovery are bubbled.
            return Err(e);
        }
    }

    // Fall back to email loop auth.
    bridges::email::auth(ctx, email_addr).await
}
