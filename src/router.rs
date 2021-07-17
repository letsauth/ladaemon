use crate::web::{empty_response, Context, HandlerResult};
use crate::{bridges, handlers};
use http::{Method, StatusCode};

/// Route the request, returning a handler
pub async fn router(ctx: &mut Context) -> HandlerResult {
    match (&ctx.method, ctx.uri.path()) {
        // Relying party endpoints
        (&Method::GET, "/.well-known/openid-configuration") => handlers::auth::discovery(ctx).await,
        (&Method::GET, "/keys.json") => handlers::auth::key_set(ctx).await,
        (&Method::GET, "/auth") | (&Method::POST, "/auth") => handlers::auth::auth(ctx).await,
        (&Method::POST, "/normalize") => handlers::normalize::normalize(ctx).await,
        (&Method::POST, "/token") => handlers::token::token(ctx).await,

        // OpenID Connect endpoints
        // For providers that don't support `response_mode=form_post`, we capture the fragment
        // parameters in javascript and emulate the POST request.
        (&Method::GET, "/callback") => handlers::rewrite_to_post::rewrite_to_post(ctx).await,
        (&Method::POST, "/callback") => bridges::oidc::callback(ctx).await,

        // Email loop endpoints
        // To thwart automated scanners that follow email links, we capture the query parameter in
        // javascripts and rewrite to a POST request.
        (&Method::GET, "/confirm") => handlers::rewrite_to_post::rewrite_to_post(ctx).await,
        (&Method::POST, "/confirm") => bridges::email::confirmation(ctx).await,

        // Misc endpoints
        (&Method::GET, "/") => handlers::pages::index(ctx).await,
        (&Method::GET, "/ver.txt") => handlers::pages::version(ctx).await,
        (&Method::GET, "/metrics") => handlers::pages::metrics(ctx).await,

        // Lastly, fall back to trying to serve static files out of ./res/
        (&Method::GET, _) | (&Method::HEAD, _) => handlers::pages::static_(ctx).await,

        _ => Ok(empty_response(StatusCode::BAD_REQUEST)),
    }
}
