use crate::agents::mailer::SendMail;
use crate::bridges::{complete_auth, BridgeData};
use crate::crypto::random_zbase32;
use crate::email_address::EmailAddress;
use crate::error::BrokerError;
use crate::metrics;
use crate::web::{html_response, json_response, Context, HandlerResult};
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use serde::{Deserialize, Serialize};
use serde_json::json;

const QUERY_ESCAPE: &AsciiSet = &CONTROLS.add(b' ').add(b'"').add(b'#').add(b'<').add(b'>');

/// Data we store in the session.
#[derive(Clone, Serialize, Deserialize)]
pub struct EmailBridgeData {
    pub code: String,
}

/// Provide authentication through an email loop.
///
/// If the email address' host does not support any native form of authentication, create a
/// randomly-generated one-time pad. Then, send an email containing a link with the secret.
/// Clicking the link will trigger the `confirmation` handler, returning an authentication result
/// to the relying party.
///
/// A form is rendered as an alternative way to confirm, without following the link. Submitting the
/// form results in the same callback as the email link.
pub async fn auth(ctx: &mut Context, email_addr: EmailAddress) -> HandlerResult {
    metrics::AUTH_EMAIL_REQUESTS.inc();

    // Generate a 12-character one-time pad.
    let code = random_zbase32(12, &ctx.app.rng).await;
    // For display, we split it in two groups of 6.
    let code_fmt = [&code[0..6], &code[6..12]].join(" ");

    // Generate the URL used to verify email address ownership.
    let href = format!(
        "{}/confirm?session={}&code={}",
        ctx.app.public_url,
        utf8_percent_encode(&ctx.session_id, QUERY_ESCAPE),
        utf8_percent_encode(&code, QUERY_ESCAPE)
    );

    let display_origin = ctx
        .return_params
        .as_ref()
        .expect("email::request called without redirect_uri set")
        .redirect_uri
        .origin()
        .unicode_serialization();

    let catalog = ctx.catalog();
    let subject = format!(
        "{} {}",
        catalog.gettext("Finish logging in to"),
        display_origin
    );
    let params = &[
        ("display_origin", display_origin.as_str()),
        ("code", &code_fmt),
        ("link", &href),
        ("title", catalog.gettext("Finish logging in to")),
        ("explanation", catalog.gettext("You received this email so that we may confirm your email address and finish your login to:")),
        ("click", catalog.gettext("Click here to login")),
        ("alternate", catalog.gettext("Alternatively, enter the following code on the login page:")),
    ];
    let html_body = ctx.app.templates.email_html.render(params);
    let text_body = ctx.app.templates.email_text.render(params);

    // Store the code in the session for use in the verify handler. We should never fail to claim
    // the session, because we only get here after all other options have failed.
    if !ctx
        .save_session(BridgeData::Email(EmailBridgeData { code }))
        .await?
    {
        return Err(BrokerError::Internal(
            "email fallback failed to claim session".to_owned(),
        ));
    }

    // Send the mail.
    let ok = ctx
        .app
        .mailer
        .send(SendMail {
            to: email_addr,
            subject,
            html_body,
            text_body,
        })
        .await;
    if !ok {
        return Err(BrokerError::Internal("Failed to send mail".to_owned()));
    }

    // Render a form for the user.
    if ctx.want_json {
        Ok(json_response(
            &json!({
                "result": "verification_code_sent",
                "session": &ctx.session_id,
            }),
            None,
        ))
    } else {
        let catalog = ctx.catalog();
        Ok(html_response(ctx.app.templates.confirm_email.render(&[
            ("display_origin", display_origin.as_str()),
            ("session_id", &ctx.session_id),
            ("title", catalog.gettext("Confirm your address")),
            (
                "explanation",
                catalog.gettext("We've sent you an email to confirm your address."),
            ),
            (
                "use",
                catalog.gettext("Use the link in that email to login to"),
            ),
            (
                "alternate",
                catalog.gettext(
                    "Alternatively, enter the code from the email to continue in this browser tab:",
                ),
            ),
        ])))
    }
}

/// Request handler for one-time pad email loop confirmation.
///
/// Retrieves the session based session ID and the expected one-time pad. Verifies the code and
/// returns the resulting token to the relying party.
pub async fn confirmation(ctx: &mut Context) -> HandlerResult {
    let mut params = ctx.form_params();
    let session_id = try_get_provider_param!(params, "session");
    let code = try_get_provider_param!(params, "code")
        .replace(char::is_whitespace, "")
        .to_lowercase();

    #[allow(clippy::match_wildcard_for_single_variants)]
    let bridge_data = match ctx.load_session(&session_id).await? {
        BridgeData::Email(bridge_data) => bridge_data,
        _ => return Err(BrokerError::ProviderInput("invalid session".to_owned())),
    };

    if code != bridge_data.code {
        metrics::AUTH_EMAIL_CODE_INCORRECT.inc();
        return Err(BrokerError::ProviderInput("incorrect code".to_owned()));
    }

    metrics::AUTH_EMAIL_COMPLETED.inc();
    complete_auth(ctx).await
}
