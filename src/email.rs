extern crate rand;
extern crate futures;

use emailaddress::EmailAddress;
use iron::Url;
use self::futures::*;
use super::error::{BrokerError, BrokerResult};
use super::lettre::email::EmailBuilder;
use super::lettre::transport::EmailTransport;
use super::lettre::transport::smtp::SmtpTransportBuilder;
use super::{Config, create_jwt};
use super::crypto::session_id;
use std::collections::HashMap;
use std::iter::Iterator;
use url::percent_encoding::{utf8_percent_encode, QUERY_ENCODE_SET};


/// Characters eligible for inclusion in the email loop one-time pad.
///
/// Currently includes all numbers, lower- and upper-case ASCII letters,
/// except those that could potentially cause confusion when reading back.
/// (That is, '1', '5', '8', '0', 'b', 'i', 'l', 'o', 's', 'u', 'B', 'D', 'I'
/// and 'O'.)
const CODE_CHARS: &'static [char] = &[
    '2', '3', '4', '6', '7', '9', 'a', 'c', 'd', 'e', 'f', 'g', 'h', 'j', 'k',
    'm', 'n', 'p', 'q', 'r', 't', 'v', 'w', 'x', 'y', 'z', 'A', 'C', 'E', 'F',
    'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
    'X', 'Y', 'Z',
];


/// Helper method to provide authentication through an email loop.
///
/// If the email address' host does not support any native form of
/// authentication, create a randomly-generated one-time pad. Then, send
/// an email containing a link with the secret. Clicking the link will trigger
/// the `ConfirmHandler`, returning an authentication result to the RP.
///
/// Returns the session ID, so a form can be rendered as an alternative way
/// to confirm, without following the link.
pub fn request(app: &Config, email_addr: EmailAddress, client_id: &str, nonce: &str, redirect_uri: &Url)
               -> BrokerResult<String> {

    // Before trying to mail, see if there are MX records.
    // TODO: Figure out a way to not block other threads.
    {
        let domain = &email_addr.domain;
        try!(app.dns.lock().unwrap().query_mx(domain).wait()
            .map_err(|_| BrokerError::Input(format!("Could not find any mailservers for {}", domain))));
    }

    // Generate a 6-character one-time pad.
    let chars: String = (0..6).map(|_| CODE_CHARS[rand::random::<usize>() % CODE_CHARS.len()]).collect();

    // Store data for this request in Redis, to reference when user uses
    // the generated link.
    let session = session_id(&email_addr, client_id);
    try!(app.store.store_session(&session, &[
        ("type", "email"),
        ("email", &email_addr.to_string()),
        ("client_id", client_id),
        ("nonce", nonce),
        ("code", &chars),
        ("redirect", &redirect_uri.to_string()),
    ]));

    // Generate the URL used to verify email address ownership.
    let href = format!("{}/confirm?session={}&code={}",
                       app.public_url,
                       utf8_percent_encode(&session, QUERY_ENCODE_SET),
                       utf8_percent_encode(&chars, QUERY_ENCODE_SET));

    // Generate a simple email and send it through the SMTP server.
    // We can unwrap here, because the possible errors cannot happen here.
    let params = &[
        ("client_id", client_id),
        ("code", &chars),
        ("link", &href),
    ];
    let email = EmailBuilder::new()
        .to(email_addr.to_string().as_str())
        .from((&*app.from_address, &*app.from_name))
        .alternative(&app.templates.email_html.render(params),
                     &app.templates.email_text.render(params))
        .subject(&format!("Finish logging in to {}", client_id))
        .build().unwrap();
    let mut builder = try!(SmtpTransportBuilder::new(app.smtp_server.as_str()));
    if let (&Some(ref username), &Some(ref password)) = (&app.smtp_username, &app.smtp_password) {
        builder = builder.credentials(username, password);
    }
    let mut mailer = builder.build();
    try!(mailer.send(email));
    mailer.close();
    Ok(session)

}

/// Helper function for verification of one-time pad sent through email.
///
/// Checks the one-time pad against the stored session data. If a match,
/// returns the Identity Token; otherwise, returns an error message.
pub fn verify(app: &Config, stored: &HashMap<String, String>, code: &str)
              -> BrokerResult<(String, String)> {

    if code != &stored["code"] {
        return Err(BrokerError::Input("incorrect code".to_string()));
    }

    let email = &stored["email"];
    let client_id = &stored["client_id"];
    let nonce = &stored["nonce"];
    let id_token = create_jwt(app, email, client_id, nonce);
    let redirect = &stored["redirect"];
    Ok((id_token, redirect.to_string()))

}
