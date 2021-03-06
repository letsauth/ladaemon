use crate::email_address::EmailAddress;
use crate::utils::agent::Message;

#[cfg(feature = "lettre_email")]
use ::{lettre::SendableEmail, lettre_email::EmailBuilder};

/// Message requesting a mail be sent.
///
/// Handlers should also time the request using `metrics::AUTH_EMAIL_SEND_DURATION`, measuring the
/// narrowest possible section of code that makes the external call.
pub struct SendMail {
    pub to: EmailAddress,
    pub subject: String,
    pub html_body: String,
    pub text_body: String,
}
impl Message for SendMail {
    type Reply = bool;
}

#[cfg(feature = "lettre_email")]
impl SendMail {
    /// Convert the message to a lettre `SendableEmail`.
    pub fn into_lettre_email(self, from_address: &EmailAddress, from_name: &str) -> SendableEmail {
        EmailBuilder::new()
            .from((from_address.as_str(), from_name))
            .to(self.to.into_string())
            .subject(self.subject)
            .alternative(self.html_body, self.text_body)
            .build()
            .expect("Could not build mail")
            .into()
    }
}

#[cfg(feature = "lettre_smtp")]
pub mod lettre_smtp;
#[cfg(feature = "lettre_smtp")]
pub use self::lettre_smtp::SmtpMailer;

#[cfg(feature = "lettre_sendmail")]
pub mod lettre_sendmail;
#[cfg(feature = "lettre_sendmail")]
pub use self::lettre_sendmail::SendmailMailer;

#[cfg(feature = "postmark")]
pub mod postmark;
#[cfg(feature = "postmark")]
pub use self::postmark::PostmarkMailer;

#[cfg(feature = "mailgun")]
pub mod mailgun;
#[cfg(feature = "mailgun")]
pub use self::mailgun::MailgunMailer;
