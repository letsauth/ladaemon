extern crate serde;
extern crate toml;

use std;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;

use super::{crypto, store, mustache};

include!(concat!(env!("OUT_DIR"), "/serde_types.rs"));


/// Union of all possible error types seen while parsing.
#[derive(Debug)]
pub enum ConfigError {
    Custom(String),
    Io(std::io::Error),
    Store(&'static str),
}

macro_rules! from_error {
    ( $orig:ty, $enum_type:ident ) => {
        impl From<$orig> for ConfigError {
            fn from(err: $orig) -> ConfigError {
                ConfigError::$enum_type(err)
            }
        }
    }
}

from_error!(std::io::Error, Io);
from_error!(&'static str, Store);


// Newtype so we can implement helpers for templates.
#[derive(Clone)]
pub struct Template(mustache::Template);


impl Template {
    pub fn render(&self, params: &[(&str, &str)]) -> String {
        let mut builder = mustache::MapBuilder::new();
        for &param in params {
            let (ref key, ref value) = param;
            builder = builder.insert_str(key, value);
        }
        self.render_data(&builder.build())
    }

    pub fn render_data(&self, data: &mustache::Data) -> String {
        let mut out: Vec<u8> = Vec::new();
        self.0.render_data(&mut out, data);
        String::from_utf8(out).unwrap()
    }
}


// Contains all templates we use in compiled form.
pub struct Templates {
    /// Page displayed when the confirmation email was sent.
    pub confirm_email: Template,
    /// HTML formatted email containing the one-type pad.
    pub email_html: Template,
    /// Plain text email containing the one-type pad.
    pub email_text: Template,
    /// The error page template.
    pub error: Template,
    /// A dummy form used to redirect back to the RP with a POST request.
    pub forward: Template,
}


impl Templates {
    fn compile_template(path: &str) -> Template {
        Template(mustache::compile_path(path).unwrap())
    }
}

impl Default for Templates {
    fn default() -> Templates {
        Templates {
            confirm_email: Self::compile_template("tmpl/confirm_email.mustache"),
            email_html: Self::compile_template("tmpl/email_html.mustache"),
            email_text: Self::compile_template("tmpl/email_text.mustache"),
            error: Self::compile_template("tmpl/error.mustache"),
            forward: Self::compile_template("tmpl/forward.mustache"),
        }
    }
}


pub struct Provider {
    pub client_id: String,
    pub secret: String,
    pub discovery_url: String,
    pub issuer_domain: String,
}


pub struct Config {
    pub listen_ip: String,
    pub listen_port: u16,
    pub public_url: String,
    pub token_ttl: u16,
    pub keys: Vec<crypto::NamedKey>,
    pub store: store::Store,
    pub from_name: String,
    pub from_address: String,
    pub smtp_server: String,
    pub smtp_username: Option<String>,
    pub smtp_password: Option<String>,
    pub providers: HashMap<String, Provider>,
    pub templates: Templates,
}


pub struct ConfigBuilder {
    pub listen_ip: String,
    pub listen_port: u16,
    pub public_url: Option<String>,
    pub token_ttl: u16,
    pub keyfiles: Vec<String>,
    pub redis_url: Option<String>,
    pub redis_session_ttl: u16,
    pub redis_cache_ttl: u16,
    pub redis_cache_max_doc_size: u16,
    pub from_name: String,
    pub from_address: Option<String>,
    pub smtp_server: Option<String>,
    pub smtp_username: Option<String>,
    pub smtp_password: Option<String>,
    pub providers: HashMap<String, Provider>,
}


impl ConfigBuilder {
    pub fn new() -> ConfigBuilder {
        ConfigBuilder {
            listen_ip: "127.0.0.1".to_string(),
            listen_port: 3333,
            public_url: None,
            token_ttl: 600,
            keyfiles: Vec::new(),
            redis_url: None,
            redis_session_ttl: 900,
            redis_cache_ttl: 3600,
            redis_cache_max_doc_size: 8096,
            from_name: "Portier".to_string(),
            from_address: None,
            smtp_username: None,
            smtp_password: None,
            smtp_server: None,
            providers: HashMap::new(),
        }
    }

    pub fn update_from_file(&mut self, path: &String) -> Result<&mut ConfigBuilder, ConfigError> {
        let mut file = try!(File::open(path));
        let mut file_contents = String::new();
        try!(file.read_to_string(&mut file_contents));
        let mut toml_config: TomlConfig = try!(
            toml::decode_str(&file_contents).ok_or("unable to parse config file")
        );

        self.listen_ip = toml_config.server.listen_ip;
        self.listen_port = toml_config.server.listen_port;
        self.public_url = Some(toml_config.server.public_url);

        self.keyfiles.append(&mut toml_config.crypto.keyfiles);
        self.token_ttl = toml_config.crypto.token_ttl;

        self.redis_url = Some(toml_config.redis.url);
        self.redis_session_ttl = toml_config.redis.session_ttl;
        self.redis_cache_ttl = toml_config.redis.cache_ttl;
        self.redis_cache_max_doc_size = toml_config.redis.cache_max_doc_size;

        self.from_name = toml_config.smtp.from_name;
        self.from_address = Some(toml_config.smtp.from_address);
        self.smtp_server = Some(toml_config.smtp.server);
        self.smtp_username = toml_config.smtp.username;
        self.smtp_password = toml_config.smtp.password;

        for (domain, values) in toml_config.providers {
            self.providers.insert(domain, Provider {
                client_id: values.client_id,
                secret: values.secret,
                discovery_url: values.discovery_url,
                issuer_domain: values.issuer_domain,
            });
        }

        Ok(self)
    }

    pub fn done(self) -> Result<Config, ConfigError> {
        // Additional validations
        if self.smtp_username.is_none() != self.smtp_password.is_none() {
            return Err(ConfigError::Custom(
                "only one of smtp username and password specified; provide both or neither".to_string()
            ));
        }

        // Child structs
        let keys = self.keyfiles.into_iter().filter_map(|path| {
            crypto::NamedKey::from_file(&path).ok()
        }).collect();

        let store = store::Store::new(
            &self.redis_url.unwrap(),
            self.redis_cache_ttl as usize,
            self.redis_session_ttl as usize,
            self.redis_cache_max_doc_size as u64,
        ).unwrap();

        Ok(Config {
            listen_ip: self.listen_ip,
            listen_port: self.listen_port,
            public_url: self.public_url.unwrap(),
            token_ttl: self.token_ttl,
            keys: keys,
            store: store,
            from_name: self.from_name,
            from_address: self.from_address.unwrap(),
            smtp_server: self.smtp_server.unwrap(),
            smtp_username: self.smtp_username,
            smtp_password: self.smtp_password,
            providers: self.providers,
            templates: Templates::default(),
        })
    }
}
