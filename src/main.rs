#![warn(clippy::pedantic)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::enum_glob_use,
    clippy::module_name_repetitions,
    clippy::single_match_else,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::wildcard_imports
)]

#[macro_use]
mod macros;

mod agents;
mod bridges;
mod config;
mod crypto;
mod email_address;
mod error;
mod handlers;
mod metrics;
mod router;
mod utils;
mod validation;
mod web;
mod webfinger;

use crate::agents::{Expiring, ImportKeySet, KeySet};
use crate::config::{ConfigBuilder, ConfigRc};
use crate::crypto::SigningAlgorithm;
use crate::utils::{
    pem::{self, ParsedKeyPair},
    BoxError,
};
use crate::web::Service;
use futures_util::future;
use hyper::{server::Server, service::make_service_fn};
use log::info;
use serde::Deserialize;
use std::{
    io::{Cursor, Read},
    net::SocketAddr,
    path::{Path, PathBuf},
    time::SystemTime,
};

/// Defines the program's version, as set by Cargo at compile time.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Defines the program's usage string.
///
/// [Docopt](http://docopt.org) parses this and generates a custom argv parser.
const USAGE: &str = r#"
Portier Broker

Usage:
  portier-broker [CONFIG]
  portier-broker [CONFIG] --import-key FILE
  portier-broker --version
  portier-broker --help

Options:
  --version          Print version information and exit
  --help             Print this help message and exit
  --import-key FILE  Import a PEM private key, for migrating to rotating keys
"#;

/// Holds parsed command line parameters.
#[derive(Deserialize)]
#[allow(non_snake_case)]
struct Args {
    arg_CONFIG: Option<PathBuf>,
    flag_import_key: Option<PathBuf>,
}

/// The `main()` method. Will loop forever to serve HTTP requests.
#[tokio::main]
async fn main() {
    crate::utils::logger::init();

    // We spawn a bunch of background tasks on the Tokio executor. If these panic, we want to exit
    // instead of continuing on without the task.
    let next_panic_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        next_panic_hook(info);
        std::process::exit(1);
    }));

    let args: Args = docopt::Docopt::new(USAGE)
        .map(|docopt| docopt.version(Some(VERSION.to_owned())))
        .and_then(|docopt| docopt.deserialize())
        .unwrap_or_else(|e| e.exit());

    let mut builder = ConfigBuilder::new();
    if let Some(ref path) = args.arg_CONFIG {
        builder.update_from_file(path);
    }
    builder.update_from_common_env();
    builder.update_from_broker_env();

    if let Some(ref path) = args.flag_import_key {
        import_key(builder, path).await;
    } else {
        start_server(builder).await;
    }
}

async fn start_server(builder: ConfigBuilder) {
    let app = ConfigRc::new(
        builder
            .done()
            .await
            .unwrap_or_else(|err| panic!("failed to build configuration: {}", err)),
    );

    // TODO: Add unix socket support.
    let builder = match listenfd::ListenFd::from_env().take_tcp_listener(0) {
        Ok(Some(tcp_listener)) => {
            let builder = Server::from_tcp(tcp_listener).expect("Socket activation failed");
            info!("Listening on the socket received from the service manager");
            builder
        }
        Ok(None) => {
            let ip_addr = app
                .listen_ip
                .parse()
                .expect("Unable to parse listen address");
            let addr = SocketAddr::new(ip_addr, app.listen_port);
            let builder = Server::bind(&addr);
            info!("Listening on {}", addr);
            builder
        }
        Err(err) => {
            panic!("Socket activation failed: {}", err);
        }
    };

    #[cfg(unix)]
    sd_notify::notify(true, &[sd_notify::NotifyState::Ready])
        .expect("Failed to signal ready to the service manager");

    let make_service = make_service_fn(|stream| {
        metrics::HTTP_CONNECTIONS.inc();
        let app = ConfigRc::clone(&app);
        future::ok::<_, BoxError>(Service::new(app, stream))
    });
    builder.serve(make_service).await.expect("Server error");
}

async fn import_key(builder: ConfigBuilder, file: &Path) {
    let contents = if file == Path::new("-") {
        let mut buf = Vec::new();
        if let Err(err) = std::io::stdin().read_to_end(&mut buf) {
            panic!("Could not read key from stdin: {}", err)
        }
        buf
    } else {
        match std::fs::read(file) {
            Ok(contents) => contents,
            Err(err) => panic!("Could not open key file '{}': {}", file.display(), err),
        }
    };

    let contents = match String::from_utf8(contents) {
        Ok(contents) => contents,
        Err(err) => panic!("Key file '{}' is not valid UTF-8: {}", file.display(), err),
    };

    let key = match pem::parse_key_pairs(Cursor::new(contents.as_bytes())) {
        Ok(keys) if keys.len() == 1 => keys.into_iter().next().unwrap(),
        Ok(_) => panic!(
            "Expected exactly one PEM block in key file '{}'",
            file.display()
        ),
        Err(err) => panic!(
            "Could not parse PEM in key file '{}': {}",
            file.display(),
            err
        ),
    };

    let keys_ttl = builder.keys_ttl;
    let store = builder
        .into_store()
        .await
        .unwrap_or_else(|err| panic!("failed to build configuration: {}", err));

    let signing_alg = match key {
        ParsedKeyPair::Ed25519(_) => SigningAlgorithm::EdDsa,
        ParsedKeyPair::Rsa(_) => SigningAlgorithm::Rs256,
    };
    store
        .send(ImportKeySet(KeySet {
            signing_alg,
            current: Some(Expiring {
                value: contents,
                expires: SystemTime::now() + keys_ttl,
            }),
            next: None,
            previous: None,
        }))
        .await;
    eprintln!("Successfully imported {} key", signing_alg);

    // TODO: This is a little hacky, but we don't have code to shutdown gracefully.
    // (Currently, if a Redis store is simply dropped, the pubsub task panics.)
    std::process::exit(0);
}
