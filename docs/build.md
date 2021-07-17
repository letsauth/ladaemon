# Building the broker

To build the broker from source code, you'll need [Rust] installed. We
currently support Rust 1.46 and newer.

[rust]: https://www.rust-lang.org/

Once installed, building the broker is straight-forward:

```bash
cargo build
```

To then run the broker:

```bash
./target/debug/portier-broker[.exe] [config.toml]
```

Or both steps combined:

```bash
cargo run -- [config.toml]
```

To make a release build, add `--release` to the Cargo commands. See the [Cargo
manual] for more information.

[cargo manual]: https://doc.rust-lang.org/cargo/

## Feature flags

Cargo supports feature flags to customize a build. These can be enabled with
`--features` on the Cargo command-line, which takes a space or comma separated
list of feature flags.

The broker has some feature flags enabled by default. If you're going to
customize your build, you may want to add `--no-default-features` to your Cargo
command-line to start from zero, then selectively enable the exact feature
flags you want.

The broker currently defines the following feature flags:

- `redis`: Enables [Redis] storage support using the [redis crate]. (Enabled by
  default.)

- `rusqlite`: Enables [SQLite] storage support using the [rusqlite crate].
  (Enabled by default.)

- `lettre_smtp`: Enables sending mail using SMTP, via the [lettre
  crate]. (Enabled by default.)

- `lettre_smtp`: Enables sending mail using the `sendmail` command, via the
  [lettre crate]. (Enabled by default.)

- `postmark`: Enables sending mail using the [Postmark] API. (Enabled by
  default.)

- `mailgun`: Enables sending mail using the [Mailgun] API. (Enabled by
  default.)

- `insecure`: Uses plain HTTP for WebFinger (instead of HTTPS), and allows
  Identity Providers to use plain HTTP in their discovery documents. Useful for
  testing Identity Provider implementations.

[redis]: https://redis.io
[redis crate]: https://crates.io/crates/redis
[sqlite]: https://www.sqlite.org/index.html
[rusqlite crate]: https://crates.io/crates/rusqlite
[lettre crate]: https://crates.io/crates/lettre
[postmark]: https://postmarkapp.com
[mailgun]: https://www.mailgun.com

## Testing

The broker code includes some unit tests which can be run using:

```bash
cargo test
```

Also included is an end-to-end test, in `tests/e2e`. See [README.md] in that
directory for instructions on how to run it.

[readme.md]: ../tests/e2e/README.md
