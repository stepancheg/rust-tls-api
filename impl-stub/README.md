[![GitHub Workflow Status](https://img.shields.io/github/workflow/status/stepancheg/rust-tls-api/CI)](https://github.com/stepancheg/rust-tls-api/actions?query=workflow%3ACI)
[![License](https://img.shields.io/crates/l/tls-api.svg)](https://github.com/stepancheg/rust-tls-api/blob/master/LICENSE)
[![crates.io](https://img.shields.io/crates/v/tls-api.svg)](https://crates.io/crates/tls-api)

## tls-api-stub

Stub implementation of tls-api. All operations return an error.

Useful when you need an implementation of type like `TlsConnector`,
but you do not intend to use it.

E. g.

```
fn connect<C : tls_api::TlsConnector>(host: &str, use_tls: bool) { ... }
```

So if the function is to be used without TLS, it can be called with stub implementation:

```
connect::<tls_api_stub::TlsConnector>("database", false);
```
