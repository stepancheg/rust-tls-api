## tls-api-stub-2

*This is a fork of [tls-api-stub](https://crates.io/crates/tls-api-stub) with updated dependencies.*

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
