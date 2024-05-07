# One TLS API to rule them all

Supports:
* **tokio** and **async-std**
* **rustls**, **native-tls**, **openssl**, **security-framework**

## Crates in this repository

* tls-api — TLS API without any implementation and without dependencies
* tls-api-native-tls — implementation of TLS API over
  [native-tls](https://github.com/sfackler/rust-native-tls) crate
* tls-api-openssl — implementation of TLS API over
  [openssl](https://github.com/sfackler/rust-openssl) crate
* tls-api-rustls — implementation of TLS API over
  [rustls](https://github.com/ctz/rustls) crate
* tls-api-security-framework — implementation of TLS API over
  [security framework](https://github.com/sfackler/rust-security-framework) crate
* tls-api-schannel — _missing_ implementation of TLS API over
  [schannel](https://github.com/steffengy/schannel-rs) crate
* tls-api-stub — stub API implementation which returns an error on any operation
* tls-api-not-tls — stub API implementation which pretends to be TLS, but returns wrapped plain socket
* test-cert-gen — utility to generate certificate for unit tests

## Why one might want to use TLS API instead of concrete implementation

* it is not decided yet which TLS implementation is better, start prototyping with one, and then switch to another
* something doesn't work, no idea why, maybe try another implementation which would provide better diagnostics
* provide a library over TLS (like database client) and allow user do specify preferred TLS implementation
* do a performace comparison of TLS implementations on the same code base
* if one implementation is buggy, it's easy to switch to another without heavy rewrite

## Example

[download-rust-lang-org.rs](https://github.com/edgedb/rust-tls-api/blob/master/examples/examples/download-rust-lang-org.rs#L66)
contains the implementation of simple TLS client downloading rust-lang.org,
which is invoked with four backends.

## Implementations comparison

|                          | openssl | rustls | security-framework | native-tls |
| ------------------------ | ------- | ------ |--------------------| ---------- |
| Can fetch google.com:443 | Yes     | Yes    | Yes                | Yes        |
| Server works             | Yes     | Yes    | Yes                | Yes        |
| Client ALPN              | Yes     | Yes    | Yes                | Yes        |
| Server ALPN              | Yes     | Yes    | No                 | No         |
| Server init from DER key | Yes     | Yes    | No                 | No         |
| Server init from PKCS12  | Yes     | No     | Yes                | Yes        |

## Why not simply use XXX

### Why not simply use native-tls

* does not support server side ALPN
* requires PKCS #12 keys on the server side
* building OpenSSL on Linux is not always trivial

### Why not simply use openssl

* sometimes it's hard to compile it
* some concerns about OpenSSL safety

### Why not simply use rustls

* diagnostics of rustls is not perfect
* certain TLS features are not supported

### Why not simply use security-framework

* only works on Apple
* does not support server side ALPN
