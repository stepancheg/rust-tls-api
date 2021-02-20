[![GitHub Workflow Status](https://img.shields.io/github/workflow/status/stepancheg/rust-tls-api/CI)](https://github.com/stepancheg/rust-tls-api/actions?query=workflow%3ACI)
[![License](https://img.shields.io/crates/l/tls-api.svg)](https://github.com/stepancheg/rust-tls-api/blob/master/LICENSE)
[![crates.io](https://img.shields.io/crates/v/tls-api.svg)](https://crates.io/crates/tls-api) 

# Rust TLS API and implementations

One TLS API to rule them all.

Supports:
* tokio and async-std
* rustls, native-tls, openssl, security-framework

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
* test-cert-gen — utility to generate certificate for unit tests

## The problem

If you develop a library, you do not know which TLS library your user would like to use,
and if they need any TLS library at all.

Because of that some libraries simply depend on specific TLS implementations, while others
provide "features" to turn on specific dependencies.

It makes development for both library authors and library users inconvenient.
Both authors and users need to configure "features" in `Cargo.toml` and `#[cfg]` in code.
For example, your library need to support three options: use openssl, use native-tls, and
no TLS at all. So you need to compile your library three times to check it can be compiled
properly with all three options.

## The solution

Library authors simply write the code with tls-api library. Since `tls-api` is
lightweight, library authors can simply write code using it, and have no configuration options.

Library users simply call that library with different implementations of connectors and acceptors.

## Example

[api-test](https://github.com/stepancheg/rust-tls-api/blob/master/api-test/src/lib.rs)
contains tests implementation independent of any library. And identical tests which
use:
* [native-tls](https://github.com/stepancheg/rust-tls-api/blob/master/impl-native-tls/tests/test.rs)
* [openssl](https://github.com/stepancheg/rust-tls-api/blob/master/impl-openssl/tests/test.rs)
* [rustls](https://github.com/stepancheg/rust-tls-api/blob/master/impl-rustls/tests/test.rs)

## Implementations comparison

|                          | openssl | rustls | security-framework | native-tls |
| ------------------------ | ------- | ------ |--------------------| ---------- |
| Can fetch google.com:443 | Yes     | Yes    | Yes                | Yes        |
| Server works             | Yes     | Yes    | Yes                | Yes        |
| Client ALPN              | Yes     | Yes    | Yes                | Yes        |
| Server ALPN              | Yes     | Yes    | No                 | No         |
| Server init from DER key | Yes     | Yes    | No                 | No         |
| Server init from PKCS12  | Yes     | No     | Yes                | Yes        |

## Why not simply use native-tls

* native-tls uses security-framework on OSX, and security-framework does not support ALPN on the server side.
* building OpenSSL on Linux might be not trivial

# Why not simply use openssl

* Sometimes it's hard to compile it
* Some concerns about OpenSSL safety

# Why not simply use rustls

* Diagnostics of rustls is not perfect
* Certain TLS features are not supported

# Why not simply use security-framework

* only works on Apple
* does not support server side ALPN
