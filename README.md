[![Build Status](https://img.shields.io/travis/stepancheg/rust-tls-api.svg)](https://travis-ci.org/stepancheg/rust-tls-api)
[![License](https://img.shields.io/crates/l/tls-api.svg)](https://github.com/stepancheg/rust-tls-api/blob/master/LICENSE)
[![crates.io](https://img.shields.io/crates/v/tls-api.svg)](https://crates.io/crates/tls-api) 

# Rust TLS API and implementations

Several crates:

* tls-api — TLS API without any implementation and without dependencies
* tls-api-native-tls — implementation of TLS API over
  [native-tls](https://github.com/sfackler/rust-native-tls) crate
* tls-api-openssl — implementation of TLS API over
  [openssl](https://github.com/sfackler/rust-openssl) crate
* tls-api-rustls — implementation of TLS API over
  [rustls](https://github.com/ctz/rustls) crate
* tls-api-schannel — _missing_ implementation of TLS API over
  [schannel](https://github.com/steffengy/schannel-rs) crate
* tls-api-security-framework — _missing_ implementation of TLS API over
  [security framework](https://github.com/sfackler/rust-security-framework) crate
* tls-api-stub — stub API implementation which returns an error on any operation
* tokio-tls-api — fork of [tokio-tls](https://github.com/tokio-rs/tokio-tls)
  which uses tls-api instead of native-tls

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

## Status

|                          | openssl | native-tls | rustls |
| ------------------------ | ------- | ---------- | ------ |
| Can fetch google.com:443 | Yes     | Yes        | Yes    |
| Server works             | Yes     | Yes        | No     |
| ALPN                     | Yes     | No         | No     |

## Why not simply use native-tls

native-tls uses security-framework on OSX, and security-framework does not support ALPN.

Or you simply want to have an option to avoid building TLS library.
