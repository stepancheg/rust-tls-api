[![GitHub Workflow Status](https://img.shields.io/github/workflow/status/stepancheg/rust-tls-api/CI)](https://github.com/stepancheg/rust-tls-api/actions?query=workflow%3ACI)
[![License](https://img.shields.io/crates/l/tls-api.svg)](https://github.com/stepancheg/rust-tls-api/blob/master/LICENSE)
[![crates.io](https://img.shields.io/crates/v/tls-api.svg)](https://crates.io/crates/tls-api)

# tls-api

Implementation neutral common denominator TLS API.

A library working with TLS can be written with this crate
independently on actual TLS implementation, and
the user of the library can fill in the actual type implementation.

This crate only provide interfaces: acceptor and connector.

## Tokio or async-std

This crate (and dependent tls-api-* crates)
have two mutially exclusive features:
* `runtime-tokio` implements API over tokio
* `runtime-async-std` implements API over async-std

## Static or dynamic

API is provided in static or dynamic flavors.

`tls_api::TlsAcceptor` and `tls_api::TlsConnector` type
are `Sized`, each function or structure using them
need to be parameterized by these types, for example:

```
async fn create_listener<C: tls_api::TlsAcceptor>()
    -> anyhow::Result<tls_api::TlsStream<async_std::net::TcpStream>>
{ ... }
```

Alternatively, there's a dynamically-dispatched version of the functions:
`tls_api::TlsAcceptorType` and `tls_api::TlsConnectorType`.
These types are not sized. Could be used like this:

```
async fn create_listener(acceptor: &tls_api::TlsAcceptorType)
    -> anyhow::Result<tls_api::TslStreamBox>
{ ... }
```

Note `create_listener` does not have a type parameter,
which makes coding slightly easier at cost of somewhat
decreased performance.
