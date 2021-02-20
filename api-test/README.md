[![GitHub Workflow Status](https://img.shields.io/github/workflow/status/stepancheg/rust-tls-api/CI)](https://github.com/stepancheg/rust-tls-api/actions?query=workflow%3ACI)
[![License](https://img.shields.io/crates/l/tls-api.svg)](https://github.com/stepancheg/rust-tls-api/blob/master/LICENSE)
[![crates.io](https://img.shields.io/crates/v/tls-api.svg)](https://crates.io/crates/tls-api)

# tls-api-test

Test implementation the all tls-api implementations.

Contain tests line `client_server` which accept
type parameters for acceptor and connector.
And actual tls-api implementations just use this
crate to do the tests.
