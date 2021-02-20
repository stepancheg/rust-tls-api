[![GitHub Workflow Status](https://img.shields.io/github/workflow/status/stepancheg/rust-tls-api/CI)](https://github.com/stepancheg/rust-tls-api/actions?query=workflow%3ACI)
[![License](https://img.shields.io/crates/l/tls-api.svg)](https://github.com/stepancheg/rust-tls-api/blob/master/LICENSE)
[![crates.io](https://img.shields.io/crates/v/tls-api.svg)](https://crates.io/crates/tls-api) 

# test-cert-gen

Utility to generate certificates for tests.

```
test_cert_gen::gen_keys()
```

returns:
* server certificate and private key pair in DER or PKCS12 format
* CA DER file to be used on the client

This is typically enough to configure a TLS server and client
for unit/integration tests.

Certificates are generated with `openssl` command.

Generated certificates expire in a day.
