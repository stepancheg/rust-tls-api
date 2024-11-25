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
