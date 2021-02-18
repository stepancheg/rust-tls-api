#[test]
fn native_tls_openssl() {
    tls_api_test::server::<tls_api_native_tls::TlsConnector, tls_api_openssl::TlsAcceptor>()
}

#[test]
fn openssl_native_tls() {
    tls_api_test::server::<tls_api_openssl::TlsConnector, tls_api_native_tls::TlsAcceptor>()
}

#[test]
fn rustls_openssl() {
    tls_api_test::server::<tls_api_rustls::TlsConnector, tls_api_openssl::TlsAcceptor>()
}

#[test]
fn openssl_rustls() {
    tls_api_test::server::<tls_api_openssl::TlsConnector, tls_api_rustls::TlsAcceptor>()
}
