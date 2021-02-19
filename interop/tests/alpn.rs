//! Invoke `tls_api_test::alpn` with various implementations

#[test]
fn native_tls_openssl() {
    tls_api_test::alpn::<tls_api_native_tls::TlsConnector, tls_api_openssl::TlsAcceptor>()
}

#[test]
fn openssl_native_tls() {
    tls_api_test::alpn::<tls_api_openssl::TlsConnector, tls_api_native_tls::TlsAcceptor>()
}

#[test]
fn rustls_openssl() {
    tls_api_test::alpn::<tls_api_rustls::TlsConnector, tls_api_openssl::TlsAcceptor>()
}

#[test]
fn openssl_rustls() {
    tls_api_test::alpn::<tls_api_openssl::TlsConnector, tls_api_rustls::TlsAcceptor>()
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
#[test]
fn openssl_security_framework() {
    tls_api_test::alpn::<tls_api_openssl::TlsConnector, tls_api_security_framework::TlsAcceptor>()
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
#[test]
fn security_framework_rustls() {
    tls_api_test::alpn::<tls_api_security_framework::TlsConnector, tls_api_rustls::TlsAcceptor>()
}
