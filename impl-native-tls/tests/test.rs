#[test]
fn test_google() {
    tls_api_test::test_google::<tls_api_native_tls::TlsConnector>()
}

#[test]
fn connect_bad_hostname() {
    tls_api_test::connect_bad_hostname::<tls_api_native_tls::TlsConnector, _>(drop);
}

#[test]
fn connect_bad_hostname_ignored() {
    tls_api_test::connect_bad_hostname_ignored::<tls_api_native_tls::TlsConnector>()
}

#[test]
fn client_server_der() {
    tls_api_test::test_client_server_der::<
        tls_api_native_tls::TlsConnector,
        tls_api_native_tls::TlsAcceptor,
    >()
}

#[test]
fn client_server_pkcs12() {
    tls_api_test::test_client_server_pkcs12::<
        tls_api_native_tls::TlsConnector,
        tls_api_native_tls::TlsAcceptor,
    >()
}

#[test]
fn alpn() {
    tls_api_test::test_alpn::<tls_api_native_tls::TlsConnector, tls_api_native_tls::TlsAcceptor>()
}
