#[test]
fn test_google() {
    tls_api_test::test_google::<tls_api_openssl::TlsConnector>();
}

#[test]
fn connect_bad_hostname() {
    tls_api_test::connect_bad_hostname::<tls_api_openssl::TlsConnector, _>(|err| {
        let debug = format!("{:?}", err);
        assert!(debug.contains("certificate verify failed"), "{}", debug);
    });
}

#[test]
fn connect_bad_hostname_ignored() {
    tls_api_test::connect_bad_hostname_ignored::<tls_api_openssl::TlsConnector>();
}

#[test]
fn client_server_pkcs12() {
    tls_api_test::client_server_pkcs12::<tls_api_openssl::TlsConnector, tls_api_openssl::TlsAcceptor>(
    );
}

#[test]
fn client_server_der() {
    tls_api_test::client_server_der::<tls_api_openssl::TlsConnector, tls_api_openssl::TlsAcceptor>(
    );
}

#[test]
fn alpn() {
    tls_api_test::alpn::<tls_api_openssl::TlsConnector, tls_api_openssl::TlsAcceptor>();
}
