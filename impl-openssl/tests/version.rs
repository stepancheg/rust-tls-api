#[test]
fn version() {
    tls_api_test::test_version::<tls_api_openssl::TlsConnector, tls_api_openssl::TlsAcceptor>();
}
