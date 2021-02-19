#[test]
fn version() {
    tls_api_test::test_version::<
        tls_api_security_framework::TlsConnector,
        tls_api_security_framework::TlsAcceptor,
    >();
}
