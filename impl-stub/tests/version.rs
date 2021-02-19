#[test]
fn version() {
    tls_api_test::test_version::<tls_api_stub::TlsConnector, tls_api_stub::TlsAcceptor>();
}
