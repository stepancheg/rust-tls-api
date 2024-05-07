#[test]
fn version() {
    tls_api_test::test_version::<tls_api_stub_2::TlsConnector, tls_api_stub_2::TlsAcceptor>();
}
