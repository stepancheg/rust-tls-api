#[test]
fn version() {
    tls_api_test::test_version::<tls_api_rustls::TlsConnector, tls_api_rustls::TlsAcceptor>();
}
