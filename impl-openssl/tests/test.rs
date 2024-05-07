#[test]
fn connect_bad_hostname() {
    tls_api_test::connect_bad_hostname::<tls_api_openssl_2::TlsConnector, _>(|err| {
        let debug = format!("{:?}", err);
        assert!(debug.contains("certificate verify failed"), "{}", debug);
    });
}
