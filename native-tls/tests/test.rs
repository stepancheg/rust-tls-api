extern crate tls_api;
extern crate tls_api_native_tls;

#[test]
fn test_google() {
    tls_api::impl_test::test_google::<tls_api_native_tls::TlsConnector>();
}
