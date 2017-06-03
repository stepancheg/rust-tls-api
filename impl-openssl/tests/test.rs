extern crate tls_api;
extern crate tls_api_openssl;

#[test]
fn test_google() {
    tls_api::impl_test::test_google::<tls_api_openssl::TlsConnectorBuilder>();
}

#[test]
fn connect_bad_hostname() {
    tls_api::impl_test::connect_bad_hostname::<tls_api_openssl::TlsConnectorBuilder>();
}

#[test]
fn connect_bad_hostname_ignored() {
    tls_api::impl_test::connect_bad_hostname_ignored::<tls_api_openssl::TlsConnectorBuilder>();
}

#[test]
fn server() {
    tls_api::impl_test::server::<
        tls_api_openssl::TlsConnectorBuilder,
        tls_api_openssl::TlsAcceptorBuilder>();
}
