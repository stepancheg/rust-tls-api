extern crate tls_api_test;
extern crate tls_api_openssl;

#[test]
fn test_google() {
    tls_api_test::test_google::<tls_api_openssl::TlsConnector>();
}

#[test]
fn connect_bad_hostname() {
    tls_api_test::connect_bad_hostname::<tls_api_openssl::TlsConnector>();
}

#[test]
fn connect_bad_hostname_ignored() {
    tls_api_test::connect_bad_hostname_ignored::<tls_api_openssl::TlsConnector>();
}

#[test]
fn server() {
    tls_api_test::server::<
        tls_api_openssl::TlsConnector,
        tls_api_openssl::TlsAcceptor>();
}
