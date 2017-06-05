extern crate tls_api_test;
extern crate tls_api_rustls;

#[test]
fn test_google() {
    tls_api_test::test_google::<tls_api_rustls::TlsConnector>();
}

#[test]
fn connect_bad_hostname() {
    tls_api_test::connect_bad_hostname::<tls_api_rustls::TlsConnector>();
}

#[test]
fn connect_bad_hostname_ignored() {
    tls_api_test::connect_bad_hostname_ignored::<tls_api_rustls::TlsConnector>();
}

#[ignore] // TODO
#[test]
fn server() {
    tls_api_test::server::<
        tls_api_rustls::TlsConnector,
        tls_api_rustls::TlsAcceptor>();
}

#[test]
fn tokio_fetch_google() {
    tls_api_test::tokio_fetch_google::<tls_api_rustls::TlsConnector>();
}
