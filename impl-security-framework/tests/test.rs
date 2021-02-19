#[test]
fn test_google() {
    tls_api_test::test_google::<tls_api_security_framework::TlsConnector>()
}

#[test]
fn connect_bad_hostname() {
    tls_api_test::connect_bad_hostname::<tls_api_security_framework::TlsConnector>();
}

#[test]
fn connect_bad_hostname_ignored() {
    tls_api_test::connect_bad_hostname_ignored::<tls_api_security_framework::TlsConnector>()
}

#[test]
fn server() {
    tls_api_test::server::<
        tls_api_security_framework::TlsConnector,
        tls_api_security_framework::TlsAcceptor,
    >()
}

#[test]
fn alpn() {
    tls_api_test::alpn::<
        tls_api_security_framework::TlsConnector,
        tls_api_security_framework::TlsAcceptor,
    >()
}
