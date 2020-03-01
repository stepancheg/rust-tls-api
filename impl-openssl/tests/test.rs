extern crate openssl;
extern crate tls_api_openssl;
extern crate tls_api_test;

#[test]
fn test_google() {
    tls_api_test::test_google::<tls_api_openssl::TlsConnector>();
}

#[test]
fn connect_bad_hostname() {
    let err = tls_api_test::connect_bad_hostname::<tls_api_openssl::TlsConnector>();
    let debug = format!("{:?}", err);
    assert!(debug.contains("certificate verify failed"), debug);
}

#[test]
fn connect_bad_hostname_ignored() {
    tls_api_test::connect_bad_hostname_ignored::<tls_api_openssl::TlsConnector>();
}

fn new_acceptor(
    pkcs12: &tls_api_test::Pkcs12,
    _: &tls_api_test::CertificatesAndKey,
) -> tls_api_openssl::TlsAcceptorBuilder {
    tls_api_openssl::TlsAcceptorBuilder::from_pkcs12(&pkcs12.der, &pkcs12.password)
        .expect("builder")
}

#[test]
fn server() {
    tls_api_test::server::<tls_api_openssl::TlsConnector, tls_api_openssl::TlsAcceptor, _>(
        new_acceptor,
    );
}

#[test]
fn alpn() {
    tls_api_test::alpn::<tls_api_openssl::TlsConnector, tls_api_openssl::TlsAcceptor, _>(
        new_acceptor,
    );
}
