extern crate tls_api_native_tls;
extern crate tls_api_test;

#[test]
fn test_google() {
    tls_api_test::test_google::<tls_api_native_tls::TlsConnector>()
}

#[test]
fn connect_bad_hostname() {
    tls_api_test::connect_bad_hostname::<tls_api_native_tls::TlsConnector>();
}

#[test]
fn connect_bad_hostname_ignored() {
    tls_api_test::connect_bad_hostname_ignored::<tls_api_native_tls::TlsConnector>()
}

fn new_acceptor(
    pkcs12: &tls_api_test::Pkcs12,
    _: &tls_api_test::CertificatesAndKey,
) -> tls_api_native_tls::TlsAcceptorBuilder {
    tls_api_native_tls::TlsAcceptorBuilder::from_pkcs12(&pkcs12.der, &pkcs12.password)
        .expect("builder")
}

#[test]
fn server() {
    tls_api_test::server::<tls_api_native_tls::TlsConnector, tls_api_native_tls::TlsAcceptor, _>(
        new_acceptor,
    )
}

#[test]
fn alpn() {
    tls_api_test::alpn::<tls_api_native_tls::TlsConnector, tls_api_native_tls::TlsAcceptor, _>(
        new_acceptor,
    )
}
