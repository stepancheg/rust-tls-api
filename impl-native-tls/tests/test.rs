extern crate tls_api_native_tls;
extern crate tls_api_test;

#[test]
fn test_google() {
    tls_api_test::test_google::<tls_api_native_tls::TlsConnector>();
}

#[test]
fn connect_bad_hostname() {
    tls_api_test::connect_bad_hostname::<tls_api_native_tls::TlsConnector>();
}

#[test]
fn connect_bad_hostname_ignored() {
    tls_api_test::connect_bad_hostname_ignored::<tls_api_native_tls::TlsConnector>();
}

fn new_acceptor(
    pkcs12: &tls_api_test::Pkcs12,
    _: &tls_api_test::CertificatesAndKey,
) -> tls_api_native_tls::TlsAcceptorBuilder {
    tls_api_native_tls::TlsAcceptorBuilder::from_pkcs12(&pkcs12.0, &pkcs12.1).expect("builder")
}

#[test]
fn server() {
    tls_api_test::server::<tls_api_native_tls::TlsConnector, tls_api_native_tls::TlsAcceptor, _>(
        new_acceptor,
    );
}

#[test]
fn alpn() {
    tls_api_test::alpn::<tls_api_native_tls::TlsConnector, tls_api_native_tls::TlsAcceptor, _>(
        new_acceptor,
    );
}

#[test]
fn tokio_fetch_google() {
    tls_api_test::tokio_fetch_google::<tls_api_native_tls::TlsConnector>();
}

#[test]
fn tokio_wrong_hostname() {
    let _err = tls_api_test::tokio_wrong_hostname_error::<tls_api_native_tls::TlsConnector>();
    // Different providers use different results, there's no single way to check error
}
