extern crate tls_api_native_tls;
extern crate tls_api_openssl;
extern crate tls_api_rustls;
extern crate tls_api_test;

fn openssl_new_acceptor(
    pkcs12: &tls_api_test::Pkcs12,
    _: &tls_api_test::CertificatesAndKey,
) -> tls_api_openssl::TlsAcceptorBuilder {
    tls_api_openssl::TlsAcceptorBuilder::from_pkcs12(&pkcs12.0, &pkcs12.1).expect("builder")
}

fn native_tls_new_acceptor(
    pkcs12: &tls_api_test::Pkcs12,
    _: &tls_api_test::CertificatesAndKey,
) -> tls_api_native_tls::TlsAcceptorBuilder {
    tls_api_native_tls::TlsAcceptorBuilder::from_pkcs12(&pkcs12.0, &pkcs12.1).expect("builder")
}

fn rustls_new_acceptor(
    _: &tls_api_test::Pkcs12,
    ck: &tls_api_test::CertificatesAndKey,
) -> tls_api_rustls::TlsAcceptorBuilder {
    let certs: Vec<&[u8]> = ck.0.iter().map(|c| c.0.as_ref()).collect();
    tls_api_rustls::TlsAcceptorBuilder::from_certs_and_key(&certs, &(ck.1).0).expect("builder")
}

#[test]
fn native_tls_openssl() {
    tls_api_test::server::<tls_api_native_tls::TlsConnector, tls_api_openssl::TlsAcceptor, _>(
        openssl_new_acceptor,
    )
}

#[test]
fn openssl_native_tls() {
    tls_api_test::server::<tls_api_openssl::TlsConnector, tls_api_native_tls::TlsAcceptor, _>(
        native_tls_new_acceptor,
    )
}

#[ignore] // TODO
#[test]
fn rustls_openssl() {
    tls_api_test::server::<tls_api_rustls::TlsConnector, tls_api_openssl::TlsAcceptor, _>(
        openssl_new_acceptor,
    )
}

#[ignore] // TODO
#[test]
fn openssl_rustls() {
    tls_api_test::server::<tls_api_openssl::TlsConnector, tls_api_rustls::TlsAcceptor, _>(
        rustls_new_acceptor,
    )
}
