use std::io;

#[test]
fn test_google() {
    tls_api_test::test_google::<tls_api_rustls::TlsConnector>()
}

#[test]
fn connect_bad_hostname() {
    let err = tls_api_test::connect_bad_hostname::<tls_api_rustls::TlsConnector>();
    let err: Box<io::Error> = err.into_inner().downcast().expect("io::Error");
    let err: &rustls::TLSError = err
        .get_ref()
        .expect("cause")
        .downcast_ref()
        .expect("rustls::TLSError");
    match err {
        rustls::TLSError::WebPKIError(webpki::Error::CertNotValidForName) => {}
        err => panic!("wrong error: {:?}", err),
    }
}

#[test]
fn connect_bad_hostname_ignored() {
    tls_api_test::connect_bad_hostname_ignored::<tls_api_rustls::TlsConnector>()
}

fn new_acceptor(
    _: &tls_api_test::Pkcs12,
    ck: &tls_api_test::CertificatesAndKey,
) -> tls_api_rustls::TlsAcceptorBuilder {
    let certs: Vec<&[u8]> = ck.0.iter().map(|c| c.0.as_ref()).collect();
    tls_api_rustls::TlsAcceptorBuilder::from_certs_and_key(&certs, &(ck.1).0).expect("builder")
}

#[test]
fn server() {
    tls_api_test::server::<tls_api_rustls::TlsConnector, tls_api_rustls::TlsAcceptor, _>(
        new_acceptor,
    );
}

#[test]
fn alpn() {
    tls_api_test::alpn::<tls_api_rustls::TlsConnector, tls_api_rustls::TlsAcceptor, _>(
        new_acceptor,
    );
}
