extern crate tls_api_test;
extern crate tls_api_rustls;
extern crate rustls;
extern crate webpki;


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

#[test]
fn tokio_wrong_hostname() {
    let err = tls_api_test::tokio_wrong_hostname_error::<tls_api_rustls::TlsConnector>();
    let err: rustls::TLSError = *err.into_inner().downcast().expect("rustls::TLSError");
    match err {
        rustls::TLSError::WebPKIError(webpki::Error::CertNotValidForName) => {
        }
        err => panic!("wrong error: {:?}", err),
    }
}
