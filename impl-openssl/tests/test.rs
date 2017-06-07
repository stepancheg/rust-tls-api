extern crate tls_api_test;
extern crate tls_api_openssl;
extern crate openssl;

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

fn new_acceptor(pkcs12: &tls_api_test::Pkcs12, _: &tls_api_test::CertificatesAndKey)
    -> tls_api_openssl::TlsAcceptorBuilder
{
    tls_api_openssl::TlsAcceptorBuilder::from_pkcs12(&pkcs12.0, &pkcs12.1).expect("builder")
}

#[test]
fn server() {
    tls_api_test::server::<
        tls_api_openssl::TlsConnector,
        tls_api_openssl::TlsAcceptor, _>(new_acceptor);
}

#[test]
fn alpn() {
    tls_api_test::alpn::<
        tls_api_openssl::TlsConnector,
        tls_api_openssl::TlsAcceptor, _>(new_acceptor);
}

#[test]
fn tokio_fetch_google() {
    tls_api_test::tokio_fetch_google::<tls_api_openssl::TlsConnector>();
}

#[test]
fn tokio_wrong_hostname() {
    let err = tls_api_test::tokio_wrong_hostname_error::<tls_api_openssl::TlsConnector>();

    let err: openssl::ssl::Error = *err.into_inner().downcast().expect("openssl::ssl::Error");

    let err = match err {
        openssl::ssl::Error::Ssl(stack) => stack,
        _ => panic!("wrong error: {:?}", err),
    };

    for err in err.errors() {
        if err.reason() == Some("certificate verify failed") {
            return;
        }
    }

    panic!("wrong error: {}", err);
}
