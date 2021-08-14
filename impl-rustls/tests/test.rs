use std::io;

#[test]
fn connect_bad_hostname() {
    tls_api_test::connect_bad_hostname::<tls_api_rustls::TlsConnector, _>(|err| {
        let err: io::Error = err.downcast().expect("io::Error");
        let err: &rustls::Error = err
            .get_ref()
            .expect("cause")
            .downcast_ref()
            .expect("rustls::TLSError");
        match err {
            rustls::Error::InvalidCertificateData(e) => {
                assert_eq!(e, "invalid peer certificate: CertNotValidForName");
            }
            err => panic!("wrong error: {:?}", err),
        }
    });
}

#[test]
fn connect_bad_hostname_ignored() {
    tls_api_test::connect_bad_hostname_ignored::<tls_api_rustls::TlsConnector>()
}

#[test]
fn client_server_der() {
    tls_api_test::test_client_server_der::<tls_api_rustls::TlsConnector, tls_api_rustls::TlsAcceptor>(
    );
}

#[test]
fn client_server_pkcs12() {
    tls_api_test::test_client_server_pkcs12::<
        tls_api_rustls::TlsConnector,
        tls_api_rustls::TlsAcceptor,
    >();
}

#[test]
fn alpn() {
    tls_api_test::test_alpn::<tls_api_rustls::TlsConnector, tls_api_rustls::TlsAcceptor>();
}
