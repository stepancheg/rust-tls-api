use test_cert_gen::ServerKeys;

fn openssl_new_acceptor(server_keys: &ServerKeys) -> tls_api_openssl::TlsAcceptorBuilder {
    tls_api_openssl::TlsAcceptorBuilder::from_pkcs12(&server_keys.server_cert_and_key_pkcs12)
        .expect("builder")
}

fn native_tls_new_acceptor(server_keys: &ServerKeys) -> tls_api_native_tls::TlsAcceptorBuilder {
    tls_api_native_tls::TlsAcceptorBuilder::from_pkcs12(&server_keys.server_cert_and_key_pkcs12)
        .expect("builder")
}

fn rustls_new_acceptor(server_keys: &ServerKeys) -> tls_api_rustls::TlsAcceptorBuilder {
    let cert = &server_keys.server_cert_and_key.cert;
    let key = &server_keys.server_cert_and_key.key;
    tls_api_rustls::TlsAcceptorBuilder::from_cert_and_key(&cert, &key).expect("builder")
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

#[test]
fn rustls_openssl() {
    tls_api_test::server::<tls_api_rustls::TlsConnector, tls_api_openssl::TlsAcceptor, _>(
        openssl_new_acceptor,
    )
}

#[test]
fn openssl_rustls() {
    tls_api_test::server::<tls_api_openssl::TlsConnector, tls_api_rustls::TlsAcceptor, _>(
        rustls_new_acceptor,
    )
}
