use std::fs;
use tls_api::TlsAcceptor;
use tls_api::TlsAcceptorBuilder;
use tls_api_test::block_on;

#[cfg(feature = "runtime-async-std")]
use async_std::net::TcpListener;
#[cfg(feature = "runtime-tokio")]
use tokio::net::TcpListener;

use test_cert_gen::pem_to_cert_key_pair;
use tls_api::runtime::AsyncWriteExt;

async fn run() {
    let (cert, key) =
        pem_to_cert_key_pair(fs::read_to_string("server.pem").unwrap().as_bytes()).unwrap();

    let builder =
        tls_api_rustls::TlsAcceptor::builder_from_der_key(cert.get_der(), key.get_der()).unwrap();
    let acceptor = builder.build().unwrap();

    #[allow(unused_mut)]
    let mut listener = TcpListener::bind(("127.0.0.1", 4433)).await.unwrap();
    // let port = listener.local_addr().expect("local_addr").port();

    let socket = listener.accept().await.unwrap().0;
    let mut socket = acceptor.accept(socket).await.unwrap();
    socket.write_all(b"hello\n").await.unwrap();
}

fn main() {
    block_on(run());
}
