use std::fs;
use tls_api::TlsConnector;
use tls_api::TlsConnectorBuilder;
use tls_api_test::block_on;

#[cfg(feature = "runtime-async-std")]
use async_std::net::TcpStream;
use test_cert_gen::Cert;
#[cfg(feature = "runtime-tokio")]
use tokio::net::TcpStream;

async fn run() {
    let socket = TcpStream::connect(("127.0.0.1", 4433)).await.unwrap();
    println!("TCP connected");

    let mut builder = tls_api_rustls_2::TlsConnector::builder().unwrap();
    builder
        .add_root_certificate(Cert::from_der(fs::read("ca.der").unwrap()).get_der())
        .unwrap();
    let connector = builder.build().unwrap();
    println!("connector ready");
    connector.connect("localhost", socket).await.unwrap();
}

fn main() {
    block_on(run());
}
