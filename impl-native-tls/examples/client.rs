#[cfg(feature = "runtime-async-std")]
use async_std::net::TcpStream;
use std::fs;
use tls_api::TlsConnector;
use tls_api::TlsConnectorBuilder;
use tls_api::X509Cert;
use tls_api_test::block_on;
#[cfg(feature = "runtime-tokio")]
use tokio::net::TcpStream;

async fn run() {
    let socket = TcpStream::connect(("127.0.0.1", 4433)).await.unwrap();
    println!("TCP connected");

    let mut builder = tls_api_native_tls::TlsConnector::builder().unwrap();
    builder
        .add_root_certificate(&X509Cert::from_der(fs::read("ca.der").unwrap()).unwrap())
        .unwrap();
    // builder.add_root_certificate(Cert::Der(X509Cert::new(fs::read("/Users/nga/devel/left/rust-security-framework/security-framework/test/server.der").unwrap()))).unwrap();
    // builder.builder.danger_accept_invalid_certs(true);
    // builder.builder.danger_accept_invalid_hostnames(true);
    let connector = builder.build().unwrap();
    println!("connector ready");
    connector.connect("localhost", socket).await.unwrap();
}

fn main() {
    block_on(run());
}
