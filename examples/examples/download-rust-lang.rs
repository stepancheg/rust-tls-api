use std::net::ToSocketAddrs;
use tls_api::runtime::AsyncReadExt;
use tls_api::runtime::AsyncWriteExt;

use tls_api::TlsConnector;
use tls_api::TlsConnectorBuilder;

#[cfg(feature = "runtime-async-std")]
use async_std::main;
#[cfg(feature = "runtime-async-std")]
use async_std::net::TcpStream;
#[cfg(feature = "runtime-tokio")]
use tokio::main;
#[cfg(feature = "runtime-tokio")]
use tokio::net::TcpStream;

#[crate::main]
async fn main() {
    let addr = "www.rust-lang.org:443"
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();

    let socket = TcpStream::connect(&addr).await.unwrap();
    let cx = tls_api_native_tls::TlsConnector::builder()
        .unwrap()
        .build()
        .unwrap();

    let mut stream = cx.connect("www.rust-lang.org", socket).await.unwrap();
    stream
        .write_all(
            "\
            GET / HTTP/1.0\r\n\
            Host: www.rust-lang.org\r\n\
            \r\n\
        "
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut data = Vec::new();
    stream.read_to_end(&mut data).await.unwrap();

    println!("{}", String::from_utf8_lossy(&data));
}
