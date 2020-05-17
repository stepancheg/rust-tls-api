use std::net::ToSocketAddrs;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;

use tls_api::TlsConnector;
use tls_api::TlsConnectorBuilder;
use tokio::net::TcpStream;

#[tokio::main]
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
