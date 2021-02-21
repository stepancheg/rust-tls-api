use std::net::ToSocketAddrs;
use tls_api::runtime::AsyncReadExt;
use tls_api::runtime::AsyncWriteExt;

// Users are not supposed to use tokio and async-std side by side.
// Use both just as an example.

#[cfg(feature = "runtime-async-std")]
use async_std::main;
#[cfg(feature = "runtime-async-std")]
use async_std::net::TcpStream;

#[cfg(feature = "runtime-tokio")]
use tokio::main;
#[cfg(feature = "runtime-tokio")]
use tokio::net::TcpStream;

async fn download_impl<C: tls_api::TlsConnector>() {
    if !C::IMPLEMENTED {
        eprintln!(
            "skipping {}, it is not available on this platform",
            C::info().name
        );
        return;
    }

    let addr = "www.rust-lang.org:443"
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();

    let socket = TcpStream::connect(&addr).await.unwrap();

    let mut stream = C::connect_default("www.rust-lang.org", socket)
        .await
        .unwrap();
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

    println!("downloaded {} bytes using {}", data.len(), C::info().name);
}

/// Try it:
/// ```
/// $ cargo run -p tls-api-examples --example download-rust-lang-org
/// ```
/// or
/// ```
/// $ cargo run -p tls-api-examples --example download-rust-lang-org \
///      --no-default-features --features=runtime-async-std
/// ```
#[crate::main]
async fn main() {
    download_impl::<tls_api_native_tls::TlsConnector>().await;
    download_impl::<tls_api_openssl::TlsConnector>().await;
    download_impl::<tls_api_security_framework::TlsConnector>().await;
    download_impl::<tls_api_rustls::TlsConnector>().await;
}
