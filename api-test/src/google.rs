use std::any;
use std::net::ToSocketAddrs;

use tls_api::runtime::AsyncReadExt;
use tls_api::runtime::AsyncWriteExt;
use tls_api::TlsConnector;
use tls_api::TlsConnectorBuilder;

use crate::block_on;
use crate::TcpStream;

async fn test_google_impl<C: TlsConnector>() {
    drop(env_logger::try_init());

    if !C::IMPLEMENTED {
        eprintln!(
            "connector {} is not implemented; skipping",
            any::type_name::<C>()
        );
        return;
    }

    // First up, resolve google.com
    let addr = t!("google.com:443".to_socket_addrs()).next().unwrap();

    let connector: C = C::builder().expect("builder").build().expect("build");
    let tcp_stream = t!(TcpStream::connect(addr).await);
    let mut tls_stream = t!(connector.connect("google.com", tcp_stream).await);

    info!("handshake complete");

    t!(tls_stream.write_all(b"GET / HTTP/1.0\r\n\r\n").await);
    let mut result = vec![];
    let res = tls_stream.read_to_end(&mut result).await;

    // Google will not send close_notify and just close the connection.
    // This means that they are not confirming to TLS exactly, that connections to google.com
    // are vulnerable to truncation attacks and that we need to suppress error about this here.
    match res {
        Ok(_) => {}
        Err(e)
            if e.to_string()
                .contains("peer closed connection without sending TLS close_notify") => {}
        Err(e) => panic!("{}", e),
    }

    println!("{}", String::from_utf8_lossy(&result));
    assert!(
        result.starts_with(b"HTTP/1.0"),
        "wrong result: {:?}",
        result
    );
    assert!(result.ends_with(b"</HTML>\r\n") || result.ends_with(b"</html>"));
}

/// Download google.com front page.
pub fn test_google<C: TlsConnector>() {
    block_on(test_google_impl::<C>())
}
