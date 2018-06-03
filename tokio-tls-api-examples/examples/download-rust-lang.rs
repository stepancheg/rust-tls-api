extern crate futures;
extern crate tls_api;
extern crate tls_api_native_tls;
extern crate tokio;
extern crate tokio_io;
extern crate tokio_tls_api;
extern crate tokio_tcp;

use std::io;
use std::net::ToSocketAddrs;

use futures::Future;
use tls_api::TlsConnector;
use tls_api::TlsConnectorBuilder;
use tokio_tcp::TcpStream;
use tokio::executor::current_thread::CurrentThread;

fn main() {
    let addr = "www.rust-lang.org:443".to_socket_addrs().unwrap().next().unwrap();

    let socket = TcpStream::connect(&addr);
    let cx = tls_api_native_tls::TlsConnector::builder().unwrap().build().unwrap();

    let tls_handshake = socket.and_then(|socket| {
        tokio_tls_api::connect_async(&cx, "www.rust-lang.org", socket).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, e)
        })
    });
    let request = tls_handshake.and_then(|socket| {
        tokio_io::io::write_all(socket, "\
            GET / HTTP/1.0\r\n\
            Host: www.rust-lang.org\r\n\
            \r\n\
        ".as_bytes())
    });
    let response = request.and_then(|(socket, _)| {
        tokio_io::io::read_to_end(socket, Vec::new())
    });

    let mut executor = CurrentThread::new();

    let (_, data) = executor.block_on(response).unwrap();
    println!("{}", String::from_utf8_lossy(&data));
}
