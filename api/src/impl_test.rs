use std::net::TcpStream;
use std::io::Write;
use std::io::Read;

use TlsConnector;
use TlsConnectorBuilder;
use TlsStream;

pub fn test_google<C : TlsConnector>() {
    let connector: C = C::builder().expect("builder").build().expect("build");
    let tcp_stream = TcpStream::connect("google.com:443").expect("connect");
    let mut tls_stream: TlsStream = connector.connect("google.com", tcp_stream).expect("tls");

    tls_stream.write_all(b"GET / HTTP/1.0\r\n\r\n").expect("write");
    let mut result = vec![];
    tls_stream.read_to_end(&mut result).expect("read_to_end");

    println!("{}", String::from_utf8_lossy(&result));
    assert!(result.starts_with(b"HTTP/1.0"));
    assert!(result.ends_with(b"</HTML>\r\n") || result.ends_with(b"</html>"));
}

pub fn connect_bad_hostname<C : TlsConnector>() {
    let connector: C = C::builder().expect("builder").build().expect("build");
    let tcp_stream = TcpStream::connect("google.com:443").expect("connect");
    connector.connect("goggle.com", tcp_stream).unwrap_err();
}
