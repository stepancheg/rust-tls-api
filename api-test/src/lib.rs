#[macro_use]
extern crate log;
extern crate env_logger;

extern crate tls_api;


use std::net::TcpStream;
use std::net::TcpListener;
use std::io::Write;
use std::io::Read;
use std::thread;

use tls_api::Certificate;
use tls_api::Pkcs12;
use tls_api::TlsConnector;
use tls_api::TlsConnectorBuilder;
use tls_api::TlsAcceptor;
use tls_api::TlsAcceptorBuilder;
use tls_api::TlsStream;


pub fn test_google<C : TlsConnector>() {
    drop(env_logger::init());

    let connector: C = C::builder().expect("builder").build().expect("build");
    let tcp_stream = TcpStream::connect("google.com:443").expect("connect");
    let mut tls_stream: TlsStream<_> = connector.connect("google.com", tcp_stream).expect("tls");

    info!("handshake complete");

    tls_stream.write_all(b"GET / HTTP/1.0\r\n\r\n").expect("write");
    let mut result = vec![];
    tls_stream.read_to_end(&mut result).expect("read_to_end");

    println!("{}", String::from_utf8_lossy(&result));
    assert!(result.starts_with(b"HTTP/1.0"), "wrong result: {:?}", result);
    assert!(result.ends_with(b"</HTML>\r\n") || result.ends_with(b"</html>"));
}

pub fn connect_bad_hostname<C : TlsConnector>() {
    drop(env_logger::init());

    let connector: C = C::builder().expect("builder").build().expect("build");
    let tcp_stream = TcpStream::connect("google.com:443").expect("connect");
    connector.connect("goggle.com", tcp_stream).unwrap_err();
}

pub fn connect_bad_hostname_ignored<C : TlsConnector>() {
    drop(env_logger::init());

    let connector: C = C::builder().expect("builder").build().expect("build");
    let tcp_stream = TcpStream::connect("google.com:443").expect("connect");
    connector.danger_connect_without_providing_domain_for_certificate_verification_and_server_name_indication(tcp_stream)
        .expect("tls");
}

pub fn server<C : TlsConnector, A : TlsAcceptor>() {
    drop(env_logger::init());
    
    let buf = include_bytes!("../test/identity.p12");
    let pkcs12 = A::Pkcs12::from_der(buf, "mypass").expect("pkcs12");
    let acceptor: A = A::builder(pkcs12).expect("acceptor builder")
        .build().expect("acceptor build");

    let listener = TcpListener::bind("[::1]:0").expect("bind");
    let port = listener.local_addr().expect("local_addr").port();

    let j = thread::spawn(move || {
        let socket = listener.accept().expect("accept").0;
        let mut socket = acceptor.accept(socket).expect("tls accept");

        let mut buf = [0; 5];
        socket.read_exact(&mut buf).expect("server read_exact");
        assert_eq!(&buf, b"hello");

        socket.write_all(b"world").expect("server write");
    });

    let root_ca = include_bytes!("../test/root-ca.der");
    let root_ca = C::Certificate::from_der(root_ca).expect("certificate");

    let socket = TcpStream::connect(("::1", port)).expect("connect");
    let mut connector = C::builder().expect("connector builder");
    connector.add_root_certificate(root_ca).expect("add root certificate");
    let connector: C = connector.build().expect("acceptor build");
    let mut socket = connector.connect("foobar.com", socket).expect("tls connect");

    socket.write_all(b"hello").expect("client write");
    let mut buf = vec![];
    socket.read_to_end(&mut buf).expect("client read");
    assert_eq!(buf, b"world");

    j.join().expect("thread join");
}
