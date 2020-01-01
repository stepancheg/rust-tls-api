extern crate futures;
extern crate tokio_core;
extern crate tokio_io;
extern crate tokio_tls_api;

extern crate pem;
extern crate untrusted;
extern crate webpki;

#[macro_use]
extern crate log;
extern crate env_logger;

extern crate tls_api;

mod tokio_google;

use std::io::Read;
use std::io::Write;
use std::net::TcpListener;
use std::net::TcpStream;
use std::thread;

use tls_api::Certificate;
use tls_api::TlsAcceptor;
use tls_api::TlsAcceptorBuilder;
use tls_api::TlsConnector;
use tls_api::TlsConnectorBuilder;
use tls_api::TlsStream;

pub fn test_google<C: TlsConnector>() {
    drop(env_logger::try_init());

    let connector: C = C::builder().expect("builder").build().expect("build");
    let tcp_stream = TcpStream::connect("google.com:443").expect("connect");
    let mut tls_stream: TlsStream<_> = connector.connect("google.com", tcp_stream).expect("tls");

    info!("handshake complete");

    tls_stream
        .write_all(b"GET / HTTP/1.0\r\n\r\n")
        .expect("write");
    let mut result = vec![];
    tls_stream.read_to_end(&mut result).expect("read_to_end");

    println!("{}", String::from_utf8_lossy(&result));
    assert!(
        result.starts_with(b"HTTP/1.0"),
        "wrong result: {:?}",
        result
    );
    assert!(result.ends_with(b"</HTML>\r\n") || result.ends_with(b"</html>"));
}

pub fn connect_bad_hostname<C: TlsConnector>() {
    drop(env_logger::try_init());

    let connector: C = C::builder().expect("builder").build().expect("build");
    let tcp_stream = TcpStream::connect("google.com:443").expect("connect");
    connector.connect("goggle.com", tcp_stream).unwrap_err();
}

pub fn connect_bad_hostname_ignored<C: TlsConnector>() {
    drop(env_logger::try_init());

    let mut builder = C::builder().expect("builder");
    builder
        .set_verify_hostname(false)
        .expect("set_verify_hostname");
    let connector: C = builder.build().expect("build");
    let tcp_stream = TcpStream::connect("google.com:443").expect("connect");
    connector.connect("ignore", tcp_stream).expect("tls");
}

pub struct RsaPrivateKey(pub Vec<u8>);
pub struct Certificatex(pub Vec<u8>);

/// File contents and password
pub struct Pkcs12(pub Vec<u8>, pub String);

pub struct CertificatesAndKey(pub Vec<Certificatex>, pub RsaPrivateKey);

impl CertificatesAndKey {
    fn parse_pem(pem: &[u8]) -> CertificatesAndKey {
        let pems = pem::parse_many(pem);

        let certs: Vec<_> = pems
            .iter()
            .filter_map(|p| {
                if p.tag == "CERTIFICATE" {
                    Some(Certificatex(p.contents.clone()))
                } else {
                    None
                }
            })
            .collect();

        assert!(certs.len() > 0);

        let mut pks: Vec<_> = pems
            .iter()
            .filter_map(|p| {
                if p.tag == "RSA PRIVATE KEY" {
                    Some(RsaPrivateKey(p.contents.clone()))
                } else {
                    None
                }
            })
            .collect();

        assert!(pks.len() == 1);

        CertificatesAndKey(certs, pks.swap_remove(0))
    }
}

fn new_acceptor<A, F>(acceptor: F) -> A::Builder
where
    A: TlsAcceptor,
    F: FnOnce(&Pkcs12, &CertificatesAndKey) -> A::Builder,
{
    let pkcs12 = include_bytes!("../test/identity.p12");
    let pkcs12 = Pkcs12(pkcs12.to_vec(), "mypass".to_owned());

    let pem = include_bytes!("../test/identity.pem");
    let pem = CertificatesAndKey::parse_pem(pem);

    acceptor(&pkcs12, &pem)
}

fn new_connector_with_root_ca<C: TlsConnector>() -> C::Builder {
    let root_ca = include_bytes!("../test/root-ca.der");
    let root_ca = Certificate::from_der(root_ca.to_vec());

    let mut connector = C::builder().expect("connector builder");
    connector
        .add_root_certificate(root_ca)
        .expect("add root certificate");
    connector
}

// `::1` is broken on travis-ci
// https://travis-ci.org/stepancheg/rust-tls-api/jobs/312681800
const BIND_HOST: &str = "127.0.0.1";

pub fn server<C, A, F>(acceptor: F)
where
    C: TlsConnector,
    A: TlsAcceptor,
    F: FnOnce(&Pkcs12, &CertificatesAndKey) -> A::Builder,
{
    drop(env_logger::try_init());

    let acceptor = new_acceptor::<A, _>(acceptor);

    let acceptor: A = acceptor.build().expect("acceptor build");

    let listener = TcpListener::bind((BIND_HOST, 0)).expect("bind");
    let port = listener.local_addr().expect("local_addr").port();

    let j = thread::spawn(move || {
        let socket = listener.accept().expect("accept").0;
        let mut socket = acceptor.accept(socket).expect("tls accept");

        let mut buf = [0; 5];
        socket.read_exact(&mut buf).expect("server read_exact");
        assert_eq!(&buf, b"hello");

        socket.write_all(b"world").expect("server write");
    });

    let socket = TcpStream::connect((BIND_HOST, port)).expect("connect");

    let connector: C::Builder = new_connector_with_root_ca::<C>();
    let connector: C = connector.build().expect("acceptor build");
    let mut socket = connector
        .connect("foobar.com", socket)
        .expect("tls connect");

    socket.write_all(b"hello").expect("client write");
    let mut buf = vec![];
    socket.read_to_end(&mut buf).expect("client read");
    assert_eq!(buf, b"world");

    j.join().expect("thread join");
}

pub fn alpn<C, A, F>(acceptor: F)
where
    C: TlsConnector,
    A: TlsAcceptor,
    F: FnOnce(&Pkcs12, &CertificatesAndKey) -> A::Builder,
{
    drop(env_logger::try_init());

    if !C::supports_alpn() {
        debug!("connector does not support ALPN");
        return;
    }

    if !A::supports_alpn() {
        debug!("acceptor does not support ALPN");
        return;
    }

    let mut acceptor: A::Builder = new_acceptor::<A, _>(acceptor);

    acceptor
        .set_alpn_protocols(&[b"abc", b"de", b"f"])
        .expect("set_alpn_protocols");

    let acceptor: A = acceptor.build().expect("acceptor build");

    let listener = TcpListener::bind((BIND_HOST, 0)).expect("bind");
    let port = listener.local_addr().expect("local_addr").port();

    let j = thread::spawn(move || {
        let socket = listener.accept().expect("accept").0;
        let mut socket = acceptor.accept(socket).expect("tls accept");

        assert_eq!(b"de", &socket.get_alpn_protocol().unwrap()[..]);

        let mut buf = [0; 5];
        socket.read_exact(&mut buf).expect("server read_exact");
        assert_eq!(&buf, b"hello");

        socket.write_all(b"world").expect("server write");
    });

    let socket = TcpStream::connect((BIND_HOST, port)).expect("connect");

    let mut connector: C::Builder = new_connector_with_root_ca::<C>();

    connector
        .set_alpn_protocols(&[b"xyz", b"de", b"u"])
        .expect("set_alpn_protocols");

    let connector: C = connector.build().expect("acceptor build");
    let mut socket = connector
        .connect("foobar.com", socket)
        .expect("tls connect");

    assert_eq!(b"de", &socket.get_alpn_protocol().unwrap()[..]);

    socket.write_all(b"hello").expect("client write");
    let mut buf = vec![];
    socket.read_to_end(&mut buf).expect("client read");
    assert_eq!(buf, b"world");

    j.join().expect("thread join");
}

pub use tokio_google::fetch_google as tokio_fetch_google;
pub use tokio_google::wrong_hostname_error as tokio_wrong_hostname_error;
