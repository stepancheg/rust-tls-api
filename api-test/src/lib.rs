//! Common implementation of tests for all TLS API implementations

#[macro_use]
extern crate log;

#[macro_use]
mod t;
mod openssl_test_key_gen;

use std::thread;

use tls_api::Certificate;
use tls_api::TlsAcceptor;
use tls_api::TlsAcceptorBuilder;
use tls_api::TlsConnector;
use tls_api::TlsConnectorBuilder;
use tls_api::TlsStream;

use std::net::ToSocketAddrs;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::net::TcpStream;

use tokio::runtime::Runtime;

async fn test_google_impl<C: TlsConnector>() {
    drop(env_logger::try_init());

    // First up, resolve google.com
    let addr = t!("google.com:443".to_socket_addrs()).next().unwrap();

    let connector: C = C::builder().expect("builder").build().expect("build");
    let tcp_stream = t!(TcpStream::connect(addr).await);
    let mut tls_stream: TlsStream<_> = t!(connector.connect("google.com", tcp_stream).await);

    info!("handshake complete");

    t!(tls_stream.write_all(b"GET / HTTP/1.0\r\n\r\n").await);
    let mut result = vec![];
    t!(tls_stream.read_to_end(&mut result).await);

    println!("{}", String::from_utf8_lossy(&result));
    assert!(
        result.starts_with(b"HTTP/1.0"),
        "wrong result: {:?}",
        result
    );
    assert!(result.ends_with(b"</HTML>\r\n") || result.ends_with(b"</html>"));
}

pub fn test_google<C: TlsConnector>() {
    t!(Runtime::new()).block_on(test_google_impl::<C>())
}

async fn connect_bad_hostname_impl<C: TlsConnector>() -> tls_api::Error {
    drop(env_logger::try_init());

    // First up, resolve google.com
    let addr = t!("google.com:443".to_socket_addrs()).next().unwrap();

    let connector: C = C::builder().expect("builder").build().expect("build");
    let tcp_stream = t!(TcpStream::connect(addr).await);
    connector
        .connect("goggle.com", tcp_stream)
        .await
        .unwrap_err()
}

pub fn connect_bad_hostname<C: TlsConnector>() -> tls_api::Error {
    t!(Runtime::new()).block_on(connect_bad_hostname_impl::<C>())
}

async fn connect_bad_hostname_ignored_impl<C: TlsConnector>() {
    drop(env_logger::try_init());

    // First up, resolve google.com
    let addr = t!("google.com:443".to_socket_addrs()).next().unwrap();

    let tcp_stream = t!(TcpStream::connect(addr).await);

    let mut builder = C::builder().expect("builder");
    builder
        .set_verify_hostname(false)
        .expect("set_verify_hostname");
    let connector: C = builder.build().expect("build");
    t!(connector.connect("ignore", tcp_stream).await);
}

pub fn connect_bad_hostname_ignored<C: TlsConnector>() {
    t!(Runtime::new()).block_on(connect_bad_hostname_ignored_impl::<C>())
}

pub struct RsaPrivateKey(pub Vec<u8>);
pub struct Certificatex(pub Vec<u8>);

/// PKCS12 and password
#[derive(Clone)]
pub struct Pkcs12 {
    /// File contents
    pub der: Vec<u8>,
    /// Password
    pub password: String,
}

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
                if p.tag == "RSA PRIVATE KEY" || p.tag == "PRIVATE KEY" {
                    Some(RsaPrivateKey(p.contents.clone()))
                } else {
                    None
                }
            })
            .collect();

        assert!(pks.len() == 1, "found {} keys", pks.len());

        CertificatesAndKey(certs, pks.swap_remove(0))
    }
}

fn new_acceptor<A, F>(acceptor: F) -> A::Builder
where
    A: TlsAcceptor,
    F: FnOnce(&Pkcs12, &CertificatesAndKey) -> A::Builder,
{
    let keys = &openssl_test_key_gen::keys().server;

    let pem = CertificatesAndKey::parse_pem(&keys.pem);

    acceptor(
        &Pkcs12 {
            der: keys.pkcs12.clone(),
            password: keys.pkcs12_password.clone(),
        },
        &pem,
    )
}

fn new_connector_with_root_ca<C: TlsConnector>() -> C::Builder {
    let keys = openssl_test_key_gen::keys();
    let root_ca = Certificate::from_der(keys.client.cert_der.clone());

    let mut connector = C::builder().expect("connector builder");
    t!(connector.add_root_certificate(root_ca));
    connector
}

// `::1` is broken on travis-ci
// https://travis-ci.org/stepancheg/rust-tls-api/jobs/312681800
const BIND_HOST: &str = "127.0.0.1";

async fn server_impl<C, A, F>(acceptor: F)
where
    C: TlsConnector,
    A: TlsAcceptor,
    F: FnOnce(&Pkcs12, &CertificatesAndKey) -> A::Builder,
{
    drop(env_logger::try_init());

    let acceptor = new_acceptor::<A, _>(acceptor);

    let acceptor: A = acceptor.build().expect("acceptor build");

    let mut listener = t!(TcpListener::bind((BIND_HOST, 0)).await);
    let port = listener.local_addr().expect("local_addr").port();

    let j = thread::spawn(move || {
        let future = async {
            let socket = t!(listener.accept().await).0;
            let mut socket = t!(acceptor.accept(socket).await);

            let mut buf = [0; 5];
            t!(socket.read_exact(&mut buf).await);
            assert_eq!(&buf, b"hello");

            t!(socket.write_all(b"world").await);
        };
        t!(Runtime::new()).block_on(future);
    });

    let socket = t!(TcpStream::connect((BIND_HOST, port)).await);

    let connector: C::Builder = new_connector_with_root_ca::<C>();
    let connector: C = connector.build().expect("acceptor build");
    let mut socket = t!(connector.connect("localhost", socket).await);

    t!(socket.write_all(b"hello").await);
    let mut buf = vec![];
    t!(socket.read_to_end(&mut buf).await);
    assert_eq!(buf, b"world");

    j.join().expect("thread join");
}

pub fn server<C, A, F>(acceptor: F)
where
    C: TlsConnector,
    A: TlsAcceptor,
    F: FnOnce(&Pkcs12, &CertificatesAndKey) -> A::Builder,
{
    t!(Runtime::new()).block_on(server_impl::<C, A, F>(acceptor))
}

async fn alpn_impl<C, A, F>(acceptor: F)
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

    let acceptor: A = t!(acceptor.build());

    let mut listener = t!(TcpListener::bind((BIND_HOST, 0)).await);
    let port = listener.local_addr().expect("local_addr").port();

    let j = thread::spawn(move || {
        let f = async {
            let socket = t!(listener.accept().await).0;
            let mut socket = t!(acceptor.accept(socket).await);

            assert_eq!(b"de", &socket.get_alpn_protocol().unwrap()[..]);

            let mut buf = [0; 5];
            t!(socket.read_exact(&mut buf).await);
            assert_eq!(&buf, b"hello");

            t!(socket.write_all(b"world").await);
        };
        t!(Runtime::new()).block_on(f);
    });

    let socket = t!(TcpStream::connect((BIND_HOST, port)).await);

    let mut connector: C::Builder = new_connector_with_root_ca::<C>();

    connector
        .set_alpn_protocols(&[b"xyz", b"de", b"u"])
        .expect("set_alpn_protocols");

    let connector: C = connector.build().expect("acceptor build");
    let mut socket = t!(connector.connect("localhost", socket).await);

    assert_eq!(b"de", &socket.get_alpn_protocol().unwrap()[..]);

    t!(socket.write_all(b"hello").await);
    let mut buf = vec![];
    t!(socket.read_to_end(&mut buf).await);
    assert_eq!(buf, b"world");

    j.join().expect("thread join");
}

pub fn alpn<C, A, F>(acceptor: F)
where
    C: TlsConnector,
    A: TlsAcceptor,
    F: FnOnce(&Pkcs12, &CertificatesAndKey) -> A::Builder,
{
    t!(Runtime::new()).block_on(alpn_impl::<C, A, F>(acceptor))
}
