//! Common implementation of tests for all TLS API implementations

#[macro_use]
extern crate log;

#[macro_use]
mod t;

mod version;

use std::any;
use std::str;
use std::thread;

use tls_api::runtime::AsyncReadExt;
use tls_api::runtime::AsyncWriteExt;
use tls_api::TlsAcceptor;
use tls_api::TlsAcceptorBuilder;
use tls_api::TlsConnector;
use tls_api::TlsConnectorBuilder;
use tls_api::TlsStream;

use std::net::ToSocketAddrs;

pub use version::test_version;

#[cfg(feature = "runtime-async-std")]
use async_std::net::TcpListener;
#[cfg(feature = "runtime-async-std")]
use async_std::net::TcpStream;

#[cfg(feature = "runtime-tokio")]
use tokio::net::TcpListener;
#[cfg(feature = "runtime-tokio")]
use tokio::net::TcpStream;

#[cfg(feature = "runtime-async-std")]
pub use async_std::task::block_on;

#[cfg(feature = "runtime-tokio")]
pub fn block_on<F, T>(future: F) -> T
where
    F: std::future::Future<Output = T>,
{
    t!(tokio::runtime::Runtime::new()).block_on(future)
}

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
    block_on(test_google_impl::<C>())
}

async fn connect_bad_hostname_impl<C: TlsConnector, F: FnOnce(tls_api::Error)>(check_error: F) {
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
    let error = connector
        .connect("goggle.com", tcp_stream)
        .await
        .unwrap_err();
    check_error(error);
}

pub fn connect_bad_hostname<C: TlsConnector, F: FnOnce(tls_api::Error)>(check_error: F) {
    block_on(connect_bad_hostname_impl::<C, F>(check_error))
}

async fn connect_bad_hostname_ignored_impl<C: TlsConnector>() {
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

    let tcp_stream = t!(TcpStream::connect(addr).await);

    let mut builder = C::builder().expect("builder");
    builder
        .set_verify_hostname(false)
        .expect("set_verify_hostname");
    let connector: C = builder.build().expect("build");
    t!(connector.connect("ignore", tcp_stream).await);
}

pub fn connect_bad_hostname_ignored<C: TlsConnector>() {
    block_on(connect_bad_hostname_ignored_impl::<C>())
}

fn new_acceptor_from_pkcs12_keys<A>() -> A::Builder
where
    A: TlsAcceptor,
{
    t!(A::builder_from_pkcs12(
        &test_cert_gen::keys().server.cert_and_key_pkcs12.pkcs12.0,
        &test_cert_gen::keys().server.cert_and_key_pkcs12.password,
    ))
}

fn new_acceptor_from_der_keys<A>() -> A::Builder
where
    A: TlsAcceptor,
{
    let keys = &test_cert_gen::keys().server.cert_and_key;
    t!(A::builder_from_der_key(
        keys.cert.get_der(),
        keys.key.get_der()
    ))
}

pub enum AcceptorKeyKind {
    Pkcs12,
    Der,
}

fn new_acceptor<A>(key: Option<AcceptorKeyKind>) -> A::Builder
where
    A: TlsAcceptor,
{
    match key {
        Some(AcceptorKeyKind::Der) => new_acceptor_from_der_keys::<A>(),
        Some(AcceptorKeyKind::Pkcs12) => new_acceptor_from_pkcs12_keys::<A>(),
        None => {
            if A::SUPPORTS_PKCS12_KEYS {
                new_acceptor_from_pkcs12_keys::<A>()
            } else if A::SUPPORTS_DER_KEYS {
                new_acceptor_from_der_keys::<A>()
            } else {
                panic!(
                    "no constructor supported for acceptor {}",
                    any::type_name::<A>()
                );
            }
        }
    }
}

fn new_connector_with_root_ca<C: TlsConnector>() -> C::Builder {
    let keys = test_cert_gen::keys();
    let root_ca = &keys.client.ca;

    let mut connector = C::builder().expect("connector builder");
    t!(connector.add_root_certificate(root_ca.get_der()));
    connector
}

// `::1` is broken on travis-ci
// https://travis-ci.org/stepancheg/rust-tls-api/jobs/312681800
const BIND_HOST: &str = "127.0.0.1";

async fn client_server_impl<C, A>(key: AcceptorKeyKind)
where
    C: TlsConnector,
    A: TlsAcceptor,
{
    drop(env_logger::try_init());

    if !C::IMPLEMENTED {
        eprintln!(
            "connector {} is not implemented; skipping",
            any::type_name::<C>()
        );
        return;
    }

    if !A::IMPLEMENTED {
        eprintln!(
            "acceptor {} is not implemented; skipping",
            any::type_name::<A>()
        );
        return;
    }

    let acceptor = new_acceptor::<A>(Some(key));

    let acceptor: A = acceptor.build().expect("acceptor build");
    #[allow(unused_mut)]
    let mut listener = t!(TcpListener::bind((BIND_HOST, 0)).await);
    let port = listener.local_addr().expect("local_addr").port();

    let server_thread_name = format!("{}-server", thread::current().name().unwrap_or("test"));
    let j = thread::Builder::new()
        .name(server_thread_name)
        .spawn(move || {
            let future = async {
                let socket = t!(listener.accept().await).0;
                let mut socket = t!(acceptor.accept(socket).await);

                let mut buf = [0; 5];
                t!(socket.read_exact(&mut buf).await);
                assert_eq!(&buf, b"hello");

                t!(socket.write_all(b"world").await);
            };
            block_on(future);
        })
        .unwrap();

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

pub fn client_server_der<C, A>()
where
    C: TlsConnector,
    A: TlsAcceptor,
{
    block_on(client_server_impl::<C, A>(AcceptorKeyKind::Der))
}

pub fn client_server_pkcs12<C, A>()
where
    C: TlsConnector,
    A: TlsAcceptor,
{
    block_on(client_server_impl::<C, A>(AcceptorKeyKind::Pkcs12))
}

async fn alpn_impl<C, A>()
where
    C: TlsConnector,
    A: TlsAcceptor,
{
    drop(env_logger::try_init());

    if !C::IMPLEMENTED {
        eprintln!(
            "connector {} is not implemented; skipping",
            any::type_name::<C>()
        );
        return;
    }

    if !A::IMPLEMENTED {
        eprintln!(
            "acceptor {} is not implemented; skipping",
            any::type_name::<A>()
        );
        return;
    }

    if !C::SUPPORTS_ALPN {
        eprintln!("connector {} does not support ALPN", any::type_name::<C>());
        return;
    }

    if !A::SUPPORTS_ALPN {
        eprintln!("acceptor {} does not support ALPN", any::type_name::<A>());
        return;
    }

    let mut acceptor: A::Builder = new_acceptor::<A>(None);

    acceptor
        .set_alpn_protocols(&[b"abc", b"de", b"f"])
        .expect("set_alpn_protocols");

    let acceptor: A = t!(acceptor.build());

    #[allow(unused_mut)]
    let mut listener = t!(TcpListener::bind((BIND_HOST, 0)).await);
    let port = listener.local_addr().expect("local_addr").port();

    let j = thread::spawn(move || {
        let f = async {
            let socket = t!(listener.accept().await).0;
            let mut socket = t!(acceptor.accept_dyn(socket).await);

            assert_eq!(b"de", &socket.get_alpn_protocol().unwrap().unwrap()[..]);

            let mut buf = [0; 5];
            t!(socket.read_exact(&mut buf).await);
            assert_eq!(&buf, b"hello");

            t!(socket.write_all(b"world").await);
        };
        block_on(f);
    });

    let socket = t!(TcpStream::connect((BIND_HOST, port)).await);

    let mut connector: C::Builder = new_connector_with_root_ca::<C>();

    connector
        .set_alpn_protocols(&[b"xyz", b"de", b"u"])
        .expect("set_alpn_protocols");

    let connector: C = connector.build().expect("acceptor build");
    let mut socket = t!(connector.connect("localhost", socket).await);

    assert_eq!(b"de", &socket.get_alpn_protocol().unwrap().unwrap()[..]);

    t!(socket.write_all(b"hello").await);
    let mut buf = vec![];
    t!(socket.read_to_end(&mut buf).await);
    assert_eq!(buf, b"world");

    j.join().expect("thread join");
}

pub fn alpn<C, A>()
where
    C: TlsConnector,
    A: TlsAcceptor,
{
    block_on(alpn_impl::<C, A>())
}
