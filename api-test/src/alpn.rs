use std::any;
use std::thread;

use tls_api::runtime::AsyncReadExt;
use tls_api::runtime::AsyncWriteExt;
use tls_api::TlsAcceptor;
use tls_api::TlsAcceptorBuilder;
use tls_api::TlsConnector;
use tls_api::TlsConnectorBuilder;
use tls_api::TlsStreamDyn;

use crate::block_on;
use crate::new_acceptor;
use crate::new_connector_builder_with_root_ca;
use crate::TcpListener;
use crate::TcpStream;
use crate::BIND_HOST;

async fn test_alpn_impl<C, A>()
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
            let mut socket = t!(acceptor.accept(socket).await);

            assert_eq!(b"de", &socket.get_alpn_protocol().unwrap().unwrap()[..]);

            let mut buf = [0; 5];
            t!(socket.read_exact(&mut buf).await);
            assert_eq!(&buf, b"hello");

            t!(socket.write_all(b"world").await);
        };
        block_on(f);
    });

    let socket = t!(TcpStream::connect((BIND_HOST, port)).await);

    let mut connector: C::Builder = new_connector_builder_with_root_ca::<C>();

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

pub fn test_alpn<C, A>()
where
    C: TlsConnector,
    A: TlsAcceptor,
{
    block_on(test_alpn_impl::<C, A>())
}
