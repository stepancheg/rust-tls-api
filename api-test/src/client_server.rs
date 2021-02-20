use std::any;
use std::thread;

use tls_api::runtime::AsyncReadExt;
use tls_api::runtime::AsyncWriteExt;
use tls_api::TlsAcceptor;
use tls_api::TlsAcceptorBuilder;
use tls_api::TlsConnector;
use tls_api::TlsConnectorBuilder;

use crate::block_on;
use crate::new_acceptor;
use crate::new_connector_with_root_ca;
use crate::AcceptorKeyKind;
use crate::TcpListener;
use crate::TcpStream;
use crate::BIND_HOST;

async fn test_client_server_impl<C, A>(key: AcceptorKeyKind)
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

pub fn test_client_server_der<C, A>()
where
    C: TlsConnector,
    A: TlsAcceptor,
{
    block_on(test_client_server_impl::<C, A>(AcceptorKeyKind::Der))
}

pub fn test_client_server_pkcs12<C, A>()
where
    C: TlsConnector,
    A: TlsAcceptor,
{
    block_on(test_client_server_impl::<C, A>(AcceptorKeyKind::Pkcs12))
}
