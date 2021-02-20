use std::thread;

use tls_api::runtime::AsyncReadExt;
use tls_api::runtime::AsyncWriteExt;
use tls_api::TlsAcceptorType;
use tls_api::TlsConnectorType;

use crate::block_on;
use crate::new_acceptor_dyn;
use crate::new_connector_dyn_with_root_ca;
use crate::AcceptorKeyKind;
use crate::TcpListener;
use crate::TcpStream;
use crate::BIND_HOST;

async fn test_client_server_dyn_impl(
    connector: &dyn TlsConnectorType,
    acceptor: &dyn TlsAcceptorType,
    key: AcceptorKeyKind,
) {
    drop(env_logger::try_init());

    if !connector.implemented() {
        eprintln!("connector {} is not implemented; skipping", connector);
        return;
    }

    if !acceptor.implemented() {
        eprintln!("acceptor {} is not implemented; skipping", acceptor);
        return;
    }

    let acceptor = new_acceptor_dyn(acceptor, Some(key));

    let acceptor = acceptor.build().expect("acceptor build");
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

    let connector = new_connector_dyn_with_root_ca(connector);
    let connector = connector.build().expect("acceptor build");
    let mut socket = t!(connector.connect("localhost", socket).await);

    t!(socket.write_all(b"hello").await);
    let mut buf = vec![];
    t!(socket.read_to_end(&mut buf).await);
    assert_eq!(buf, b"world");

    j.join().expect("thread join");
}

pub fn test_client_server_dyn_der(
    connector: &dyn TlsConnectorType,
    acceptor: &dyn TlsAcceptorType,
) {
    block_on(test_client_server_dyn_impl(
        connector,
        acceptor,
        AcceptorKeyKind::Der,
    ))
}

pub fn test_client_server_dyn_pkcs12(
    connector: &dyn TlsConnectorType,
    acceptor: &dyn TlsAcceptorType,
) {
    block_on(test_client_server_dyn_impl(
        connector,
        acceptor,
        AcceptorKeyKind::Pkcs12,
    ))
}
