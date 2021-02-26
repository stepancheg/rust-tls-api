#![cfg(all(rustc_nightly, feature = "runtime-tokio"))]

use std::thread;

use crate::new_acceptor_from_der_keys;
use crate::new_connector_with_root_ca;
use crate::TcpListener;
use crate::TcpStream;
use crate::BIND_HOST;
use test::Bencher;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::runtime::Runtime;

pub fn bench_1<C: tls_api::TlsConnector, A: tls_api::TlsAcceptor>(bencher: &mut Bencher) {
    let acceptor = new_acceptor_from_der_keys::<A>();

    let server_rt = Runtime::new().unwrap();

    #[allow(unused_mut)]
    let mut listener = server_rt
        .block_on(TcpListener::bind((crate::BIND_HOST, 0)))
        .unwrap();
    let port = listener.local_addr().expect("local_addr").port();

    let t = thread::spawn(move || {
        Runtime::new().unwrap().block_on(async {
            let socket = listener.accept().await.unwrap().0;
            let mut stream = acceptor.accept(socket).await.unwrap();
            loop {
                let mut buf = [0];
                let read = stream.read(&mut buf).await.unwrap();
                if read == 0 {
                    break;
                }
                assert_eq!(1, read);
                assert_eq!(1, stream.write(&buf).await.unwrap());
            }
        });
    });

    let rt = Runtime::new().unwrap();

    let socket = rt.block_on(TcpStream::connect((BIND_HOST, port))).unwrap();

    let connector: C = new_connector_with_root_ca();
    let mut tls_stream = rt.block_on(connector.connect("localhost", socket)).unwrap();

    bencher.iter(|| {
        rt.block_on(async {
            assert_eq!(1, tls_stream.write(&[10]).await.unwrap());
            let mut buf = [0];
            assert_eq!(1, tls_stream.read(&mut buf).await.unwrap());
            assert_eq!(10, buf[0]);
        })
    });

    drop(tls_stream);

    t.join().unwrap();
}
