//! Implementation neutral TLS API.
//!
//! The idea is that code can be written in generic fashion like:
//!
//! ```ignore
//! use tls_api::{TlsConnector, TlsConnectorBuilder};
//! use tokio::net::TcpStream;
//! use tokio::io::{AsyncWriteExt, AsyncReadExt};
//! // or use async-std instead of tokio
//!
//! async fn download_rust_lang_org<C: TlsConnector>() -> tls_api::Result<Vec<u8>> {
//!     let stream = TcpStream::connect(("rust-lang.org", 443)).await?;
//!     let mut  stream = C::builder()?.build()?.connect("rust-lang.org", stream).await?;
//!     stream.write_all(b"GET / HTTP/1.1\r\nHost: rust-lang.org\r\n\r\n").await?;
//!     let mut buf = Vec::new();
//!     stream.read_to_end(&mut buf).await?;
//!     Ok(buf)
//! }
//! ```
//!
//! (Full working example is
//! [on GitHub](https://github.com/stepancheg/rust-tls-api/blob/master/examples/examples/download-rust-lang.rs).)
//!
//! And then this function can be executed with any API implementations. The implementations are:
//! * `tls-api-openssl`, wraps `openssl` crate
//! * `tls-api-rustls`, wraps `rustls` crate
//! * `tls-api-native-tls`, wraps `native-tls` crate
//! * `tls-api-security-framework`, wraps `security-framework` crate
//! * (there's also `tls-api-stub` crate which returns an error on any operations,
//!   it is useful sometimes to check code compiles).
//!
//! Additionally, the API is provided to be compatible with both tokio and async-std.
//! Runtime features:
//! * `runtime-tokio` enables the implementation over tokio
//! * `runtime-async-std` enables the implementation over async-std
//! Currently the features are mutually exclusive.

#![deny(broken_intra_doc_links)]
#![deny(missing_docs)]

pub use acceptor::TlsAcceptor;
pub use acceptor::TlsAcceptorBuilder;
pub use cert::pem_to_cert_key_pair;
pub use cert::Pkcs12;
pub use cert::Pkcs12AndPassword;
pub use cert::PrivateKey;
pub use cert::X509Cert;
pub use connector::TlsConnector;
pub use connector::TlsConnectorBuilder;
pub use connector_box::TlsConnectorBox;
pub use connector_box::TlsConnectorBuilderBox;
pub use connector_box::TlsConnectorType;
pub use error::Error;
pub use error::Result;
pub use future::BoxFuture;
pub use socket::AsyncSocket;
pub use socket_box::AsyncSocketBox;
pub use stream::TlsStream;
pub use stream_box::TlsStreamBox;

pub mod runtime;
pub mod spi;

mod acceptor;
mod cert;
mod connector;
mod connector_box;
mod error;
mod future;
mod socket;
mod socket_box;
mod stream;
mod stream_box;

fn _check_kinds() {
    fn assert_sync<T: Sync>() {}
    fn assert_send<T: Send>() {}
    fn assert_send_value<T: Send>(t: T) -> T {
        t
    }

    assert_sync::<Error>();
    assert_send::<Error>();
    // assert_sync::<TlsStream<TcpStream>>();

    fn assert_tls_stream_send<S: AsyncSocket>() {
        assert_send::<TlsStream<S>>();
    }

    fn connect_future_is_send<C, S>(c: &C, s: S)
    where
        C: TlsConnector,
        S: AsyncSocket,
    {
        let f = c.connect("dom", s);
        assert_send_value(f);
    }

    fn accept_future_is_send<A, S>(a: &A, s: S)
    where
        A: TlsAcceptor,
        S: AsyncSocket,
    {
        let f = a.accept(s);
        assert_send_value(f);
    }
}
