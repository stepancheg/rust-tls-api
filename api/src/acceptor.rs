use crate::acceptor_box::TlsAcceptorType;
use crate::acceptor_box::TlsAcceptorTypeImpl;
use crate::openssl::der_to_pkcs12;
use crate::openssl::pkcs12_to_der;
use crate::socket::AsyncSocket;
use crate::stream::TlsStream;
use crate::BoxFuture;
use crate::ImplInfo;
use crate::TlsAcceptorBox;
use crate::TlsStreamDyn;
use crate::TlsStreamWithSocket;
use std::fmt;
use std::marker;

/// A builder for `TlsAcceptor`s.
pub trait TlsAcceptorBuilder: Sized + Sync + Send + 'static {
    /// Type of acceptor produced by this builder.
    type Acceptor: TlsAcceptor;

    /// Type of the underlying builder.
    ///
    /// Underlying builder might be needed to perform custom setup
    /// when it is not supported by common API.
    type Underlying;

    /// Specify ALPN protocols for negotiation.
    ///
    /// This operation returns an error if the implemenation does not support ALPN.
    ///
    /// Whether ALPN is supported, can be queried using [`TlsAcceptor::SUPPORTS_ALPN`].
    fn set_alpn_protocols(&mut self, protocols: &[&[u8]]) -> anyhow::Result<()>;

    /// Get the underlying builder.
    ///
    /// API intentionally exposes the underlying acceptor builder to allow fine tuning
    /// not possible in common API.
    fn underlying_mut(&mut self) -> &mut Self::Underlying;

    /// Finish the acceptor construction.
    fn build(self) -> anyhow::Result<Self::Acceptor>;
}

/// A builder for server-side TLS connections.
pub trait TlsAcceptor: Sized + Sync + Send + 'static {
    /// Type of the builder for this acceptor.
    type Builder: TlsAcceptorBuilder<Acceptor = Self>;

    /// Type of the underlying acceptor.
    type Underlying;

    /// `crate::TlsStream<tls_api::AsyncSocketBox>`.
    ///
    /// In the world of HKT this would be:
    ///
    /// ```ignore
    /// type TlsStream<S: TlsStreamDyn> : TlsStreamWithSocketDyn<S>;
    /// ```
    ///
    /// Note each implementation has `accept_impl` function
    /// which returns more specific type, providing both access to implementation details
    /// and the underlying socket.
    type TlsStream: TlsStreamDyn;

    /// Get the underlying acceptor.
    ///
    /// API intentionally exposes the underlying acceptor builder to allow fine acceptor
    /// not possible in common API.
    fn underlying_mut(&mut self) -> &mut Self::Underlying;

    /// Whether this acceptor type is implemented.
    ///
    /// For example, `tls-api-security-framework` is available on Linux,
    /// but all operations result in error, so `IMPLEMENTED = false`
    /// for that implementation.
    const IMPLEMENTED: bool;
    /// Whether this implementation supports ALPN negotiation.
    const SUPPORTS_ALPN: bool;
    /// Whether this implementation supports construction of acceptor using
    /// a pair of a DER certificate and file pair.
    const SUPPORTS_DER_KEYS: bool;
    /// Whether this implementation supports construction of acceptor using
    /// PKCS #12 file.
    const SUPPORTS_PKCS12_KEYS: bool;

    /// Dynamic (without type parameter) version of the acceptor.
    ///
    /// This function returns an acceptor type, which can be used to constructor acceptors.
    const TYPE_DYN: &'static dyn TlsAcceptorType =
        &TlsAcceptorTypeImpl::<Self>(marker::PhantomData);

    /// Dynamic (without type parameter) version of the connector.
    fn into_dyn(self) -> TlsAcceptorBox {
        TlsAcceptorBox::new(self)
    }

    /// Implementation info.
    fn info() -> ImplInfo;

    /// New builder from given server key.
    ///
    /// Parameters are DER-encoded (binary) X509 cert and corresponding private key.
    ///
    /// Note if this implementation does not support DER keys directly,
    /// `openssl` command is used to convert the certificate.
    fn builder_from_der_key(cert: &[u8], key: &[u8]) -> anyhow::Result<Self::Builder> {
        let _ = (cert, key);
        assert!(!Self::SUPPORTS_DER_KEYS);

        if !Self::SUPPORTS_PKCS12_KEYS {
            Err(crate::CommonError::TlsBuilderFromFromDerOrPkcs12NotSupported(Self::TYPE_DYN))?;
        }

        let (pkcs12, pkcs12pass) = der_to_pkcs12(cert, key)?;

        Self::builder_from_pkcs12(&pkcs12, &pkcs12pass)
    }

    /// New builder from given server key.
    ///
    /// Note if this implementation does not support PKCS #12 keys directly,
    /// `openssl` command is used to convert the certificate.
    fn builder_from_pkcs12(pkcs12: &[u8], passphrase: &str) -> anyhow::Result<Self::Builder> {
        let _ = (pkcs12, passphrase);
        assert!(!Self::SUPPORTS_PKCS12_KEYS);

        if !Self::SUPPORTS_DER_KEYS {
            Err(crate::CommonError::TlsBuilderFromFromDerOrPkcs12NotSupported(Self::TYPE_DYN))?;
        }

        let (cert, key) = pkcs12_to_der(pkcs12, passphrase)?;

        Self::builder_from_der_key(&cert, &key)
    }

    /// Accept a connection.
    ///
    /// This operation returns a future which is resolved when the negotiation is complete,
    /// and the stream is ready to send and receive.
    ///
    /// This version of `accept` returns a stream parameterized by the underlying socket type.
    fn accept_with_socket<S>(
        &self,
        stream: S,
    ) -> BoxFuture<'_, anyhow::Result<TlsStreamWithSocket<S>>>
    where
        S: AsyncSocket + fmt::Debug + Unpin;

    /// Accept a connection.
    ///
    /// This operation returns a future which is resolved when the negotiation is complete,
    /// and the stream is ready to send and receive.
    ///
    /// This version of `accept` returns a stream parameterized by the underlying socket type.
    ///
    /// Practically, [`accept`](Self::accept) is usually enough.
    fn accept_impl_tls_stream<S>(
        &self,
        stream: S,
    ) -> BoxFuture<'_, anyhow::Result<Self::TlsStream>>
    where
        S: AsyncSocket;

    /// Accept a connection.
    ///
    /// This operation returns a future which is resolved when the negotiation is complete,
    /// and the stream is ready to send and receive.
    ///
    /// This version return a stream of the underlying implementation, which
    /// might be useful to obtain some TLS implementation-specific data.
    ///
    /// Practically, [`accept`](Self::accept) is usually enough.
    fn accept<S>(&self, stream: S) -> BoxFuture<'_, anyhow::Result<TlsStream>>
    where
        S: AsyncSocket + fmt::Debug + Unpin,
    {
        BoxFuture::new(async move { self.accept_with_socket(stream).await.map(TlsStream::new) })
    }
}

/// Common part of all connectors. Poor man replacement for HKT.
#[macro_export]
macro_rules! spi_acceptor_common {
    ($stream: ty) => {
        fn accept_with_socket<'a, S>(
            &'a self,
            stream: S,
        ) -> $crate::BoxFuture<'a, anyhow::Result<$crate::TlsStreamWithSocket<S>>>
        where
            S: $crate::AsyncSocket,
        {
            $crate::BoxFuture::new(async move {
                let crate_tls_stream: $stream = self.accept_impl(stream).await?;
                Ok($crate::TlsStreamWithSocket::new(crate_tls_stream))
            })
        }

        fn accept_impl_tls_stream<'a, S>(
            &'a self,
            stream: S,
        ) -> tls_api::BoxFuture<'a, anyhow::Result<Self::TlsStream>>
        where
            S: AsyncSocket,
        {
            $crate::BoxFuture::new(self.accept_impl(tls_api::AsyncSocketBox::new(stream)))
        }
    };
}
