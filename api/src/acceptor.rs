use crate::acceptor_box::TlsAcceptorType;
use crate::acceptor_box::TlsAcceptorTypeImpl;
use crate::socket::AsyncSocket;
use crate::stream_box::TlsStreamBox;
use crate::BoxFuture;
use crate::Cert;
use crate::Pkcs12AndPassword;
use crate::PrivateKey;
use crate::TlsStream;
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
    fn set_alpn_protocols(&mut self, protocols: &[&[u8]]) -> crate::Result<()>;

    /// Get the underlying builder.
    fn underlying_mut(&mut self) -> &mut Self::Underlying;

    /// Finish the acceptor construction.
    fn build(self) -> crate::Result<Self::Acceptor>;
}

/// A builder for server-side TLS connections.
pub trait TlsAcceptor: Sized + Sync + Send + 'static {
    /// Type of the builder for this acceptor.
    type Builder: TlsAcceptorBuilder<Acceptor = Self>;

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
    /// This function returns a connector type, which can be used to constructor connectors.
    const TYPE_DYN: &'static dyn TlsAcceptorType =
        &TlsAcceptorTypeImpl::<Self>(marker::PhantomData);

    /// Unspecified version information about this implementation.
    fn version() -> &'static str;

    /// New builder from given server key.
    ///
    /// This operation is guaranteed to fail if not [`TlsAcceptor::SUPPORTS_DER_KEYS`].
    fn builder_from_der_key(cert: &Cert, key: &PrivateKey) -> crate::Result<Self::Builder> {
        let _ = (cert, key);
        assert!(!Self::SUPPORTS_DER_KEYS);
        Err(crate::Error::new_other(
            "construction from DER key is not implemented",
        ))
    }

    /// New builder from given server key.
    ///
    /// This operation is guaranteed to fail if not [`TlsAcceptor::SUPPORTS_PKCS12_KEYS`].
    fn builder_from_pkcs12(pkcs12: &Pkcs12AndPassword) -> crate::Result<Self::Builder> {
        let _ = pkcs12;
        assert!(!Self::SUPPORTS_PKCS12_KEYS);
        Err(crate::Error::new_other(
            "construction from PKCS12 is not implemented",
        ))
    }

    /// Accept a connection.
    ///
    /// This operation returns a future which is resolved when the negotiation is complete,
    /// and the stream is ready to send and receive.
    fn accept<'a, S>(&'a self, stream: S) -> BoxFuture<'a, crate::Result<TlsStream<S>>>
    where
        S: AsyncSocket + fmt::Debug + Unpin;

    /// More dynamic version of [`TlsAcceptor::accept`]: returned stream object
    /// does not have a type parameter.
    fn accept_dyn<'a, S>(&'a self, stream: S) -> BoxFuture<'a, crate::Result<TlsStreamBox>>
    where
        S: AsyncSocket + fmt::Debug + Unpin,
    {
        BoxFuture::new(async move { self.accept(stream).await.map(TlsStreamBox::new) })
    }
}
