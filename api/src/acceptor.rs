use crate::acceptor_box::TlsAcceptorType;
use crate::acceptor_box::TlsAcceptorTypeImpl;
use crate::openssl::der_to_pkcs12;
use crate::openssl::pkcs12_to_der;
use crate::socket::AsyncSocket;
use crate::stream_box::TlsStreamBox;
use crate::BoxFuture;
use crate::ImplInfo;
use crate::TlsAcceptorBox;
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
    fn builder_from_der_key(cert: &[u8], key: &[u8]) -> crate::Result<Self::Builder> {
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
    fn builder_from_pkcs12(pkcs12: &[u8], passphrase: &str) -> crate::Result<Self::Builder> {
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
