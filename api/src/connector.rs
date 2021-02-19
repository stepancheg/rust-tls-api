use crate::socket::AsyncSocket;
use crate::stream_box::TlsStreamBox;
use crate::BoxFuture;
use crate::TlsStream;
use crate::X509Cert;

/// A builder for `TlsConnector`s.
pub trait TlsConnectorBuilder: Sized + Sync + Send + 'static {
    /// Result of connector to be build.
    type Connector: TlsConnector;

    /// Type of the underlying builder.
    type Underlying;

    /// Get the underlying builder.
    ///
    /// Can be used to fine-tuning the setup not supported by API
    /// common to all implementations.
    fn underlying_mut(&mut self) -> &mut Self::Underlying;

    /// Set ALPN-protocols to negotiate.
    ///
    /// This operations fails is not [`TlsConnector::SUPPORTS_ALPN`].
    fn set_alpn_protocols(&mut self, protocols: &[&[u8]]) -> crate::Result<()>;

    /// Should hostname verification be performed?
    /// Use carefully, it opens the door to MITM attacks.
    fn set_verify_hostname(&mut self, verify: bool) -> crate::Result<()>;

    /// Add trusted root certificate. By default connector supports only
    /// global trusted root.
    fn add_root_certificate(&mut self, cert: &X509Cert) -> crate::Result<&mut Self>;

    /// Finish the acceptor constructon.
    fn build(self) -> crate::Result<Self::Connector>;
}

/// A builder for client-side TLS connections.
pub trait TlsConnector: Sized + Sync + Send + 'static {
    /// Type of the builder for this connector.
    type Builder: TlsConnectorBuilder<Connector = Self>;

    /// Is it implemented? When `false` all operations return an error.
    ///
    /// At the moment of writing, there are two crates which return `false` here:
    /// * `tls-api-stub`, dummy implementation is not meant to be instantiated
    /// * `tls-api-security-framework`, `true` only on macOS and iOS, false elsewhere
    const IMPLEMENTED: bool;

    /// Whether this implementation supports ALPN negotiation.
    const SUPPORTS_ALPN: bool;

    /// Unspecified version of the underlying implementation.
    fn version() -> &'static str;

    /// New builder for the acceptor.
    fn builder() -> crate::Result<Self::Builder>;

    /// Connect.
    ///
    /// Returned future is resolved when the TLS-negotiation completes,
    /// and the stream is ready to send and receive.
    fn connect<'a, S>(
        &'a self,
        domain: &'a str,
        stream: S,
    ) -> BoxFuture<'a, crate::Result<TlsStream<S>>>
    where
        S: AsyncSocket;

    /// More dynamic version of [`TlsConnector::connect`]: returned type
    /// does not have a type parameter.
    fn connect_dyn<'a, S>(
        &'a self,
        domain: &'a str,
        stream: S,
    ) -> BoxFuture<'a, crate::Result<TlsStreamBox>>
    where
        S: AsyncSocket,
    {
        BoxFuture::new(async move { self.connect(domain, stream).await.map(TlsStreamBox::new) })
    }
}
