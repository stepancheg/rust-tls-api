use std::fmt;
use std::marker;

use crate::assert_send;
use crate::assert_sync;
use crate::AsyncSocket;
use crate::AsyncSocketBox;
use crate::BoxFuture;
use crate::ImplInfo;
use crate::TlsAcceptor;
use crate::TlsAcceptorBuilder;
use crate::TlsStream;

// Type

/// Similar to [`TlsAcceptor`], but it is dynamic, does not require type parameter.
///
/// This can be obtained with [`TlsAcceptor::TYPE_DYN`].
pub trait TlsAcceptorType: fmt::Debug + fmt::Display + Sync + 'static {
    /// Whether this acceptor type is implemented.
    ///
    /// For example, `tls-api-security-framework` is available on Linux,
    /// but all operations result in error, so `implemented()` returns `false`
    /// for that implementation.
    fn implemented(&self) -> bool;
    /// Whether this implementation supports ALPN negotiation.
    fn supports_alpn(&self) -> bool;
    /// Whether this implementation supports construction of acceptor using
    /// a pair of a DER certificate and file pair.
    fn supports_der_keys(&self) -> bool;
    /// Whether this implementation supports construction of acceptor using
    /// PKCS #12 file.
    fn supports_pkcs12_keys(&self) -> bool;
    /// Unspecified version information about this implementation.
    fn info(&self) -> ImplInfo;

    /// New builder from given server key.
    ///
    /// This operation is guaranteed to fail if not [`TlsAcceptorType::supports_der_keys`].
    fn builder_from_der_key(
        &self,
        cert: &[u8],
        key: &[u8],
    ) -> anyhow::Result<TlsAcceptorBuilderBox>;

    /// New builder from given server key.
    ///
    /// This operation is guaranteed to fail if not [`TlsAcceptorType::supports_pkcs12_keys`].
    fn builder_from_pkcs12(
        &self,
        pkcs12: &[u8],
        passphrase: &str,
    ) -> anyhow::Result<TlsAcceptorBuilderBox>;
}

pub(crate) struct TlsAcceptorTypeImpl<A: TlsAcceptor>(pub marker::PhantomData<A>);

impl<A: TlsAcceptor> fmt::Debug for TlsAcceptorTypeImpl<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&A::info(), f)
    }
}

impl<A: TlsAcceptor> fmt::Display for TlsAcceptorTypeImpl<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&A::info(), f)
    }
}

impl<A: TlsAcceptor> TlsAcceptorType for TlsAcceptorTypeImpl<A> {
    fn implemented(&self) -> bool {
        A::IMPLEMENTED
    }

    fn supports_alpn(&self) -> bool {
        A::SUPPORTS_ALPN
    }

    fn supports_der_keys(&self) -> bool {
        A::SUPPORTS_DER_KEYS
    }

    fn supports_pkcs12_keys(&self) -> bool {
        A::SUPPORTS_PKCS12_KEYS
    }

    fn info(&self) -> ImplInfo {
        A::info()
    }

    fn builder_from_der_key(
        &self,
        cert: &[u8],
        key: &[u8],
    ) -> anyhow::Result<TlsAcceptorBuilderBox> {
        let builder = A::builder_from_der_key(cert, key)?;
        Ok(TlsAcceptorBuilderBox(Box::new(builder)))
    }

    fn builder_from_pkcs12(
        &self,
        pkcs12: &[u8],
        passphrase: &str,
    ) -> anyhow::Result<TlsAcceptorBuilderBox> {
        let builder = A::builder_from_pkcs12(pkcs12, passphrase)?;
        Ok(TlsAcceptorBuilderBox(Box::new(builder)))
    }
}

// Builder

trait TlsAcceptorBuilderDyn: Send + 'static {
    fn type_dyn(&self) -> &'static dyn TlsAcceptorType;

    fn set_alpn_protocols(&mut self, protocols: &[&[u8]]) -> anyhow::Result<()>;

    fn build(self: Box<Self>) -> anyhow::Result<TlsAcceptorBox>;
}

impl<A: TlsAcceptorBuilder> TlsAcceptorBuilderDyn for A {
    fn type_dyn(&self) -> &'static dyn TlsAcceptorType {
        <A::Acceptor as TlsAcceptor>::TYPE_DYN
    }

    fn set_alpn_protocols(&mut self, protocols: &[&[u8]]) -> anyhow::Result<()> {
        (*self).set_alpn_protocols(protocols)
    }

    fn build(self: Box<Self>) -> anyhow::Result<TlsAcceptorBox> {
        Ok(TlsAcceptorBox(Box::new((*self).build()?)))
    }
}

/// Dynamic version of [`TlsAcceptorBuilder`].
pub struct TlsAcceptorBuilderBox(Box<dyn TlsAcceptorBuilderDyn>);

impl TlsAcceptorBuilderBox {
    /// Dynamic (without type parameter) version of the acceptor.
    ///
    /// This function returns an acceptor type, which can be used to constructor acceptors.
    pub fn type_dyn(&self) -> &'static dyn TlsAcceptorType {
        self.0.type_dyn()
    }

    /// Specify ALPN protocols for negotiation.
    ///
    /// This operation returns an error if the implemenation does not support ALPN.
    ///
    /// Whether ALPN is supported, can be queried using [`TlsAcceptor::SUPPORTS_ALPN`].
    pub fn set_alpn_protocols(&mut self, protocols: &[&[u8]]) -> anyhow::Result<()> {
        self.0.set_alpn_protocols(protocols)
    }

    /// Finish the acceptor construction.
    pub fn build(self) -> anyhow::Result<TlsAcceptorBox> {
        self.0.build()
    }
}

// Acceptor

trait TlsAcceptorDyn: Send + Sync + 'static {
    fn type_dyn(&self) -> &'static dyn TlsAcceptorType;

    fn accept<'a>(&'a self, socket: AsyncSocketBox) -> BoxFuture<'a, anyhow::Result<TlsStream>>;
}

impl<A: TlsAcceptor> TlsAcceptorDyn for A {
    fn type_dyn(&self) -> &'static dyn TlsAcceptorType {
        A::TYPE_DYN
    }

    fn accept<'a>(&'a self, socket: AsyncSocketBox) -> BoxFuture<'a, anyhow::Result<TlsStream>> {
        self.accept(socket)
    }
}

/// Dynamic version of [`TlsAcceptor`].
///
/// This can be constructed either with:
/// * [`TlsAcceptor::into_dyn`]
/// * [`TlsAcceptorBuilderBox::build`]
pub struct TlsAcceptorBox(Box<dyn TlsAcceptorDyn>);

impl TlsAcceptorBox {
    pub(crate) fn new<A: TlsAcceptor>(acceptor: A) -> TlsAcceptorBox {
        TlsAcceptorBox(Box::new(acceptor))
    }

    /// Dynamic (without type parameter) version of the acceptor.
    ///
    /// This function returns a connector type, which can be used to constructor connectors.
    pub fn type_dyn(&self) -> &'static dyn TlsAcceptorType {
        self.0.type_dyn()
    }

    /// Accept a connection.
    ///
    /// This operation returns a future which is resolved when the negotiation is complete,
    /// and the stream is ready to send and receive.
    pub fn accept<'a, S: AsyncSocket>(
        &'a self,
        socket: S,
    ) -> BoxFuture<'a, anyhow::Result<TlsStream>> {
        self.0.accept(AsyncSocketBox::new(socket))
    }
}

fn _assert_kinds() {
    assert_send::<TlsAcceptorBuilderBox>();
    assert_send::<TlsAcceptorBox>();
    assert_sync::<TlsAcceptorBox>();
}
