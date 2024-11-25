use std::fmt;
use std::marker;

use crate::assert_send;
use crate::assert_sync;
use crate::AsyncSocket;
use crate::AsyncSocketBox;
use crate::BoxFuture;
use crate::ImplInfo;
use crate::TlsConnector;
use crate::TlsConnectorBuilder;
use crate::TlsStream;

// Connector type.

/// Similar to [`TlsConnector`], but it is dynamic, does not require type parameter.
///
/// This can be obtained with [`TlsConnector::TYPE_DYN`].
pub trait TlsConnectorType: fmt::Display + fmt::Debug + 'static {
    /// Constructor a builder dynamically.
    fn builder(&self) -> anyhow::Result<TlsConnectorBuilderBox>;

    /// It this connector implemented?
    ///
    /// When not implemented, all operations return error.
    ///
    /// For example, `tls-api-security-framework` is available on Linux,
    /// but all operations result in error, so `implemented()` returns `false`
    /// for that implementation.
    fn implemented(&self) -> bool;

    /// Is this implementation ALPN negotation?
    fn supports_alpn(&self) -> bool;

    /// Implementation version.
    fn info(&self) -> ImplInfo;
}

pub(crate) struct TlsConnectorTypeImpl<C: TlsConnector>(pub marker::PhantomData<C>);

impl<A: TlsConnector> fmt::Debug for TlsConnectorTypeImpl<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&A::info(), f)
    }
}

impl<A: TlsConnector> fmt::Display for TlsConnectorTypeImpl<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&A::info(), f)
    }
}

impl<C: TlsConnector> TlsConnectorType for TlsConnectorTypeImpl<C> {
    fn builder(&self) -> anyhow::Result<TlsConnectorBuilderBox> {
        Ok(TlsConnectorBuilderBox(Box::new(C::builder()?)))
    }

    fn implemented(&self) -> bool {
        C::IMPLEMENTED
    }

    fn supports_alpn(&self) -> bool {
        C::SUPPORTS_ALPN
    }

    fn info(&self) -> ImplInfo {
        C::info()
    }
}

// Connector builder.

trait TlsConnectorBuilderDyn: Send + 'static {
    fn set_alpn_protocols(&mut self, protocols: &[&[u8]]) -> anyhow::Result<()>;

    fn set_verify_hostname(&mut self, verify: bool) -> anyhow::Result<()>;

    fn add_root_certificate(&mut self, cert: &[u8]) -> anyhow::Result<()>;

    fn build(self: Box<Self>) -> anyhow::Result<TlsConnectorBox>;
}

impl<C: TlsConnectorBuilder> TlsConnectorBuilderDyn for C {
    fn set_alpn_protocols(&mut self, protocols: &[&[u8]]) -> anyhow::Result<()> {
        self.set_alpn_protocols(protocols)
    }

    fn set_verify_hostname(&mut self, verify: bool) -> anyhow::Result<()> {
        self.set_verify_hostname(verify)
    }

    fn add_root_certificate(&mut self, cert: &[u8]) -> anyhow::Result<()> {
        self.add_root_certificate(cert)
    }

    fn build(self: Box<Self>) -> anyhow::Result<TlsConnectorBox> {
        let connector = (*self).build()?;
        Ok(TlsConnectorBox(Box::new(connector)))
    }
}

/// [`TlsConnector`] without type parameter.
///
/// Implementation can be switched without parameterizing every function.
pub struct TlsConnectorBuilderBox(Box<dyn TlsConnectorBuilderDyn>);

impl TlsConnectorBuilderBox {
    /// Build a connector.
    pub fn build(self) -> anyhow::Result<TlsConnectorBox> {
        self.0.build()
    }

    /// Set ALPN-protocols to negotiate.
    ///
    /// This operations fails is not [`TlsConnector::SUPPORTS_ALPN`].
    pub fn set_alpn_protocols(&mut self, protocols: &[&[u8]]) -> anyhow::Result<()> {
        self.0.set_alpn_protocols(protocols)
    }

    /// Should hostname verification be performed?
    /// Use carefully, it opens the door to MITM attacks.
    pub fn set_verify_hostname(&mut self, verify: bool) -> anyhow::Result<()> {
        self.0.set_verify_hostname(verify)
    }

    /// Add trusted certificate (e. g. CA).
    pub fn add_root_certificate(&mut self, cert: &[u8]) -> anyhow::Result<()> {
        self.0.add_root_certificate(cert)
    }
}

// Connector.

trait TlsConnectorDyn: Send + Sync + 'static {
    fn connect<'a>(
        &'a self,
        domain: &'a str,
        stream: AsyncSocketBox,
    ) -> BoxFuture<'a, anyhow::Result<TlsStream>>;
}

impl<C: TlsConnector> TlsConnectorDyn for C {
    fn connect<'a>(
        &'a self,
        domain: &'a str,
        stream: AsyncSocketBox,
    ) -> BoxFuture<'a, anyhow::Result<TlsStream>> {
        self.connect(domain, stream)
    }
}

/// Configured connector. This is a dynamic version of [`TlsConnector`].
///
/// This can be constructed either with:
/// * [`TlsConnector::into_dyn`]
/// * [`TlsConnectorBuilderBox::build`]
pub struct TlsConnectorBox(Box<dyn TlsConnectorDyn>);

impl TlsConnectorBox {
    pub(crate) fn new<C: TlsConnector>(connector: C) -> TlsConnectorBox {
        TlsConnectorBox(Box::new(connector))
    }
}

impl TlsConnectorBox {
    /// Connect.
    pub fn connect_dyn<'a>(
        &'a self,
        domain: &'a str,
        stream: AsyncSocketBox,
    ) -> BoxFuture<'a, anyhow::Result<TlsStream>> {
        self.0.connect(domain, stream)
    }

    /// Connect.
    pub fn connect<'a, S: AsyncSocket>(
        &'a self,
        domain: &'a str,
        stream: S,
    ) -> BoxFuture<'a, anyhow::Result<TlsStream>> {
        self.connect_dyn(domain, AsyncSocketBox::new(stream))
    }
}

fn _assert_kinds() {
    assert_send::<TlsConnectorBuilderBox>();
    assert_send::<TlsConnectorBox>();
    assert_sync::<TlsConnectorBox>();
}
