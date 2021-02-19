use crate::AsyncSocket;
use crate::AsyncSocketBox;
use crate::BoxFuture;
use crate::Cert;
use crate::TlsConnector;
use crate::TlsConnectorBuilder;
use crate::TlsStreamBox;
use std::marker;

// Connector type.

/// Similar to [`TlsConnector`], but it is dynamic, does not require type parameter.
///
/// Also it works slower.
pub trait TlsConnectorType {
    /// Constructor a builder dynamically.
    fn builder(&self) -> crate::Result<TlsConnectorBuilderBox>;

    /// It this connector implemented?
    ///
    /// When not implemented, all operations return error.
    fn implemented(&self) -> bool;

    /// Is this implementation ALPN negotation?
    fn supports_alpn(&self) -> bool;

    /// Implementation version.
    fn version(&self) -> &'static str;
}

pub(crate) struct TlsConnectorTypeImpl<C: TlsConnector>(pub marker::PhantomData<C>);

impl<C: TlsConnector> TlsConnectorType for TlsConnectorTypeImpl<C> {
    fn builder(&self) -> crate::Result<TlsConnectorBuilderBox> {
        Ok(TlsConnectorBuilderBox(Box::new(C::builder()?)))
    }

    fn implemented(&self) -> bool {
        C::IMPLEMENTED
    }

    fn supports_alpn(&self) -> bool {
        C::SUPPORTS_ALPN
    }

    fn version(&self) -> &'static str {
        C::version()
    }
}

// Connector builder.

trait TlsConnectorBuilderDyn {
    fn type_dyn(&self) -> &'static dyn TlsConnectorType;

    fn set_alpn_protocols(&mut self, protocols: &[&[u8]]) -> crate::Result<()>;

    fn set_verify_hostname(&mut self, verify: bool) -> crate::Result<()>;

    fn add_root_certificate(&mut self, cert: &Cert) -> crate::Result<()>;

    fn build(self: Box<Self>) -> crate::Result<TlsConnectorBox>;
}

impl<C: TlsConnectorBuilder> TlsConnectorBuilderDyn for C {
    fn type_dyn(&self) -> &'static dyn TlsConnectorType {
        <C::Connector as TlsConnector>::TYPE_DYN
    }

    fn set_alpn_protocols(&mut self, protocols: &[&[u8]]) -> crate::Result<()> {
        self.set_alpn_protocols(protocols)
    }

    fn set_verify_hostname(&mut self, verify: bool) -> crate::Result<()> {
        self.set_verify_hostname(verify)
    }

    fn add_root_certificate(&mut self, cert: &Cert) -> crate::Result<()> {
        self.add_root_certificate(cert)
    }

    fn build(self: Box<Self>) -> crate::Result<TlsConnectorBox> {
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
    pub fn build(self) -> crate::Result<TlsConnectorBox> {
        self.0.build()
    }

    /// Set ALPN-protocols to negotiate.
    ///
    /// This operations fails is not [`TlsConnector::SUPPORTS_ALPN`].
    pub fn set_alpn_protocols(&mut self, protocols: &[&[u8]]) -> crate::Result<()> {
        self.0.set_alpn_protocols(protocols)
    }

    /// Should hostname verification be performed?
    /// Use carefully, it opens the door to MITM attacks.
    pub fn set_verify_hostname(&mut self, verify: bool) -> crate::Result<()> {
        self.0.set_verify_hostname(verify)
    }

    /// Should hostname verification be performed?
    /// Use carefully, it opens the door to MITM attacks.
    pub fn add_root_certificate(&mut self, cert: &Cert) -> crate::Result<()> {
        self.0.add_root_certificate(cert)
    }
}

// Connector.

trait TlsConnectorDyn {
    fn type_dyn(&self) -> &'static dyn TlsConnectorType;

    fn connect<'a>(
        &'a self,
        domain: &'a str,
        stream: AsyncSocketBox,
    ) -> BoxFuture<'a, crate::Result<TlsStreamBox>>;
}

impl<C: TlsConnector> TlsConnectorDyn for C {
    fn type_dyn(&self) -> &'static dyn TlsConnectorType {
        C::TYPE_DYN
    }

    fn connect<'a>(
        &'a self,
        domain: &'a str,
        stream: AsyncSocketBox,
    ) -> BoxFuture<'a, crate::Result<TlsStreamBox>> {
        self.connect_dyn(domain, stream)
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
    ) -> BoxFuture<'a, crate::Result<TlsStreamBox>> {
        self.0.connect(domain, stream)
    }

    /// Connect.
    pub fn connect<'a, S: AsyncSocket>(
        &'a self,
        domain: &'a str,
        stream: S,
    ) -> BoxFuture<'a, crate::Result<TlsStreamBox>> {
        self.connect_dyn(domain, AsyncSocketBox::new(stream))
    }
}
