// Incomplete.
#![doc(hidden)]

use crate::AsyncSocket;
use crate::AsyncSocketBox;
use crate::BoxFuture;
use crate::TlsConnector;
use crate::TlsConnectorBuilder;
use crate::TlsStreamBox;
use std::marker;

/// Similar to [`TlsConnector`], but it is dynamic, does not require type parameter.
///
/// Also it works slower.
pub trait TlsConnectorTypeDyn {
    /// Constructor a builder dynamically.
    fn builder(&self) -> crate::Result<TlsConnectorBuilderDyn>;
}

trait TlsConnectorBuilderDynImpl {
    fn build(self: Box<Self>) -> crate::Result<TlsConnectorDyn>;
}

impl<C: TlsConnectorBuilder> TlsConnectorBuilderDynImpl for C {
    fn build(self: Box<Self>) -> crate::Result<TlsConnectorDyn> {
        let connector = (*self).build()?;
        Ok(TlsConnectorDyn(Box::new(connector)))
    }
}

pub(crate) struct TlsConnectorTypeImpl<C: TlsConnector>(pub marker::PhantomData<C>);

impl<C: TlsConnector> TlsConnectorTypeDyn for TlsConnectorTypeImpl<C> {
    fn builder(&self) -> crate::Result<TlsConnectorBuilderDyn> {
        Ok(TlsConnectorBuilderDyn(Box::new(C::builder()?)))
    }
}

pub struct TlsConnectorBuilderDyn(Box<dyn TlsConnectorBuilderDynImpl>);

impl TlsConnectorBuilderDyn {
    pub fn build(self) -> crate::Result<TlsConnectorDyn> {
        self.0.build()
    }
}

trait TlsConnectorDynImpl {
    fn connect<'a>(
        &'a self,
        domain: &'a str,
        stream: AsyncSocketBox,
    ) -> BoxFuture<'a, crate::Result<TlsStreamBox>>;
}

impl<C: TlsConnector> TlsConnectorDynImpl for C {
    fn connect<'a>(
        &'a self,
        domain: &'a str,
        stream: AsyncSocketBox,
    ) -> BoxFuture<'a, crate::Result<TlsStreamBox>> {
        self.connect_dyn(domain, stream)
    }
}

pub struct TlsConnectorDyn(Box<dyn TlsConnectorDynImpl>);

impl TlsConnectorDyn {
    pub fn connect<'a, S: AsyncSocket>(
        &'a self,
        domain: &'a str,
        stream: S,
    ) -> BoxFuture<'a, crate::Result<TlsStreamBox>> {
        self.0.connect(domain, AsyncSocketBox::new(stream))
    }
}
