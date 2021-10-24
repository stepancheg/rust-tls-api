#![allow(dead_code)]

use crate::ImplInfo;
use std::marker;
use std::pin::Pin;
use tls_api::spi::TlsStreamWithUpcastDyn;
use tls_api::spi_async_socket_impl_delegate;
use tls_api::AsyncSocket;
use tls_api::TlsStreamDyn;
use tls_api::TlsStreamWithSocketDyn;
use void::Void;

/// Non-instantiatable stream.
#[derive(Debug)]
pub struct TlsStream<S: AsyncSocket>(Void, marker::PhantomData<S>);

impl<S: AsyncSocket> TlsStream<S> {
    fn deref_pin_mut_for_impl_socket(self: Pin<&mut Self>) -> Pin<&mut dyn AsyncSocket> {
        void::unreachable(self.get_mut().0)
    }

    fn deref_for_impl_socket(&self) -> Pin<&mut dyn AsyncSocket> {
        void::unreachable(self.0)
    }
}

impl<S: AsyncSocket> TlsStreamDyn for TlsStream<S> {
    fn get_alpn_protocol(&self) -> anyhow::Result<Option<Vec<u8>>> {
        void::unreachable(self.0)
    }

    fn impl_info(&self) -> ImplInfo {
        void::unreachable(self.0)
    }

    fn get_socket_dyn_mut(&mut self) -> &mut dyn AsyncSocket {
        void::unreachable(self.0)
    }

    fn get_socket_dyn_ref(&self) -> &dyn AsyncSocket {
        void::unreachable(self.0)
    }
}

impl<S: AsyncSocket> TlsStreamWithSocketDyn<S> for TlsStream<S> {
    fn get_socket_mut(&mut self) -> &mut S {
        void::unreachable(self.0)
    }

    fn get_socket_ref(&self) -> &S {
        void::unreachable(self.0)
    }
}

impl<S: AsyncSocket> TlsStreamWithUpcastDyn<S> for TlsStream<S> {
    fn upcast_box(self: Box<Self>) -> Box<dyn TlsStreamDyn> {
        self
    }
}

spi_async_socket_impl_delegate!(TlsStream<S>);
