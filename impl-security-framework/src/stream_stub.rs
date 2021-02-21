#![allow(dead_code)]

use std::pin::Pin;
use tls_api::spi_async_socket_impl_delegate;
use tls_api::AsyncSocket;
use tls_api::ImplInfo;
use tls_api::TlsStreamDyn;
use void::Void;

#[derive(Debug)]
pub struct TlsStream(Void);

impl TlsStream {
    fn deref_pin_mut_for_impl_socket(self: Pin<&mut Self>) -> Pin<&mut dyn AsyncSocket> {
        void::unreachable(self.get_mut().0)
    }

    fn deref_for_impl_socket(&self) -> Pin<&mut dyn AsyncSocket> {
        void::unreachable(self.0)
    }
}

impl TlsStreamDyn for TlsStream {
    fn get_alpn_protocol(&self) -> tls_api::Result<Option<Vec<u8>>> {
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

spi_async_socket_impl_delegate!(TlsStream);
