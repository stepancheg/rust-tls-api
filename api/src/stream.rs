use crate::assert_kinds::assert_socket;
use crate::assert_send;
use crate::socket::AsyncSocket;
use crate::spi_async_socket_impl_delegate;
use crate::ImplInfo;
use crate::TlsStreamDyn;
use crate::TlsStreamWithSocket;
use std::pin::Pin;

/// Similar to [`TlsStreamWithSocket`], but without a socket type parameter.
#[derive(Debug)]
pub struct TlsStream(Box<dyn TlsStreamDyn>);

fn _assert_kinds() {
    assert_send::<TlsStream>();
    assert_socket::<TlsStream>();
}

impl TlsStream {
    /// Wrap.
    pub fn new<S: AsyncSocket>(stream: TlsStreamWithSocket<S>) -> TlsStream {
        TlsStream(stream.0.upcast_box())
    }

    fn deref_pin_mut_for_impl_socket(self: Pin<&mut Self>) -> Pin<&mut dyn AsyncSocket> {
        Pin::new(&mut self.get_mut().0)
    }

    #[allow(dead_code)]
    fn deref_for_impl_socket(&self) -> &dyn AsyncSocket {
        &self.0
    }
}

impl TlsStreamDyn for TlsStream {
    fn get_alpn_protocol(&self) -> anyhow::Result<Option<Vec<u8>>> {
        self.0.get_alpn_protocol()
    }

    fn impl_info(&self) -> ImplInfo {
        self.0.impl_info()
    }

    fn get_socket_dyn_mut(&mut self) -> &mut dyn AsyncSocket {
        self.0.get_socket_dyn_mut()
    }

    fn get_socket_dyn_ref(&self) -> &dyn AsyncSocket {
        self.0.get_socket_dyn_ref()
    }
}

spi_async_socket_impl_delegate!(TlsStream);
