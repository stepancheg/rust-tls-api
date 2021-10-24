use std::fmt;
use std::ops::Deref;
use std::ops::DerefMut;
use std::pin::Pin;

use crate::assert_kinds::assert_socket;
use crate::assert_send;
use crate::runtime::AsyncRead;
use crate::runtime::AsyncWrite;
use crate::socket::AsyncSocket;
use crate::spi::TlsStreamWithUpcastDyn;
use crate::spi_async_socket_impl_delegate;
use crate::ImplInfo;
use crate::TlsStream;
use crate::TlsStreamDyn;
use crate::TlsStreamWithSocketDyn;

/// TLS stream object returned by `connect_with_socket` and `accept_with_socket` operations.
///
/// Since Rust has no HKT, it is not possible to declare something like
///
/// ```ignore
/// trait TlsConnector {
///     type <S> TlsStream<S> : TlsStreamImpl;
/// }
/// ```
///
/// So `TlsStream` is actually a box to concrete TLS implementation.
/// So each operation perform a virtual call (which is not a big deal for sockets).
///
/// This type is parameterized by socket type, [`TlsStream`] is simpler version of this stream.
pub struct TlsStreamWithSocket<S: AsyncSocket>(pub(crate) Box<dyn TlsStreamWithUpcastDyn<S>>);

fn _assert_kinds<S: AsyncRead + AsyncWrite + fmt::Debug + Unpin + Send + 'static>() {
    assert_send::<TlsStreamWithSocket<S>>();
    assert_socket::<TlsStreamWithSocket<S>>();
}

impl<S: AsyncSocket> fmt::Debug for TlsStreamWithSocket<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("TlsStream").field(&self.0).finish()
    }
}

impl<S: AsyncSocket> TlsStreamDyn for TlsStreamWithSocket<S> {
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

impl<S: AsyncSocket> TlsStreamWithSocketDyn<S> for TlsStreamWithSocket<S> {
    /// Get a reference the underlying TLS-wrapped socket.
    fn get_socket_mut(&mut self) -> &mut S {
        self.0.get_socket_mut()
    }

    /// Get a reference the underlying TLS-wrapped socket.
    fn get_socket_ref(&self) -> &S {
        self.0.get_socket_ref()
    }
}

impl<S: AsyncSocket> TlsStreamWithSocket<S> {
    /// Construct a stream from a stream implementation.
    ///
    /// This function is intended to be used by API implementors, not by users.
    pub fn new<I: TlsStreamWithUpcastDyn<S>>(imp: I) -> TlsStreamWithSocket<S> {
        TlsStreamWithSocket(Box::new(imp))
    }

    /// Convert to a functionally and performance identical TLS stream object
    /// but without socket type parameter.
    pub fn without_type_parameter(self) -> TlsStream {
        TlsStream::new(self)
    }

    fn deref_pin_mut_for_impl_socket(
        self: Pin<&mut Self>,
    ) -> Pin<&mut dyn TlsStreamWithUpcastDyn<S>> {
        Pin::new(&mut *self.get_mut().0)
    }

    fn deref_for_impl_socket(&self) -> &dyn TlsStreamWithUpcastDyn<S> {
        &*self.0
    }
}

impl<S: AsyncSocket> Deref for TlsStreamWithSocket<S> {
    type Target = dyn TlsStreamWithUpcastDyn<S>;

    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

impl<S: AsyncSocket> DerefMut for TlsStreamWithSocket<S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut *self.0
    }
}

spi_async_socket_impl_delegate!(TlsStreamWithSocket<S>);
