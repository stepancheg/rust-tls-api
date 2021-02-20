use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;

use crate::assert_send;
use crate::runtime::AsyncRead;
use crate::runtime::AsyncWrite;
use crate::socket::AsyncSocket;
use crate::spi::TlsStreamWithUpcastDyn;
use crate::ImplInfo;
use crate::TlsStream;
use crate::TlsStreamDyn;
use crate::TlsStreamWithSocketDyn;
use std::ops::Deref;
use std::ops::DerefMut;

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

fn _assert_kinds() {
    fn assert_tls_stream_send<S: AsyncSocket>() {
        assert_send::<TlsStreamWithSocket<S>>();
    }
}

impl<S: AsyncSocket> fmt::Debug for TlsStreamWithSocket<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("TlsStream").field(&self.0).finish()
    }
}

impl<S: AsyncSocket> TlsStreamDyn for TlsStreamWithSocket<S> {
    fn get_alpn_protocol(&self) -> crate::Result<Option<Vec<u8>>> {
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

impl<S: AsyncSocket> AsyncRead for TlsStreamWithSocket<S> {
    #[cfg(feature = "runtime-tokio")]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }

    #[cfg(feature = "runtime-async-std")]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl<S: AsyncSocket> AsyncWrite for TlsStreamWithSocket<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    #[cfg(feature = "runtime-tokio")]
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.0).poll_write_vectored(cx, bufs)
    }

    #[cfg(feature = "runtime-tokio")]
    fn is_write_vectored(&self) -> bool {
        self.0.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    #[cfg(feature = "runtime-async-std")]
    fn poll_close(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_close(ctx)
    }

    #[cfg(feature = "runtime-tokio")]
    fn poll_shutdown(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(ctx)
    }
}
