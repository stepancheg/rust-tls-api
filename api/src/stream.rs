use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;

use crate::assert_send;
use crate::runtime::AsyncRead;
use crate::runtime::AsyncWrite;
use crate::socket::AsyncSocket;
use crate::spi::TlsStreamImpl;
use crate::ImplInfo;
use crate::TlsStreamBox;
use std::ops::Deref;
use std::ops::DerefMut;

/// TLS stream object returned by `connect` and `accept` operations.
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
pub struct TlsStream<S: AsyncSocket>(pub(crate) Box<dyn TlsStreamImpl<S>>);

fn _assert_kinds() {
    fn assert_tls_stream_send<S: AsyncSocket>() {
        assert_send::<TlsStream<S>>();
    }
}

impl<S: AsyncSocket> fmt::Debug for TlsStream<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("TlsStream").field(&self.0).finish()
    }
}

impl<S: AsyncSocket> TlsStream<S> {
    /// Construct a stream from a stream implementation.
    ///
    /// This function is intended to be used by API implementors, not by users.
    pub fn new<I: TlsStreamImpl<S>>(imp: I) -> TlsStream<S> {
        TlsStream(Box::new(imp))
    }

    /// Convert to a functionally and performance identical TLS stream object
    /// but without socket type parameter.
    pub fn without_type_parameter(self) -> TlsStreamBox {
        TlsStreamBox::new(self)
    }

    /// Implementation info for this stream (e. g. which crate provides it).
    pub fn impl_info(&self) -> ImplInfo {
        self.0.impl_info()
    }

    /// Get a reference the underlying TLS-wrapped socket.
    pub fn get_socket_mut(&mut self) -> &mut S {
        self.0.get_socket_mut()
    }

    /// Get a reference the underlying TLS-wrapped socket.
    pub fn get_socket_ref(&self) -> &S {
        self.0.get_socket_ref()
    }

    /// Get negotiated ALPN protocol.
    ///
    /// Return `Ok(None)` is there was no protocol negotiated.
    /// In particular, `Ok(None)` is returned when the implementation
    /// does not support ALPN.
    pub fn get_alpn_protocol(&self) -> crate::Result<Option<Vec<u8>>> {
        self.0.get_alpn_protocol()
    }
}

impl<S: AsyncSocket> Deref for TlsStream<S> {
    type Target = dyn TlsStreamImpl<S>;

    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

impl<S: AsyncSocket> DerefMut for TlsStream<S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut *self.0
    }
}

impl<S: AsyncSocket> AsyncRead for TlsStream<S> {
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

impl<S: AsyncSocket> AsyncWrite for TlsStream<S> {
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
