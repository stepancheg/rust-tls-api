use crate::assert_send;
use crate::runtime::AsyncRead;
use crate::runtime::AsyncWrite;
use crate::socket::AsyncSocket;
use crate::ImplInfo;
use crate::TlsStreamDyn;
use crate::TlsStreamWithSocket;
use std::io;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;

/// Similar to [`TlsStreamWithSocket`], but without a socket type parameter.
#[derive(Debug)]
pub struct TlsStream(Box<dyn TlsStreamDyn>);

fn _assert_kinds() {
    assert_send::<TlsStream>();
}

impl TlsStream {
    /// Wrap.
    pub fn new<S: AsyncSocket>(stream: TlsStreamWithSocket<S>) -> TlsStream {
        TlsStream(stream.0.upcast_box())
    }
}

impl TlsStreamDyn for TlsStream {
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

impl AsyncRead for TlsStream {
    #[cfg(feature = "runtime-tokio")]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }

    #[cfg(feature = "runtime-async-std")]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl AsyncWrite for TlsStream {
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
