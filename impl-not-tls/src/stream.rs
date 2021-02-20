use std::io;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;
use tls_api::runtime::AsyncRead;
use tls_api::runtime::AsyncWrite;
use tls_api::spi::TlsStreamDyn;
use tls_api::spi::TlsStreamImpl;
use tls_api::AsyncSocket;
use tls_api::ImplInfo;

#[derive(Debug)]
pub(crate) struct TlsStream<A>(pub A)
where
    A: AsyncSocket;

impl<A: AsyncSocket> TlsStream<A> {
    fn get_inner(self: Pin<&mut Self>) -> Pin<&mut A> {
        Pin::new(&mut self.get_mut().0)
    }
}

impl<A: AsyncSocket> TlsStreamDyn for TlsStream<A> {
    fn impl_info(&self) -> ImplInfo {
        crate::info()
    }

    fn get_alpn_protocol(&self) -> tls_api::Result<Option<Vec<u8>>> {
        Err(crate::Error::Alpn.into())
    }
}

impl<A: AsyncSocket> TlsStreamImpl<A> for TlsStream<A> {
    fn upcast_box(self: Box<Self>) -> Box<dyn TlsStreamDyn> {
        self
    }

    fn get_socket_mut(&mut self) -> &mut A {
        &mut self.0
    }

    fn get_socket_ref(&self) -> &A {
        &self.0
    }
}

impl<A: AsyncSocket> AsyncRead for TlsStream<A> {
    #[cfg(feature = "runtime-tokio")]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf,
    ) -> Poll<io::Result<()>> {
        self.get_inner().poll_read(cx, buf)
    }

    #[cfg(feature = "runtime-async-std")]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.get_inner().poll_read(cx, buf)
    }
}

impl<A: AsyncSocket> AsyncWrite for TlsStream<A> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_inner().poll_write(cx, buf)
    }

    #[cfg(feature = "runtime-async-std")]
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.get_inner().poll_write_vectored(cx, bufs)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_inner().poll_flush(cx)
    }

    #[cfg(feature = "runtime-tokio")]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_inner().poll_shutdown(cx)
    }

    #[cfg(feature = "runtime-async-std")]
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_inner().poll_close(cx)
    }
}
