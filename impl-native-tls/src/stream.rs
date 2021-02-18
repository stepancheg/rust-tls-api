use std::fmt;
use std::io;
use std::io::Read;
use std::io::Write;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;
use tls_api::async_as_sync::AsyncIoAsSyncIo;
use tls_api::async_as_sync::AsyncIoAsSyncIoWrapper;
use tls_api::runtime::AsyncRead;
use tls_api::runtime::AsyncWrite;

#[derive(Debug)]
pub(crate) struct TlsStream<S: AsyncRead + AsyncWrite + fmt::Debug + Unpin>(
    pub native_tls::TlsStream<AsyncIoAsSyncIo<S>>,
);

impl<S: Unpin + fmt::Debug + AsyncRead + AsyncWrite + Unpin + Sync + Send> AsyncIoAsSyncIoWrapper<S>
    for TlsStream<S>
{
    fn get_mut(&mut self) -> &mut AsyncIoAsSyncIo<S> {
        self.0.get_mut()
    }
}

impl<S: Unpin + fmt::Debug + AsyncRead + AsyncWrite + Sync + Send> AsyncWrite for TlsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut()
            .with_context_sync_to_async(cx, |stream| stream.0.write(buf))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut()
            .with_context_sync_to_async(cx, |stream| stream.0.flush())
    }

    #[cfg(feature = "runtime-tokio")]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut()
            .with_context_sync_to_async(cx, |stream| stream.0.shutdown())
    }

    #[cfg(feature = "runtime-async-std")]
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut()
            .with_context_sync_to_async(cx, |stream| stream.0.shutdown())
    }
}

impl<S: Unpin + fmt::Debug + AsyncRead + AsyncWrite + Sync + Send> AsyncRead for TlsStream<S> {
    #[cfg(feature = "runtime-tokio")]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf,
    ) -> Poll<io::Result<()>> {
        self.get_mut()
            .with_context_sync_to_async_tokio(cx, buf, |stream, buf| stream.0.read(buf))
    }

    #[cfg(feature = "runtime-async-std")]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut()
            .with_context_sync_to_async(cx, |stream| stream.0.read(buf))
    }
}

impl<S: Unpin + fmt::Debug + AsyncRead + AsyncWrite + Sync + Send + 'static>
    tls_api::TlsStreamImpl<S> for TlsStream<S>
{
    fn get_alpn_protocol(&self) -> Option<Vec<u8>> {
        None
    }

    fn get_mut(&mut self) -> &mut S {
        self.0.get_mut().get_inner_mut()
    }

    fn get_ref(&self) -> &S {
        self.0.get_ref().get_inner_ref()
    }
}
