use security_framework::secure_transport::SslStream;
use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;
use tls_api::async_as_sync::AsyncIoAsSyncIo;
use tls_api::async_as_sync::AsyncIoAsSyncIoWrapper;
use tls_api::runtime::AsyncRead;
use tls_api::runtime::AsyncWrite;
use tls_api::TlsStreamImpl;

#[derive(Debug)]
pub(crate) struct TlsStream<S: AsyncRead + AsyncWrite + fmt::Debug + Unpin>(
    pub SslStream<AsyncIoAsSyncIo<S>>,
);

impl<S: Unpin + fmt::Debug + AsyncRead + AsyncWrite + Unpin + Sync + Send> AsyncIoAsSyncIoWrapper<S>
    for TlsStream<S>
{
    fn get_mut(&mut self) -> &mut AsyncIoAsSyncIo<S> {
        self.0.get_mut()
    }
}

impl<S> TlsStreamImpl<S> for TlsStream<S>
where
    S: AsyncRead + AsyncWrite + fmt::Debug + Unpin + Sync + Send + 'static,
{
    fn get_alpn_protocol(&self) -> Option<Vec<u8>> {
        unimplemented!()
    }

    fn get_mut(&mut self) -> &mut S {
        self.0.get_mut().get_inner_mut()
    }

    fn get_ref(&self) -> &S {
        self.0.get_ref().get_inner_ref()
    }
}

impl<S> AsyncRead for TlsStream<S>
where
    S: AsyncRead + AsyncWrite + fmt::Debug + Unpin,
{
    #[cfg(feature = "runtime-tokio")]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf,
    ) -> Poll<io::Result<()>> {
        unimplemented!()
    }

    #[cfg(feature = "runtime-async-std")]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        unimplemented!()
    }
}

impl<S> AsyncWrite for TlsStream<S>
where
    S: AsyncRead + AsyncWrite + fmt::Debug + Unpin + Send + Sync,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        unimplemented!()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        unimplemented!()
    }

    #[cfg(feature = "runtime-tokio")]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut()
            .with_context_sync_to_async(cx, |stream| stream.0.close())
    }

    #[cfg(feature = "runtime-async-std")]
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut()
            .with_context_sync_to_async(cx, |stream| stream.0.close())
    }
}
