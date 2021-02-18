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
pub(crate) struct TlsStream<S: AsyncRead + AsyncWrite + Unpin + fmt::Debug>(
    pub openssl::ssl::SslStream<AsyncIoAsSyncIo<S>>,
);

impl<S: AsyncRead + AsyncWrite + fmt::Debug + Unpin> AsyncIoAsSyncIoWrapper<S> for TlsStream<S> {
    fn get_mut(&mut self) -> &mut AsyncIoAsSyncIo<S> {
        self.0.get_mut()
    }
}

impl<S: AsyncRead + AsyncWrite + fmt::Debug + Unpin> AsyncRead for TlsStream<S> {
    #[cfg(feature = "runtime-tokio")]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf,
    ) -> Poll<io::Result<()>> {
        self.with_context_sync_to_async_tokio(cx, buf, |stream, buf| stream.0.read(buf))
    }

    #[cfg(feature = "runtime-async-std")]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.with_context_sync_to_async(cx, |stream| stream.0.read(buf))
    }
}

impl<S: AsyncRead + AsyncWrite + fmt::Debug + Unpin> AsyncWrite for TlsStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.with_context_sync_to_async(cx, |stream| stream.0.write(buf))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.with_context_sync_to_async(cx, |stream| stream.0.flush())
    }

    #[cfg(feature = "runtime-tokio")]
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.with_context_sync_to_async(cx, |stream| match stream.0.shutdown() {
            Ok(_) => Ok(()),
            Err(ref e) if e.code() == openssl::ssl::ErrorCode::ZERO_RETURN => Ok(()),
            Err(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
        })
    }

    #[cfg(feature = "runtime-async-std")]
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.with_context_sync_to_async(cx, |stream| match stream.0.shutdown() {
            Ok(_) => Ok(()),
            Err(ref e) if e.code() == openssl::ssl::ErrorCode::ZERO_RETURN => Ok(()),
            Err(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
        })
    }
}

impl<S: AsyncRead + AsyncWrite + fmt::Debug + Unpin + Send + Sync + 'static>
    tls_api::TlsStreamImpl<S> for TlsStream<S>
{
    fn get_mut(&mut self) -> &mut S {
        self.0.get_mut().get_inner_mut()
    }

    fn get_ref(&self) -> &S {
        self.0.get_ref().get_inner_ref()
    }

    #[cfg(has_alpn)]
    fn get_alpn_protocol(&self) -> Option<Vec<u8>> {
        self.0.ssl().selected_alpn_protocol().map(Vec::from)
    }

    #[cfg(not(has_alpn))]
    fn get_alpn_protocol(&self) -> Option<Vec<u8>> {
        None
    }
}
