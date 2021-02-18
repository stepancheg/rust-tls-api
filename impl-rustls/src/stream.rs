use rustls::StreamOwned;
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

pub(crate) struct TlsStream<S, T>
where
    S: AsyncRead + AsyncWrite + fmt::Debug + Unpin + Send + 'static,
    T: rustls::Session + Unpin + 'static,
{
    pub stream: StreamOwned<T, AsyncIoAsSyncIo<S>>,
}

// TODO: do not require Sync from TlsStream
unsafe impl<S, T> Sync for TlsStream<S, T>
where
    S: AsyncRead + AsyncWrite + fmt::Debug + Unpin + Send + 'static,
    T: rustls::Session + Unpin + 'static,
{
}

// TlsStream

impl<S, T> fmt::Debug for TlsStream<S, T>
where
    S: AsyncRead + AsyncWrite + fmt::Debug + Unpin + Send + 'static,
    T: rustls::Session + Unpin + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("TlsStream")
            .field("stream", &self.stream.sock)
            .field("session", &"...")
            .finish()
    }
}

impl<S, T> AsyncIoAsSyncIoWrapper<S> for TlsStream<S, T>
where
    S: AsyncRead + AsyncWrite + fmt::Debug + Unpin + Send + 'static,
    T: rustls::Session + Unpin + 'static,
{
    fn get_mut(&mut self) -> &mut AsyncIoAsSyncIo<S> {
        &mut self.stream.sock
    }
}

impl<S, T> AsyncRead for TlsStream<S, T>
where
    S: AsyncRead + AsyncWrite + fmt::Debug + Unpin + Send + 'static,
    T: rustls::Session + Unpin + 'static,
{
    #[cfg(feature = "runtime-tokio")]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf,
    ) -> Poll<io::Result<()>> {
        self.with_context_sync_to_async_tokio(cx, buf, |s, buf| s.stream.read(buf))
    }

    #[cfg(feature = "runtime-async-std")]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.with_context_sync_to_async(cx, |stream| {
            rustls::Stream {
                sock: &mut stream.stream,
                sess: &mut stream.session,
            }
            .read(buf)
        })
    }
}

impl<S, T> AsyncWrite for TlsStream<S, T>
where
    S: AsyncRead + AsyncWrite + fmt::Debug + Unpin + Send + 'static,
    T: rustls::Session + Unpin + 'static,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.with_context_sync_to_async(cx, |stream| stream.stream.write(buf))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.with_context_sync_to_async(cx, |stream| stream.stream.flush())
    }

    #[cfg(feature = "runtime-tokio")]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }

    #[cfg(feature = "runtime-async-std")]
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

impl<S, T> tls_api::TlsStreamImpl<S> for TlsStream<S, T>
where
    S: AsyncRead + AsyncWrite + fmt::Debug + Unpin + Send + 'static,
    T: rustls::Session + Unpin + 'static,
{
    fn get_alpn_protocol(&self) -> Option<Vec<u8>> {
        self.stream.sess.get_alpn_protocol().map(Vec::from)
    }

    fn get_mut(&mut self) -> &mut S {
        self.stream.sock.get_inner_mut()
    }

    fn get_ref(&self) -> &S {
        self.stream.sock.get_inner_ref()
    }
}
