//! Handshake future

use std::future::Future;
use std::mem;
use std::pin::Pin;
use std::result;
use std::task::Context;
use std::task::Poll;

use tls_api::async_as_sync::AsyncIoAsSyncIo;
use tls_api::spi::save_context;
use tls_api::AsyncSocket;

use crate::stream::OpenSSLStream;

pub(crate) enum HandshakeFuture<F, S: Unpin> {
    Initial(F, AsyncIoAsSyncIo<S>),
    MidHandshake(openssl::ssl::MidHandshakeSslStream<AsyncIoAsSyncIo<S>>),
    Done,
}

impl<F, S> Future for HandshakeFuture<F, S>
where
    S: AsyncSocket,
    F: FnOnce(
        AsyncIoAsSyncIo<S>,
    ) -> result::Result<
        openssl::ssl::SslStream<AsyncIoAsSyncIo<S>>,
        openssl::ssl::HandshakeError<AsyncIoAsSyncIo<S>>,
    >,
    Self: Unpin,
{
    type Output = anyhow::Result<crate::TlsStream<S>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        save_context(cx, || {
            let self_mut = self.get_mut();
            match mem::replace(self_mut, HandshakeFuture::Done) {
                HandshakeFuture::Initial(f, stream) => match f(stream) {
                    Ok(stream) => {
                        return Poll::Ready(Ok(crate::TlsStream::new(OpenSSLStream(stream))));
                    }
                    Err(openssl::ssl::HandshakeError::WouldBlock(mid)) => {
                        *self_mut = HandshakeFuture::MidHandshake(mid);
                        return Poll::Pending;
                    }
                    Err(openssl::ssl::HandshakeError::Failure(e)) => {
                        return Poll::Ready(Err(anyhow::Error::new(e.into_error())))
                    }
                    Err(openssl::ssl::HandshakeError::SetupFailure(e)) => {
                        return Poll::Ready(Err(anyhow::Error::new(e)))
                    }
                },
                HandshakeFuture::MidHandshake(stream) => match stream.handshake() {
                    Ok(stream) => {
                        return Poll::Ready(Ok(crate::TlsStream::new(OpenSSLStream(stream))));
                    }
                    Err(openssl::ssl::HandshakeError::WouldBlock(mid)) => {
                        *self_mut = HandshakeFuture::MidHandshake(mid);
                        return Poll::Pending;
                    }
                    Err(openssl::ssl::HandshakeError::Failure(e)) => {
                        return Poll::Ready(Err(anyhow::Error::new(e.into_error())))
                    }
                    Err(openssl::ssl::HandshakeError::SetupFailure(e)) => {
                        return Poll::Ready(Err(anyhow::Error::new(e)))
                    }
                },
                HandshakeFuture::Done => panic!("Future must not be polled after ready"),
            }
        })
    }
}
