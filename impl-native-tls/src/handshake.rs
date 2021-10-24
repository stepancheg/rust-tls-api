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

pub(crate) enum HandshakeFuture<F, S: Unpin> {
    Initial(F, AsyncIoAsSyncIo<S>),
    MidHandshake(native_tls::MidHandshakeTlsStream<AsyncIoAsSyncIo<S>>),
    Done,
}

impl<F, A> Future for HandshakeFuture<F, A>
where
    A: AsyncSocket,
    F: FnOnce(
        AsyncIoAsSyncIo<A>,
    ) -> result::Result<
        native_tls::TlsStream<AsyncIoAsSyncIo<A>>,
        native_tls::HandshakeError<AsyncIoAsSyncIo<A>>,
    >,
    Self: Unpin,
{
    type Output = anyhow::Result<crate::TlsStream<A>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        save_context(cx, || {
            let self_mut = self.get_mut();
            match mem::replace(self_mut, HandshakeFuture::Done) {
                HandshakeFuture::Initial(f, stream) => match f(stream) {
                    Ok(stream) => {
                        return Poll::Ready(Ok(crate::TlsStream::new(stream)));
                    }
                    Err(native_tls::HandshakeError::WouldBlock(mid)) => {
                        *self_mut = HandshakeFuture::MidHandshake(mid);
                        return Poll::Pending;
                    }
                    Err(native_tls::HandshakeError::Failure(e)) => {
                        return Poll::Ready(Err(anyhow::Error::new(e)))
                    }
                },
                HandshakeFuture::MidHandshake(stream) => match stream.handshake() {
                    Ok(stream) => {
                        return Poll::Ready(Ok(crate::TlsStream::new(stream)));
                    }
                    Err(native_tls::HandshakeError::WouldBlock(mid)) => {
                        *self_mut = HandshakeFuture::MidHandshake(mid);
                        return Poll::Pending;
                    }
                    Err(native_tls::HandshakeError::Failure(e)) => {
                        return Poll::Ready(Err(anyhow::Error::new(e)))
                    }
                },
                HandshakeFuture::Done => panic!("Future must not be polled after ready"),
            }
        })
    }
}
