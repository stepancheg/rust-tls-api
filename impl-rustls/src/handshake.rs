//! Handshake future

use crate::TlsStream;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::{fmt, io, mem};
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;

pub(crate) enum HandshakeFuture<S, T>
where
    S: AsyncRead + AsyncWrite + fmt::Debug + Unpin + Send + 'static,
    T: rustls::Session + Unpin + 'static,
{
    MidHandshake(TlsStream<S, T>),
    Done,
}

impl<S, T> Future for HandshakeFuture<S, T>
where
    S: AsyncRead + AsyncWrite + fmt::Debug + Unpin + Send + 'static,
    T: rustls::Session + Unpin + 'static,
{
    type Output = tls_api::Result<tls_api::TlsStream<S>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        unsafe {
            let self_mut = self.get_mut();
            match mem::replace(self_mut, HandshakeFuture::Done) {
                HandshakeFuture::MidHandshake(mut stream) => {
                    // sanity check
                    assert!(stream.session.is_handshaking());
                    stream.stream.set_context(cx);
                    match stream.session.complete_io(&mut stream.stream) {
                        Ok(_) => {
                            stream.stream.unset_context();
                            return Poll::Ready(Ok(tls_api::TlsStream::new(stream)));
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            stream.stream.unset_context();
                            *self_mut = HandshakeFuture::MidHandshake(stream);
                            return Poll::Pending;
                        }
                        Err(e) => return Poll::Ready(Err(tls_api::Error::new(e))),
                    }
                }
                HandshakeFuture::Done => panic!("Future must not be polled after ready"),
            }
        }
    }
}
