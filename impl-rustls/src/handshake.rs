//! Handshake future

use crate::TlsStream;
use std::fmt;
use std::future::Future;
use std::io;
use std::mem;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;

use tls_api::spi::save_context;
use tls_api::AsyncSocket;

pub(crate) enum HandshakeFuture<A, T>
where
    A: AsyncSocket,
    T: rustls::Session + fmt::Debug + Unpin + 'static,
{
    MidHandshake(TlsStream<A, T>),
    Done,
}

impl<A, T> Future for HandshakeFuture<A, T>
where
    A: AsyncSocket,
    T: rustls::Session + fmt::Debug + Unpin + 'static,
{
    type Output = tls_api::Result<tls_api::TlsStream<A>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        save_context(cx, || {
            let self_mut = self.get_mut();
            match mem::replace(self_mut, HandshakeFuture::Done) {
                HandshakeFuture::MidHandshake(mut stream) => {
                    // sanity check
                    assert!(stream.stream.sess.is_handshaking());
                    match stream.stream.sess.complete_io(&mut stream.stream.sock) {
                        Ok(_) => {
                            return Poll::Ready(Ok(tls_api::TlsStream::new(stream)));
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            *self_mut = HandshakeFuture::MidHandshake(stream);
                            return Poll::Pending;
                        }
                        Err(e) => return Poll::Ready(Err(tls_api::Error::new(e))),
                    }
                }
                HandshakeFuture::Done => panic!("Future must not be polled after ready"),
            }
        })
    }
}
