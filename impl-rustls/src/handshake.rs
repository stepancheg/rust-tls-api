//! Handshake future

use crate::TlsStream;
use std::future::Future;
use std::io;
use std::mem;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;

use tls_api::spi::save_context;
use tls_api::AsyncSocket;

pub(crate) enum HandshakeFuture<A>
where
    A: AsyncSocket,
{
    MidHandshake(TlsStream<A>),
    Done,
}

impl<A> Future for HandshakeFuture<A>
where
    A: AsyncSocket,
{
    type Output = tls_api::Result<tls_api::TlsStreamWithSocket<A>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        save_context(cx, || {
            let self_mut = self.get_mut();
            match mem::replace(self_mut, HandshakeFuture::Done) {
                HandshakeFuture::MidHandshake(mut stream) => {
                    // sanity check
                    assert!(stream.stream.is_handshaking());
                    match stream.stream.complete_io() {
                        Ok(_) => {
                            return Poll::Ready(Ok(tls_api::TlsStreamWithSocket::new(stream)));
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
