use std::io;
use std::io::IoSlice;
use std::mem;
use std::pin::Pin;
use std::ptr;
use std::task::Context;
use std::task::Poll;

use crate::assert_send;
use crate::runtime::AsyncRead;
use crate::runtime::AsyncWrite;
use crate::AsyncSocket;
use std::any::TypeId;
use std::mem::MaybeUninit;

/// Newtype for [`Box<dyn AsyncSocket>`](AsyncSocket).
#[derive(Debug)]
pub struct AsyncSocketBox(Box<dyn AsyncSocket>);

fn _assert_kinds() {
    assert_send::<AsyncSocketBox>();
}

fn transmute_or_map<A: 'static, B: 'static>(a: A, f: impl FnOnce(A) -> B) -> B {
    if TypeId::of::<A>() == TypeId::of::<B>() {
        assert_eq!(mem::size_of::<A>(), mem::size_of::<B>());
        // Can be made safe with specialization.
        unsafe {
            let mut b = MaybeUninit::<B>::uninit();
            ptr::copy(&a as *const A, b.as_mut_ptr() as *mut A, 1);
            mem::forget(a);
            b.assume_init()
        }
    } else {
        f(a)
    }
}

impl AsyncSocketBox {
    /// Construct.
    pub fn new<S: AsyncSocket>(socket: S) -> AsyncSocketBox {
        transmute_or_map(socket, |socket| AsyncSocketBox(Box::new(socket)))
    }

    fn get_inner(self: Pin<&mut Self>) -> Pin<&mut dyn AsyncSocket> {
        Pin::new(&mut self.get_mut().0)
    }
}

impl AsyncRead for AsyncSocketBox {
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

    #[cfg(feature = "runtime-async-std")]
    fn poll_read_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [std::io::IoSliceMut<'_>],
    ) -> Poll<io::Result<usize>> {
        self.get_inner().poll_read_vectored(cx, bufs)
    }
}

impl AsyncWrite for AsyncSocketBox {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_inner().poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
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

fn _assert_async_socket_box_is_async_socket(s: AsyncSocketBox) {
    fn accepts_socket<S: AsyncSocket>(_: S) {}
    accepts_socket(s);
}
