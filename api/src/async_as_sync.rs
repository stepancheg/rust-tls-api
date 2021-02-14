//! Utility used in different implementations of TLS API.

use std::error;
use std::fmt;
use std::io;
use std::io::Read;
use std::io::Write;
use std::marker;
use std::pin::Pin;
use std::ptr;
use std::task::Context;
use std::task::Poll;

use crate::runtime::AsyncRead;
use crate::runtime::AsyncWrite;

/// Async IO object as sync IO.
///
/// Used in API implementations.
#[derive(Debug)]
pub struct AsyncIoAsSyncIo<S: Unpin> {
    inner: S,
    context: *mut (),
}

unsafe impl<S: Unpin + Sync> Sync for AsyncIoAsSyncIo<S> {}
unsafe impl<S: Unpin + Send> Send for AsyncIoAsSyncIo<S> {}

impl<S: Unpin> AsyncIoAsSyncIo<S> {
    /// Get a mutable reference to a wrapped stream
    pub fn get_inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// And a reference to a wrapped stream
    pub fn get_inner_ref(&self) -> &S {
        &self.inner
    }

    /// Wrap sync object in this wrapper.
    pub fn new(inner: S) -> AsyncIoAsSyncIo<S> {
        AsyncIoAsSyncIo {
            inner,
            context: ptr::null_mut(),
        }
    }

    /// Store async context inside this object
    pub unsafe fn set_context(&mut self, cx: &mut Context<'_>) {
        assert!(self.context.is_null());
        self.context = cx as *mut _ as *mut _;
    }

    /// Clear async context
    pub unsafe fn unset_context(&mut self) {
        assert!(!self.context.is_null());
        self.context = ptr::null_mut();
    }
}

pub trait AsyncIoAsSyncIoWrapper<S: Unpin>: Sized {
    fn get_mut(&mut self) -> &mut AsyncIoAsSyncIo<S>;

    fn with_context<F, R>(&mut self, cx: &mut Context<'_>, f: F) -> R
    where
        F: FnOnce(&mut Self) -> R,
    {
        unsafe {
            let s = self.get_mut();
            s.set_context(cx);
            let g = Guard(self, marker::PhantomData);
            f(g.0)
        }
    }

    fn with_context_sync_to_async<F, R>(
        &mut self,
        cx: &mut Context<'_>,
        f: F,
    ) -> Poll<io::Result<R>>
    where
        F: FnOnce(&mut Self) -> io::Result<R>,
    {
        result_to_poll(self.with_context(cx, f))
    }
}

impl<S: Unpin> AsyncIoAsSyncIoWrapper<S> for AsyncIoAsSyncIo<S> {
    fn get_mut(&mut self) -> &mut AsyncIoAsSyncIo<S> {
        self
    }
}

struct Guard<'a, S: Unpin, W: AsyncIoAsSyncIoWrapper<S>>(&'a mut W, marker::PhantomData<S>);

impl<'a, S: Unpin, W: AsyncIoAsSyncIoWrapper<S>> Drop for Guard<'a, S, W> {
    fn drop(&mut self) {
        unsafe {
            let s = self.0.get_mut();
            s.unset_context();
        }
    }
}

impl<S: Unpin> AsyncIoAsSyncIo<S> {
    fn with_context_inner<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut Context<'_>, Pin<&mut S>) -> R,
    {
        unsafe {
            assert!(!self.context.is_null());
            let context = &mut *(self.context as *mut _);
            f(context, Pin::new(&mut self.inner))
        }
    }
}

impl<S: AsyncRead + Unpin> Read for AsyncIoAsSyncIo<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.with_context_inner(|cx, s| poll_to_result(s.poll_read(cx, buf)))
    }
}

impl<S: AsyncWrite + Unpin> Write for AsyncIoAsSyncIo<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.with_context_inner(|cx, s| poll_to_result(s.poll_write(cx, buf)))
    }

    fn flush(&mut self) -> io::Result<()> {
        self.with_context_inner(|cx, s| poll_to_result(s.poll_flush(cx)))
    }
}

/// Convert blocking API result to async result
pub fn result_to_poll<T>(r: io::Result<T>) -> Poll<io::Result<T>> {
    match r {
        Ok(v) => Poll::Ready(Ok(v)),
        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
        Err(e) => Poll::Ready(Err(e)),
    }
}

#[derive(Debug)]
struct ShouldNotReturnWouldBlockFromAsync(io::Error);

impl error::Error for ShouldNotReturnWouldBlockFromAsync {}

impl fmt::Display for ShouldNotReturnWouldBlockFromAsync {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "should not return WouldBlock from async API: {}", self.0)
    }
}

/// Convert nonblocking API to sync result
pub fn poll_to_result<T>(r: Poll<io::Result<T>>) -> io::Result<T> {
    match r {
        Poll::Ready(Ok(r)) => Ok(r),
        Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::WouldBlock => Err(io::Error::new(
            io::ErrorKind::Other,
            ShouldNotReturnWouldBlockFromAsync(e),
        )),
        Poll::Ready(Err(e)) => Err(e),
        Poll::Pending => Err(io::Error::from(io::ErrorKind::WouldBlock)),
    }
}
