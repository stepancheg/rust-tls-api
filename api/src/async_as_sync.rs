//! Utility used in different implementations of TLS API.
//! Not needed for regular users of the library.

use std::error;
use std::fmt;
use std::io;
use std::io::Read;
use std::io::Write;
use std::pin::Pin;
use std::ptr;
use std::task::Context;
use std::task::Poll;

use crate::runtime::AsyncRead;
use crate::runtime::AsyncWrite;
use crate::TlsStreamImpl;
use std::marker::PhantomData;

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
    #[cfg(feature = "runtime-tokio")]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.with_context_inner(|cx, s| {
            let mut read_buf = tokio::io::ReadBuf::new(buf);
            let () = poll_to_result(s.poll_read(cx, &mut read_buf))?;
            Ok(read_buf.filled().len())
        })
    }

    #[cfg(feature = "runtime-async-std")]
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

pub trait AsyncWrapperOps<A>: fmt::Debug + Unpin + Send + 'static
where
    A: Unpin,
{
    type SyncWrapper: Read + Write + Unpin + Send + 'static;

    fn debug(w: &Self::SyncWrapper) -> &dyn fmt::Debug;

    fn get_mut(w: &mut Self::SyncWrapper) -> &mut AsyncIoAsSyncIo<A>;
    fn get_ref(w: &Self::SyncWrapper) -> &AsyncIoAsSyncIo<A>;

    fn shutdown(w: &mut Self::SyncWrapper) -> io::Result<()>;

    fn get_alpn_protocols(w: &Self::SyncWrapper) -> Option<Vec<u8>>;
}

pub struct TlsStreamOverSyncIo<A, O>
where
    A: Unpin,
    O: AsyncWrapperOps<A>,
{
    pub stream: O::SyncWrapper,
    _phantom: PhantomData<(A, O)>,
}

impl<A, O> fmt::Debug for TlsStreamOverSyncIo<A, O>
where
    A: Unpin,
    O: AsyncWrapperOps<A>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("TlsStreamOverSyncIo")
            .field(O::debug(&self.stream))
            .finish()
    }
}

struct Guard2<'a, A, O>(&'a mut TlsStreamOverSyncIo<A, O>)
where
    A: Unpin,
    O: AsyncWrapperOps<A>;

impl<'a, A, O> Drop for Guard2<'a, A, O>
where
    A: Unpin,
    O: AsyncWrapperOps<A>,
{
    fn drop(&mut self) {
        unsafe {
            let s = O::get_mut(&mut self.0.stream);
            s.unset_context();
        }
    }
}

impl<A, O> TlsStreamOverSyncIo<A, O>
where
    A: Unpin,
    O: AsyncWrapperOps<A>,
{
    pub fn new(stream: O::SyncWrapper) -> TlsStreamOverSyncIo<A, O> {
        TlsStreamOverSyncIo {
            stream,
            _phantom: PhantomData,
        }
    }

    fn with_context<F, R>(&mut self, cx: &mut Context<'_>, f: F) -> R
    where
        F: FnOnce(&mut Self) -> R,
    {
        unsafe {
            let s = O::get_mut(&mut self.stream);
            s.set_context(cx);
            let g = Guard2(self);
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
        result_to_poll(Self::with_context(self, cx, f))
    }

    #[cfg(feature = "runtime-tokio")]
    fn with_context_sync_to_async_tokio<F>(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf,
        f: F,
    ) -> Poll<io::Result<()>>
    where
        F: FnOnce(&mut Self, &mut [u8]) -> io::Result<usize>,
    {
        self.with_context_sync_to_async(cx, |s| {
            let unfilled = buf.initialize_unfilled();
            let read = f(s, unfilled)?;
            buf.advance(read);
            Ok(())
        })
    }
}

impl<A, O> AsyncRead for TlsStreamOverSyncIo<A, O>
where
    A: Unpin,
    O: AsyncWrapperOps<A>,
{
    #[cfg(feature = "runtime-tokio")]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf,
    ) -> Poll<io::Result<()>> {
        self.get_mut()
            .with_context_sync_to_async_tokio(cx, buf, |s, buf| s.stream.read(buf))
    }

    #[cfg(feature = "runtime-async-std")]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut()
            .with_context_sync_to_async(cx, |s| s.stream.read(buf))
    }
}

impl<A, O> AsyncWrite for TlsStreamOverSyncIo<A, O>
where
    A: Unpin,
    O: AsyncWrapperOps<A>,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut()
            .with_context_sync_to_async(cx, |stream| stream.stream.write(buf))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut()
            .with_context_sync_to_async(cx, |stream| stream.stream.flush())
    }

    #[cfg(feature = "runtime-tokio")]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut()
            .with_context_sync_to_async(cx, |stream| O::shutdown(&mut stream.stream))
    }

    #[cfg(feature = "runtime-async-std")]
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut()
            .with_context_sync_to_async(cx, |stream| O::shutdown(&mut stream.stream))
    }
}

impl<A, O> TlsStreamImpl<A> for TlsStreamOverSyncIo<A, O>
where
    A: fmt::Debug + Unpin + Send + 'static,
    O: AsyncWrapperOps<A>,
{
    fn get_alpn_protocol(&self) -> Option<Vec<u8>> {
        O::get_alpn_protocols(&self.stream)
    }

    fn get_mut(&mut self) -> &mut A {
        O::get_mut(&mut self.stream).get_inner_mut()
    }

    fn get_ref(&self) -> &A {
        O::get_ref(&self.stream).get_inner_ref()
    }
}
