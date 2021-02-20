//! Utility used in different implementations of TLS API.
//!
//! Not to be used by regular users of the library.

use std::error;
use std::fmt;
use std::io;
use std::io::Read;
use std::io::Write;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;

use crate::runtime::AsyncRead;
use crate::runtime::AsyncWrite;
use crate::spi::thread_local_context::restore_context;
use crate::spi::thread_local_context::save_context;
use crate::spi::TlsStreamDyn;
use crate::spi::TlsStreamImpl;
use crate::AsyncSocket;
use crate::ImplInfo;

/// Async IO object as sync IO.
///
/// Used in API implementations.
#[derive(Debug)]
pub struct AsyncIoAsSyncIo<S: Unpin> {
    inner: S,
}

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
        AsyncIoAsSyncIo { inner }
    }

    fn get_inner_pin(&mut self) -> Pin<&mut S> {
        Pin::new(&mut self.inner)
    }
}

impl<S: AsyncRead + Unpin> Read for AsyncIoAsSyncIo<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        restore_context_poll_to_result(|cx| {
            #[cfg(feature = "runtime-tokio")]
            {
                let mut read_buf = tokio::io::ReadBuf::new(buf);
                let p = self.get_inner_pin().poll_read(cx, &mut read_buf);
                p.map_ok(|()| read_buf.filled().len())
            }
            #[cfg(feature = "runtime-async-std")]
            {
                self.get_inner_pin().poll_read(cx, buf)
            }
        })
    }
}

impl<S: AsyncWrite + Unpin> Write for AsyncIoAsSyncIo<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        restore_context_poll_to_result(|cx| self.get_inner_pin().poll_write(cx, buf))
    }

    fn flush(&mut self) -> io::Result<()> {
        restore_context_poll_to_result(|cx| self.get_inner_pin().poll_flush(cx))
    }
}

/// Convert blocking API result to async result
fn result_to_poll<T>(r: io::Result<T>) -> Poll<io::Result<T>> {
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
fn poll_to_result<T>(r: Poll<io::Result<T>>) -> io::Result<T> {
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

fn restore_context_poll_to_result<R>(
    f: impl FnOnce(&mut Context<'_>) -> Poll<io::Result<R>>,
) -> io::Result<R> {
    restore_context(|cx| poll_to_result(f(cx)))
}

/// Used by API implementors.
pub trait AsyncWrapperOps<A>: fmt::Debug + Unpin + Send + 'static
where
    A: Unpin,
{
    /// API-implementation of wrapper stream.
    ///
    /// Wrapped object is always [`AsyncIoAsSyncIo`].
    type SyncWrapper: Read + Write + Unpin + Send + 'static;

    /// Which crates imlpements this?
    fn impl_info() -> ImplInfo;

    /// Cast the wrapper to [`fmt::Debug`] or provide substitute debug.
    /// This is work around not all wrappers implementing [`fmt::Debug`].
    fn debug(w: &Self::SyncWrapper) -> &dyn fmt::Debug;

    /// Unwrap the wrapper.
    fn get_mut(w: &mut Self::SyncWrapper) -> &mut AsyncIoAsSyncIo<A>;
    /// Unwrap the wrapper.
    fn get_ref(w: &Self::SyncWrapper) -> &AsyncIoAsSyncIo<A>;

    /// Get negotiated ALPN protocol.
    fn get_alpn_protocol(w: &Self::SyncWrapper) -> crate::Result<Option<Vec<u8>>>;
}

/// Implementation of `TlsStreamImpl` for APIs using synchronous I/O.
pub struct TlsStreamOverSyncIo<A, O>
where
    A: Unpin,
    O: AsyncWrapperOps<A>,
{
    /// TLS-implementation.
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

impl<A, O> TlsStreamOverSyncIo<A, O>
where
    A: Unpin,
    O: AsyncWrapperOps<A>,
{
    /// Constructor.
    pub fn new(stream: O::SyncWrapper) -> TlsStreamOverSyncIo<A, O> {
        TlsStreamOverSyncIo {
            stream,
            _phantom: PhantomData,
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
        result_to_poll(save_context(cx, || f(self)))
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
            .with_context_sync_to_async_tokio(cx, buf, |s, buf| {
                let result = s.stream.read(buf);
                match result {
                    Ok(r) => Ok(r),
                    Err(e) if e.kind() == io::ErrorKind::ConnectionAborted => {
                        // rustls returns `ConnectionAborted` on EOF
                        Ok(0)
                    }
                    Err(e) => Err(e),
                }
            })
    }

    #[cfg(feature = "runtime-async-std")]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().with_context_sync_to_async(cx, |s| {
            let result = s.stream.read(buf);
            match result {
                Ok(r) => Ok(r),
                Err(e) if e.kind() == io::ErrorKind::ConnectionAborted => {
                    // rustls returns `ConnectionAborted` on EOF
                    Ok(0)
                }
                Err(e) => Err(e),
            }
        })
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
            .with_context_sync_to_async(cx, |stream| stream.stream.flush())
    }

    #[cfg(feature = "runtime-async-std")]
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut()
            .with_context_sync_to_async(cx, |stream| stream.stream.flush())
    }
}

impl<A, O> TlsStreamDyn for TlsStreamOverSyncIo<A, O>
where
    A: AsyncSocket,
    O: AsyncWrapperOps<A>,
{
    fn impl_info(&self) -> ImplInfo {
        O::impl_info()
    }

    fn get_alpn_protocol(&self) -> crate::Result<Option<Vec<u8>>> {
        O::get_alpn_protocol(&self.stream)
    }

    fn get_socket_dyn_mut(&mut self) -> &mut dyn AsyncSocket {
        O::get_mut(&mut self.stream).get_inner_mut()
    }

    fn get_socket_dyn_ref(&self) -> &dyn AsyncSocket {
        O::get_ref(&self.stream).get_inner_ref()
    }
}

impl<A, O> TlsStreamImpl<A> for TlsStreamOverSyncIo<A, O>
where
    A: AsyncSocket,
    O: AsyncWrapperOps<A>,
{
    fn upcast_box(self: Box<Self>) -> Box<dyn TlsStreamDyn> {
        self
    }

    fn get_socket_mut(&mut self) -> &mut A {
        O::get_mut(&mut self.stream).get_inner_mut()
    }

    fn get_socket_ref(&self) -> &A {
        O::get_ref(&self.stream).get_inner_ref()
    }
}
