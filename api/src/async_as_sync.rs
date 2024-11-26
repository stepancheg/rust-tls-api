//! Utility used in different implementations of TLS API.
//!
//! Not to be used by regular users of the library.

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
use crate::spi::restore_context;
use crate::spi::save_context;
use crate::spi::TlsStreamWithUpcastDyn;
use crate::AsyncSocket;
use crate::ImplInfo;
use crate::TlsStreamDyn;
use crate::TlsStreamWithSocketDyn;

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

#[derive(Debug, thiserror::Error)]
#[error("should not return WouldBlock from async API: {}", _0)]
struct ShouldNotReturnWouldBlockFromAsync(io::Error);

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
    type SyncWrapper: Read + Write + WriteShutdown + Unpin + Send + 'static;

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
    fn get_alpn_protocol(w: &Self::SyncWrapper) -> anyhow::Result<Option<Vec<u8>>>;
}

/// Notify the writer that there will be no more data written.
/// In context of TLS providers, this is great time to send notify_close message.
pub trait WriteShutdown: Write {
    /// Initiates or attempts to shut down this writer, returning when
    /// the I/O connection has completely shut down.
    ///
    /// For example this is suitable for implementing shutdown of a
    /// TLS connection or calling `TcpStream::shutdown` on a proxied connection.
    /// Protocols sometimes need to flush out final pieces of data or otherwise
    /// perform a graceful shutdown handshake, reading/writing more data as
    /// appropriate. This method is the hook for such protocols to implement the
    /// graceful shutdown logic.
    ///
    /// This `shutdown` method is required by implementers of the
    /// `AsyncWrite` trait. Wrappers typically just want to proxy this call
    /// through to the wrapped type, and base types will typically implement
    /// shutdown logic here or just return `Ok(().into())`. Note that if you're
    /// wrapping an underlying `AsyncWrite` a call to `shutdown` implies that
    /// transitively the entire stream has been shut down. After your wrapper's
    /// shutdown logic has been executed you should shut down the underlying
    /// stream.
    ///
    /// Invocation of a `shutdown` implies an invocation of `flush`. Once this
    /// method returns it implies that a flush successfully happened
    /// before the shutdown happened. That is, callers don't need to call
    /// `flush` before calling `shutdown`. They can rely that by calling
    /// `shutdown` any pending buffered data will be written out.
    ///
    /// # Errors
    ///
    /// This function can return normal I/O errors through `Err`, described
    /// above. Additionally this method may also render the underlying
    /// `Write::write` method no longer usable (e.g. will return errors in the
    /// future). It's recommended that once `shutdown` is called the
    /// `write` method is no longer called.
    fn shutdown(&mut self) -> Result<(), io::Error> {
        self.flush()?;
        Ok(())
    }
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
            .with_context_sync_to_async(cx, |stream| stream.stream.shutdown())
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

    fn get_alpn_protocol(&self) -> anyhow::Result<Option<Vec<u8>>> {
        O::get_alpn_protocol(&self.stream)
    }

    fn get_socket_dyn_mut(&mut self) -> &mut dyn AsyncSocket {
        O::get_mut(&mut self.stream).get_inner_mut()
    }

    fn get_socket_dyn_ref(&self) -> &dyn AsyncSocket {
        O::get_ref(&self.stream).get_inner_ref()
    }
}

impl<A, O> TlsStreamWithSocketDyn<A> for TlsStreamOverSyncIo<A, O>
where
    A: AsyncSocket,
    O: AsyncWrapperOps<A>,
{
    fn get_socket_mut(&mut self) -> &mut A {
        O::get_mut(&mut self.stream).get_inner_mut()
    }

    fn get_socket_ref(&self) -> &A {
        O::get_ref(&self.stream).get_inner_ref()
    }
}

impl<A, O> TlsStreamWithUpcastDyn<A> for TlsStreamOverSyncIo<A, O>
where
    A: AsyncSocket,
    O: AsyncWrapperOps<A>,
{
    fn upcast_box(self: Box<Self>) -> Box<dyn TlsStreamDyn> {
        self
    }
}

/// Implement wrapper for [`TlsStreamOverSyncIo`].
#[macro_export]
macro_rules! spi_tls_stream_over_sync_io_wrapper {
    ( $t:ident, $n:ident ) => {
        #[derive(Debug)]
        pub struct TlsStream<A: AsyncSocket>(
            pub(crate) TlsStreamOverSyncIo<A, AsyncWrapperOpsImpl<AsyncIoAsSyncIo<A>, A>>,
        );

        impl<A: AsyncSocket> TlsStream<A> {
            pub(crate) fn new(stream: $n<AsyncIoAsSyncIo<A>>) -> TlsStream<A> {
                TlsStream(TlsStreamOverSyncIo::new(stream))
            }

            fn deref_pin_mut_for_impl_socket(
                self: std::pin::Pin<&mut Self>,
            ) -> std::pin::Pin<
                &mut TlsStreamOverSyncIo<A, AsyncWrapperOpsImpl<AsyncIoAsSyncIo<A>, A>>,
            > {
                std::pin::Pin::new(&mut self.get_mut().0)
            }

            fn deref_for_impl_socket(
                &self,
            ) -> &TlsStreamOverSyncIo<A, AsyncWrapperOpsImpl<AsyncIoAsSyncIo<A>, A>> {
                &self.0
            }
        }

        spi_async_socket_impl_delegate!($t<S>);

        impl<A: tls_api::AsyncSocket> tls_api::TlsStreamDyn for $t<A> {
            fn get_alpn_protocol(&self) -> anyhow::Result<Option<Vec<u8>>> {
                self.0.get_alpn_protocol()
            }

            fn impl_info(&self) -> ImplInfo {
                self.0.impl_info()
            }

            fn get_socket_dyn_mut(&mut self) -> &mut dyn AsyncSocket {
                self.0.get_socket_dyn_mut()
            }

            fn get_socket_dyn_ref(&self) -> &dyn AsyncSocket {
                self.0.get_socket_dyn_ref()
            }
        }

        impl<A: tls_api::AsyncSocket> tls_api::TlsStreamWithSocketDyn<A> for $t<A> {
            fn get_socket_mut(&mut self) -> &mut A {
                self.0.get_socket_mut()
            }

            fn get_socket_ref(&self) -> &A {
                self.0.get_socket_ref()
            }
        }

        impl<A: tls_api::AsyncSocket> tls_api::spi::TlsStreamWithUpcastDyn<A> for $t<A> {
            fn upcast_box(self: Box<Self>) -> Box<dyn tls_api::TlsStreamDyn> {
                self
            }
        }
    };
}
