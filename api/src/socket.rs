use crate::runtime::AsyncRead;
use crate::runtime::AsyncWrite;
use std::fmt;

/// Type alias for necessary socket async traits.
///
/// Type alias exists to avoid repetition of traits in function signatures.
///
/// This type cannot be implemented directly, and there's no need to.
pub trait AsyncSocket: AsyncRead + AsyncWrite + fmt::Debug + Unpin + Send + 'static {}

/// Auto-implement for all socket types.
impl<A: AsyncRead + AsyncWrite + fmt::Debug + Unpin + Send + 'static> AsyncSocket for A {}

/// Delegate [`AsyncSocket`] implementation to the underlying socket.
///
/// This is meant to be used only by API implementations.
///
/// # See also
/// * [PR in tokio](https://github.com/tokio-rs/tokio/pull/3540)
/// * [PR in futures](https://github.com/rust-lang/futures-rs/pull/2352)
#[macro_export]
macro_rules! spi_async_socket_impl_delegate {
    ( "AsyncRead" ) => {
        #[cfg(feature = "runtime-tokio")]
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf,
        ) -> std::task::Poll<std::io::Result<()>> {
            self.get_socket_pin_for_delegate().poll_read(cx, buf)
        }

        #[cfg(feature = "runtime-async-std")]
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut [u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            self.get_socket_pin_for_delegate().poll_read(cx, buf)
        }
    };
    ( "AsyncWrite" ) => {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            self.get_socket_pin_for_delegate().poll_write(cx, buf)
        }

        #[cfg(feature = "runtime-tokio")]
        fn poll_write_vectored(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            bufs: &[std::io::IoSlice<'_>],
        ) -> std::task::Poll<std::result::Result<usize, io::Error>> {
            self.get_socket_pin_for_delegate()
                .poll_write_vectored(cx, bufs)
        }

        #[cfg(feature = "runtime-tokio")]
        fn is_write_vectored(&self) -> bool {
            self.get_socket_ref_for_delegate().is_write_vectored()
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            self.get_socket_pin_for_delegate().poll_flush(cx)
        }

        #[cfg(feature = "runtime-async-std")]
        fn poll_close(
            self: std::pin::Pin<&mut Self>,
            ctx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            self.get_socket_pin_for_delegate().poll_close(ctx)
        }

        #[cfg(feature = "runtime-tokio")]
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            ctx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            self.get_socket_pin_for_delegate().poll_shutdown(ctx)
        }
    };
    ( $t:ident <S> ) => {
        impl<S: $crate::AsyncSocket> $crate::runtime::AsyncRead for $t<S> {
            spi_async_socket_impl_delegate!("AsyncRead");
        }

        impl<S: $crate::AsyncSocket> $crate::runtime::AsyncWrite for $t<S> {
            spi_async_socket_impl_delegate!("AsyncWrite");
        }
    };
    ( $t:ty ) => {
        impl $crate::runtime::AsyncRead for $t {
            spi_async_socket_impl_delegate!("AsyncRead");
        }

        impl $crate::runtime::AsyncWrite for $t {
            spi_async_socket_impl_delegate!("AsyncWrite");
        }
    };
}
