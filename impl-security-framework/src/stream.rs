#![cfg(any(target_os = "macos", target_os = "ios"))]

use std::fmt;
use std::marker::PhantomData;

use security_framework::secure_transport::SslContext;
use security_framework::secure_transport::SslStream;

use tls_api::async_as_sync::AsyncIoAsSyncIo;
use tls_api::async_as_sync::AsyncWrapperOps;
use tls_api::async_as_sync::TlsStreamOverSyncIo;
use tls_api::spi_async_socket_impl_delegate;
use tls_api::spi_tls_stream_over_sync_io_wrapper;
use tls_api::AsyncSocket;
use tls_api::ImplInfo;

spi_tls_stream_over_sync_io_wrapper!(TlsStream, SslStream);

impl<A: AsyncSocket> TlsStream<A> {
    /// Get `SslContext` reference for this stream.
    pub fn ssl_context(&self) -> &SslContext {
        self.0.stream.context()
    }
}

#[derive(Debug)]
pub(crate) struct AsyncWrapperOpsImpl<S, A>(PhantomData<(S, A)>)
where
    S: fmt::Debug + Unpin + Send + 'static,
    A: AsyncSocket;

impl<S, A> AsyncWrapperOps<A> for AsyncWrapperOpsImpl<S, A>
where
    S: fmt::Debug + Unpin + Send + 'static,
    A: AsyncSocket,
{
    type SyncWrapper = SslStream<AsyncIoAsSyncIo<A>>;

    fn impl_info() -> ImplInfo {
        crate::info()
    }

    fn debug(w: &Self::SyncWrapper) -> &dyn fmt::Debug {
        w
    }

    fn get_mut(w: &mut Self::SyncWrapper) -> &mut AsyncIoAsSyncIo<A> {
        w.get_mut()
    }

    fn get_ref(w: &Self::SyncWrapper) -> &AsyncIoAsSyncIo<A> {
        w.get_ref()
    }

    fn get_alpn_protocol(w: &Self::SyncWrapper) -> anyhow::Result<Option<Vec<u8>>> {
        let mut protocols = w.context().alpn_protocols().map_err(anyhow::Error::new)?;
        if protocols.len() <= 1 {
            Ok(protocols.pop().map(String::into_bytes))
        } else {
            Err(crate::Error::TooManyAlpnProtocols(protocols).into())
        }
    }
}
