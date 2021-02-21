use std::fmt;
use std::marker::PhantomData;

use openssl::ssl::SslStream;
use std::pin::Pin;
use tls_api::spi::async_as_sync::AsyncIoAsSyncIo;
use tls_api::spi::async_as_sync::AsyncWrapperOps;
use tls_api::spi::async_as_sync::TlsStreamOverSyncIo;
use tls_api::spi_async_socket_impl_delegate;
use tls_api::spi_tls_stream_over_sync_io_wrapper;
use tls_api::AsyncSocket;
use tls_api::ImplInfo;

spi_tls_stream_over_sync_io_wrapper!(TlsStream, SslStream);

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
    type SyncWrapper = openssl::ssl::SslStream<AsyncIoAsSyncIo<A>>;

    fn debug(w: &Self::SyncWrapper) -> &dyn fmt::Debug {
        w
    }

    fn get_mut(w: &mut Self::SyncWrapper) -> &mut AsyncIoAsSyncIo<A> {
        w.get_mut()
    }

    fn get_ref(w: &Self::SyncWrapper) -> &AsyncIoAsSyncIo<A> {
        w.get_ref()
    }

    #[cfg(has_alpn)]
    fn get_alpn_protocol(w: &Self::SyncWrapper) -> tls_api::Result<Option<Vec<u8>>> {
        Ok(w.ssl().selected_alpn_protocol().map(Vec::from))
    }

    #[cfg(not(has_alpn))]
    fn get_alpn_protocols(_w: &Self::SyncWrapper) -> tls_api::Result<Option<Vec<u8>>> {
        Ok(None)
    }

    fn impl_info() -> ImplInfo {
        crate::into()
    }
}
