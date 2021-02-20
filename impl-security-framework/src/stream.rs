#![cfg(any(target_os = "macos", target_os = "ios"))]

use std::fmt;
use std::marker::PhantomData;

use security_framework::secure_transport::SslStream;

use tls_api::spi::async_as_sync::AsyncIoAsSyncIo;
use tls_api::spi::async_as_sync::AsyncWrapperOps;
use tls_api::spi::async_as_sync::TlsStreamOverSyncIo;
use tls_api::AsyncSocket;
use tls_api::ImplInfo;

pub(crate) type TlsStream<A> = TlsStreamOverSyncIo<A, AsyncWrapperOpsImpl<AsyncIoAsSyncIo<A>, A>>;

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

    fn get_alpn_protocol(w: &Self::SyncWrapper) -> tls_api::Result<Option<Vec<u8>>> {
        let mut protocols = w.context().alpn_protocols().map_err(tls_api::Error::new)?;
        if protocols.len() <= 1 {
            Ok(protocols.pop().map(String::into_bytes))
        } else {
            Err(crate::Error::TooManyAlpnProtocols(protocols).into())
        }
    }
}
