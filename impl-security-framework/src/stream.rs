use security_framework::secure_transport::SslStream;
use std::fmt;
use std::io;
use std::io::Write;
use std::marker::PhantomData;
use tls_api::async_as_sync::AsyncIoAsSyncIo;
use tls_api::async_as_sync::AsyncWrapperOps;
use tls_api::async_as_sync::TlsStreamOverSyncIo;
use tls_api::runtime::AsyncRead;
use tls_api::runtime::AsyncWrite;

pub(crate) type TlsStream<A> = TlsStreamOverSyncIo<A, AsyncWrapperOpsImpl<AsyncIoAsSyncIo<A>, A>>;

#[derive(Debug)]
pub(crate) struct AsyncWrapperOpsImpl<S, A>(PhantomData<(S, A)>)
where
    S: fmt::Debug + Unpin + Send + 'static,
    A: AsyncRead + AsyncWrite + fmt::Debug + Unpin + Send + 'static;

impl<S, A> AsyncWrapperOps<A> for AsyncWrapperOpsImpl<S, A>
where
    S: fmt::Debug + Unpin + Send + 'static,
    A: AsyncRead + AsyncWrite + fmt::Debug + Unpin + Send + 'static,
{
    type SyncWrapper = SslStream<AsyncIoAsSyncIo<A>>;

    fn debug(w: &Self::SyncWrapper) -> &dyn fmt::Debug {
        w
    }

    fn get_mut(w: &mut Self::SyncWrapper) -> &mut AsyncIoAsSyncIo<A> {
        w.get_mut()
    }

    fn get_ref(w: &Self::SyncWrapper) -> &AsyncIoAsSyncIo<A> {
        w.get_ref()
    }

    fn shutdown(w: &mut Self::SyncWrapper) -> io::Result<()> {
        // TODO
        w.flush()
    }

    fn get_alpn_protocols(_w: &Self::SyncWrapper) -> Option<Vec<u8>> {
        None // TODO
             // TODO: do not ignore error
             // w.context().alpn_protocols().ok()
             //     .map(|v| v.into_iter().map(|s| s.into_bytes()).collect())
    }
}
