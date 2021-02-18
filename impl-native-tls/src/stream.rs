use std::fmt;
use std::io;
use std::marker::PhantomData;
use tls_api::async_as_sync::AsyncIoAsSyncIo;
use tls_api::async_as_sync::AsyncWrapperOps;
use tls_api::runtime::AsyncRead;
use tls_api::runtime::AsyncWrite;

#[derive(Debug)]
pub(crate) struct NativeTlsOps<S, A>(PhantomData<(S, A)>)
where
    S: fmt::Debug + Unpin + Send + Sync + 'static,
    A: AsyncRead + AsyncWrite + fmt::Debug + Unpin + Send + Sync + 'static;

impl<S, A> AsyncWrapperOps<A> for NativeTlsOps<S, A>
where
    S: fmt::Debug + Unpin + Send + Sync + 'static,
    A: AsyncRead + AsyncWrite + fmt::Debug + Unpin + Send + Sync + 'static,
{
    type SyncWrapper = native_tls::TlsStream<AsyncIoAsSyncIo<A>>;

    fn get_mut(w: &mut Self::SyncWrapper) -> &mut AsyncIoAsSyncIo<A> {
        w.get_mut()
    }

    fn get_ref(w: &Self::SyncWrapper) -> &AsyncIoAsSyncIo<A> {
        w.get_ref()
    }

    fn shutdown(w: &mut Self::SyncWrapper) -> io::Result<()> {
        w.shutdown()
    }

    fn get_alpn_protocols(_w: &Self::SyncWrapper) -> Option<Vec<u8>> {
        None
        // TODO
        // w.negotiated_alpn()
    }
}
