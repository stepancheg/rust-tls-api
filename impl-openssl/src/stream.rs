use std::fmt;
use std::io;
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

    fn shutdown(w: &mut Self::SyncWrapper) -> io::Result<()> {
        match w.shutdown() {
            Ok(_) => Ok(()),
            Err(ref e) if e.code() == openssl::ssl::ErrorCode::ZERO_RETURN => Ok(()),
            Err(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
        }
    }

    #[cfg(has_alpn)]
    fn get_alpn_protocols(w: &Self::SyncWrapper) -> Option<Vec<u8>> {
        w.ssl().selected_alpn_protocol().map(Vec::from)
    }

    #[cfg(not(has_alpn))]
    fn get_alpn_protocols(_w: &Self::SyncWrapper) -> Option<Vec<u8>> {
        None
    }
}
