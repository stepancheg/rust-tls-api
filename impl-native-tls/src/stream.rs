use std::fmt;
use std::io;
use std::io::Read;
use std::io::Write;
use std::marker::PhantomData;
use tls_api::async_as_sync::AsyncIoAsSyncIo;
use tls_api::async_as_sync::AsyncWrapperOps;
use tls_api::async_as_sync::TlsStreamOverSyncIo;
use tls_api::async_as_sync::WriteShutdown;
use tls_api::spi_async_socket_impl_delegate;
use tls_api::spi_tls_stream_over_sync_io_wrapper;
use tls_api::AsyncSocket;
use tls_api::ImplInfo;

spi_tls_stream_over_sync_io_wrapper!(TlsStream, NativeTlsStream);

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
    type SyncWrapper = NativeTlsStream<AsyncIoAsSyncIo<A>>;

    fn impl_info() -> ImplInfo {
        crate::info()
    }

    fn debug(w: &Self::SyncWrapper) -> &dyn fmt::Debug {
        &w.0
    }

    fn get_mut(w: &mut Self::SyncWrapper) -> &mut AsyncIoAsSyncIo<A> {
        w.0.get_mut()
    }

    fn get_ref(w: &Self::SyncWrapper) -> &AsyncIoAsSyncIo<A> {
        w.0.get_ref()
    }

    fn get_alpn_protocol(w: &Self::SyncWrapper) -> anyhow::Result<Option<Vec<u8>>> {
        w.0.negotiated_alpn().map_err(anyhow::Error::new)
    }
}

pub(crate) struct NativeTlsStream<A: Read + Write>(pub(crate) native_tls::TlsStream<A>);

impl<A: Read + Write> Write for NativeTlsStream<A> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }

    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        self.0.write_vectored(bufs)
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.0.write_all(buf)
    }

    fn write_fmt(&mut self, fmt: fmt::Arguments<'_>) -> io::Result<()> {
        self.0.write_fmt(fmt)
    }
}

impl<A: Read + Write> WriteShutdown for NativeTlsStream<A> {
    fn shutdown(&mut self) -> Result<(), io::Error> {
        self.flush()?;
        self.0.shutdown()?;
        Ok(())
    }
}

impl<A: Read + Write> Read for NativeTlsStream<A> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }

    fn read_vectored(&mut self, bufs: &mut [io::IoSliceMut<'_>]) -> io::Result<usize> {
        self.0.read_vectored(bufs)
    }

    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> io::Result<usize> {
        self.0.read_to_end(buf)
    }

    fn read_to_string(&mut self, buf: &mut String) -> io::Result<usize> {
        self.0.read_to_string(buf)
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        self.0.read_exact(buf)
    }
}
