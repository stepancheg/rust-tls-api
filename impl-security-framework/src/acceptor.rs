use std::fmt;
use std::future::Future;
use std::pin::Pin;
use tls_api::runtime::AsyncRead;
use tls_api::runtime::AsyncWrite;

pub struct TlsAcceptor();
pub struct TlsAcceptorBuilder();

impl tls_api::TlsAcceptorBuilder for TlsAcceptorBuilder {
    type Acceptor = TlsAcceptor;
    type Underlying = ();
    const SUPPORTS_ALPN: bool = false;

    fn set_alpn_protocols(&mut self, protocols: &[&[u8]]) -> tls_api::Result<()> {
        unimplemented!()
    }

    fn underlying_mut(&mut self) -> &mut Self::Underlying {
        unimplemented!()
    }

    fn build(self) -> tls_api::Result<Self::Acceptor> {
        unimplemented!()
    }
}

impl tls_api::TlsAcceptor for TlsAcceptor {
    type Builder = TlsAcceptorBuilder;

    fn accept<'a, S>(
        &'a self,
        stream: S,
    ) -> Pin<Box<dyn Future<Output = tls_api::Result<tls_api::TlsStream<S>>> + Send>>
    where
        S: AsyncRead + AsyncWrite + fmt::Debug + Unpin + Send + Sync + 'static,
    {
        unimplemented!()
    }
}
