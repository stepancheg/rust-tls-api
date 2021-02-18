use security_framework::secure_transport::ServerBuilder;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use tls_api::runtime::AsyncRead;
use tls_api::runtime::AsyncWrite;

pub struct TlsAcceptor(ServerBuilder);
pub struct TlsAcceptorBuilder(ServerBuilder);

impl tls_api::TlsAcceptorBuilder for TlsAcceptorBuilder {
    type Acceptor = TlsAcceptor;
    type Underlying = ServerBuilder;
    const SUPPORTS_ALPN: bool = false;

    fn set_alpn_protocols(&mut self, _protocols: &[&[u8]]) -> tls_api::Result<()> {
        // TODO
        unimplemented!()
    }

    fn underlying_mut(&mut self) -> &mut Self::Underlying {
        &mut self.0
    }

    fn build(self) -> tls_api::Result<Self::Acceptor> {
        Ok(TlsAcceptor(self.0))
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
        let _ = stream;
        unimplemented!()
    }
}
