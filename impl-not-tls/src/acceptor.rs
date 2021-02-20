use std::fmt;
use tls_api::AsyncSocket;
use tls_api::BoxFuture;

pub struct TlsAcceptorBuilder(pub ());

impl tls_api::TlsAcceptorBuilder for TlsAcceptorBuilder {
    type Acceptor = TlsAcceptor;
    type Underlying = ();

    fn set_alpn_protocols(&mut self, protocols: &[&[u8]]) -> tls_api::Result<()> {
        let _ = protocols;
        Err(tls_api::Error::new_other(
            "ALPN is not implemented in not-TLS implementation",
        ))
    }

    fn underlying_mut(&mut self) -> &mut Self::Underlying {
        &mut self.0
    }

    fn build(self) -> tls_api::Result<TlsAcceptor> {
        Ok(TlsAcceptor(self.0))
    }
}

pub struct TlsAcceptor(pub ());

impl tls_api::TlsAcceptor for TlsAcceptor {
    type Builder = TlsAcceptorBuilder;

    const IMPLEMENTED: bool = true;
    const SUPPORTS_ALPN: bool = false;
    const SUPPORTS_DER_KEYS: bool = false;
    const SUPPORTS_PKCS12_KEYS: bool = false;

    fn version() -> &'static str {
        crate::version()
    }

    fn accept<'a, S>(&'a self, stream: S) -> BoxFuture<'a, tls_api::Result<tls_api::TlsStream<S>>>
    where
        S: AsyncSocket + fmt::Debug + Unpin,
    {
        BoxFuture::new(async { Ok(tls_api::TlsStream::new(crate::stream::TlsStream(stream))) })
    }
}
