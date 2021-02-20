use std::fmt;
use tls_api::AsyncSocket;
use tls_api::BoxFuture;
use tls_api::ImplInfo;

pub struct TlsAcceptorBuilder(pub ());

impl tls_api::TlsAcceptorBuilder for TlsAcceptorBuilder {
    type Acceptor = TlsAcceptor;
    type Underlying = ();

    fn set_alpn_protocols(&mut self, protocols: &[&[u8]]) -> tls_api::Result<()> {
        let _ = protocols;
        Err(crate::Error::Alpn.into())
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

    type Underlying = ();

    fn underlying_mut(&mut self) -> &mut Self::Underlying {
        &mut self.0
    }

    fn info() -> ImplInfo {
        crate::info()
    }

    fn accept_with_socket<'a, S>(
        &'a self,
        stream: S,
    ) -> BoxFuture<'a, tls_api::Result<tls_api::TlsStreamWithSocket<S>>>
    where
        S: AsyncSocket + fmt::Debug + Unpin,
    {
        BoxFuture::new(async {
            Ok(tls_api::TlsStreamWithSocket::new(crate::stream::TlsStream(
                stream,
            )))
        })
    }
}
