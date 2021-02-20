use void::Void;

use tls_api::AsyncSocket;
use tls_api::BoxFuture;
use tls_api::ImplInfo;

use crate::Error;

/// Non-instantiatable.
pub struct TlsAcceptorBuilder(Void);
/// Non-instantiatable.
pub struct TlsAcceptor(Void);

impl tls_api::TlsAcceptorBuilder for TlsAcceptorBuilder {
    type Acceptor = TlsAcceptor;

    type Underlying = Void;

    fn set_alpn_protocols(&mut self, _protocols: &[&[u8]]) -> tls_api::Result<()> {
        Err(tls_api::Error::new(Error))
    }

    fn underlying_mut(&mut self) -> &mut Void {
        &mut self.0
    }

    fn build(self) -> tls_api::Result<TlsAcceptor> {
        Err(tls_api::Error::new(Error))
    }
}

impl tls_api::TlsAcceptor for TlsAcceptor {
    type Builder = TlsAcceptorBuilder;

    const IMPLEMENTED: bool = false;
    const SUPPORTS_ALPN: bool = false;
    const SUPPORTS_DER_KEYS: bool = false;
    const SUPPORTS_PKCS12_KEYS: bool = false;

    type Underlying = Void;

    fn underlying_mut(&mut self) -> &mut Self::Underlying {
        &mut self.0
    }

    fn info() -> ImplInfo {
        crate::info()
    }

    fn accept_with_socket<'a, S>(
        &'a self,
        _stream: S,
    ) -> BoxFuture<'a, tls_api::Result<tls_api::TlsStreamWithSocket<S>>>
    where
        S: AsyncSocket,
    {
        BoxFuture::new(async { Err(tls_api::Error::new(Error)) })
    }
}
