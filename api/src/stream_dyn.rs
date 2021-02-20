use std::fmt;

use crate::runtime::AsyncRead;
use crate::runtime::AsyncWrite;
use crate::AsyncSocket;
use crate::ImplInfo;

/// Trait to be used by API implementors (like openssl),
/// not meant to be used of implemented directly.
pub trait TlsStreamDyn: AsyncRead + AsyncWrite + fmt::Debug + Unpin + Send + 'static {
    /// Get negotiated ALPN protocol negotiated.
    fn get_alpn_protocol(&self) -> crate::Result<Option<Vec<u8>>>;

    /// Implementation info for this stream (e. g. which crate provides it).
    fn impl_info(&self) -> ImplInfo;

    /// Get the underlying socket.
    fn get_socket_dyn_mut(&mut self) -> &mut dyn AsyncSocket;

    /// Get the underlying socket.
    fn get_socket_dyn_ref(&self) -> &dyn AsyncSocket;
}

/// Trait to be used by API implementors (like openssl),
/// not meant to be used of implemented directly.
pub trait TlsStreamImpl<S>: TlsStreamDyn {
    /// Upcast.
    fn upcast_box(self: Box<Self>) -> Box<dyn TlsStreamDyn>;

    /// Get the underlying socket.
    fn get_socket_mut(&mut self) -> &mut S;

    /// Get the underlying socket.
    fn get_socket_ref(&self) -> &S;
}
