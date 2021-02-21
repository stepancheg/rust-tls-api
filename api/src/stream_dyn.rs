use crate::AsyncSocket;
use crate::ImplInfo;

/// Trait implemented by all `TlsStream` objects.
///
/// Provide access to some TLS stream properties (only ALPN at the moment.)
pub trait TlsStreamDyn: AsyncSocket {
    /// Get negotiated ALPN protocol negotiated.
    fn get_alpn_protocol(&self) -> crate::Result<Option<Vec<u8>>>;

    /// Implementation info for this stream (e. g. which crate provides it).
    fn impl_info(&self) -> ImplInfo;

    /// Get the underlying socket.
    fn get_socket_dyn_mut(&mut self) -> &mut dyn AsyncSocket;

    /// Get the underlying socket.
    fn get_socket_dyn_ref(&self) -> &dyn AsyncSocket;
}

/// Get the underlying socket.
pub trait TlsStreamWithSocketDyn<S>: TlsStreamDyn {
    /// Get the underlying socket.
    fn get_socket_mut(&mut self) -> &mut S;

    /// Get the underlying socket.
    fn get_socket_ref(&self) -> &S;
}

/// Interface upcast. This is an interface for API implementors.
pub trait TlsStreamWithUpcastDyn<S>: TlsStreamWithSocketDyn<S> {
    /// Upcast.
    fn upcast_box(self: Box<Self>) -> Box<dyn TlsStreamDyn>;
}
