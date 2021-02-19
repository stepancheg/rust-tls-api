//! Wrapper over `security-framework`.
//!
//! This crate is available on non-iOS or non-macOS, but most operations
//! simply return error.

mod stream;

mod acceptor;
mod connector;
mod handshake;

pub use acceptor::SecureTransportTlsAcceptorBuilder;
pub use acceptor::TlsAcceptor;
pub use acceptor::TlsAcceptorBuilder;
pub use connector::TlsConnector;
pub use connector::TlsConnectorBuilder;

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub(crate) use stream::TlsStream;

#[allow(dead_code)]
pub(crate) fn not_ios_or_macos<T>() -> tls_api::Result<T> {
    Err(tls_api::Error::new_other("not iOS or macOS"))
}

pub(crate) fn version() -> &'static str {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        "unknown"
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    {
        "not iOS or macOS"
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub(crate) const IMPLEMENTED: bool = true;
#[cfg(not(any(target_os = "macos", target_os = "ios")))]
pub(crate) const IMPLEMENTED: bool = false;
