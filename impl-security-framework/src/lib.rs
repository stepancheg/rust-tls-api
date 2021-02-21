//! [`tls_api`] implementation for `security_framework`.
//!
//! This crate is available on non-iOS or non-macOS, but most operations
//! simply return error. So code depending on this crate can be typechecked
//! without cargo target-specific setup and conditional compilation.

#![deny(broken_intra_doc_links)]
#![cfg_attr(not(any(target_os = "macos", target_os = "ios")), allow(dead_code))]

mod stream;

mod acceptor;
mod connector;
mod error;
mod handshake;

use tls_api::ImplInfo;

pub use acceptor::SecureTransportTlsAcceptorBuilder;
pub use acceptor::TlsAcceptor;
pub use acceptor::TlsAcceptorBuilder;
pub use connector::TlsConnector;
pub use connector::TlsConnectorBuilder;

pub(crate) use error::Error;

// TODO: some dummy otherwise
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub(crate) use stream::TlsStream;

#[allow(dead_code)]
pub(crate) fn not_ios_or_macos<T>() -> tls_api::Result<T> {
    Err(Error::NotIosOrMacos.into())
}

pub(crate) fn info() -> ImplInfo {
    ImplInfo {
        name: "security-framework",
        version: {
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            {
                "unknown"
            }
            #[cfg(not(any(target_os = "macos", target_os = "ios")))]
            {
                "not iOS or macOS"
            }
        },
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub(crate) const IMPLEMENTED: bool = true;
#[cfg(not(any(target_os = "macos", target_os = "ios")))]
pub(crate) const IMPLEMENTED: bool = false;
