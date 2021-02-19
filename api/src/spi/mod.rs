//! Interfaces needed by API implementor (like `tls-api-rustls`),
//! and not needed by the users of API.

pub use crate::stream::TlsStreamImpl;

pub mod async_as_sync;
