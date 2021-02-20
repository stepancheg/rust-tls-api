//! Interfaces needed by API implementor (like `tls-api-rustls`),
//! and not needed by the users of API.

pub use crate::stream::TlsStreamDyn;
pub use crate::stream::TlsStreamImpl;

pub mod async_as_sync;

mod thread_local_context;

pub use thread_local_context::restore_context;
pub use thread_local_context::save_context;
