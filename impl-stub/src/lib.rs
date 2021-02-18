//! Stub implementation of TLS API.
//!
//! All operations return error. No objects can be instantiated.
//!
//! Can be useful when you need a type parameter of type e. g. `TlsConnector`:
//!
//! ```
//! use tls_api_stub::TlsConnector;
//!
//! let no_connector: Option<TlsConnector> = None;
//! ```

use std::error::Error as std_Error;
use std::fmt;

mod stream;

mod acceptor;
mod connector;

pub use acceptor::TlsAcceptor;
pub use acceptor::TlsAcceptorBuilder;
pub use connector::TlsConnector;
pub use connector::TlsConnectorBuilder;

#[derive(Debug)]
struct Error;

impl std_Error for Error {
    fn description(&self) -> &str {
        "stub implementation"
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "stub implementation")
    }
}
