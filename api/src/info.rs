use crate::assert_send;
use crate::assert_sync;
use std::fmt;

/// Basic info about the implementation.
#[derive(Debug, Clone, Default)]
pub struct ImplInfo {
    /// Implementation name (usually the name of crate the underlying implementation).
    pub name: &'static str,
    /// Some unspecified version number (e. g. openssl library version for openssl implementation).
    pub version: &'static str,
}

fn _assert_kinds() {
    assert_send::<ImplInfo>();
    assert_sync::<ImplInfo>();
}

impl fmt::Display for ImplInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}={}", self.name, self.version)
    }
}
