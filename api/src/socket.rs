use crate::runtime::AsyncRead;
use crate::runtime::AsyncWrite;
use std::fmt;

/// Type alias for necessary socket async traits.
///
/// Type alias exists to avoid repetition of traits in function signatures.
pub trait AsyncSocket: AsyncRead + AsyncWrite + fmt::Debug + Unpin + Send + 'static {}

/// Auto-implement for all socket types.
impl<A: AsyncRead + AsyncWrite + fmt::Debug + Unpin + Send + 'static> AsyncSocket for A {}
