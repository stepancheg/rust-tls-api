use std::future::Future;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;

/// Simple alias alias `Pin<Box<Future>>` for easier typechecker.
pub struct BoxFuture<'a, R>(Pin<Box<dyn Future<Output = R> + Send + 'a>>);

impl<'a, R> BoxFuture<'a, R> {
    /// Wrap a future.
    pub fn new(f: impl Future<Output = R> + Send + 'a) -> Self {
        BoxFuture(Box::pin(f))
    }
}

impl<'a, R> Future for BoxFuture<'a, R> {
    type Output = R;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.get_mut().0).poll(cx)
    }
}
