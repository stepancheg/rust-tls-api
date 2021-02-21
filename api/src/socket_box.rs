use std::any::TypeId;
use std::mem;
use std::mem::MaybeUninit;
use std::pin::Pin;
use std::ptr;

use crate::assert_send;
use crate::spi_async_socket_impl_delegate;
use crate::AsyncSocket;

/// Newtype for [`Box<dyn AsyncSocket>`](AsyncSocket).
#[derive(Debug)]
pub struct AsyncSocketBox(Box<dyn AsyncSocket>);

fn _assert_kinds() {
    assert_send::<AsyncSocketBox>();
}

fn transmute_or_map<A: 'static, B: 'static>(a: A, f: impl FnOnce(A) -> B) -> B {
    if TypeId::of::<A>() == TypeId::of::<B>() {
        assert_eq!(mem::size_of::<A>(), mem::size_of::<B>());
        // Can be made safe with specialization.
        unsafe {
            let mut b = MaybeUninit::<B>::uninit();
            ptr::copy(&a as *const A, b.as_mut_ptr() as *mut A, 1);
            mem::forget(a);
            b.assume_init()
        }
    } else {
        f(a)
    }
}

impl AsyncSocketBox {
    /// Construct.
    pub fn new<S: AsyncSocket>(socket: S) -> AsyncSocketBox {
        transmute_or_map(socket, |socket| AsyncSocketBox(Box::new(socket)))
    }

    fn get_socket_pin_for_delegate(self: Pin<&mut Self>) -> Pin<&mut dyn AsyncSocket> {
        Pin::new(&mut self.get_mut().0)
    }

    fn get_socket_ref_for_delegate(&self) -> &dyn AsyncSocket {
        &self.0
    }
}

spi_async_socket_impl_delegate!(AsyncSocketBox);

fn _assert_async_socket_box_is_async_socket(s: AsyncSocketBox) {
    fn accepts_socket<S: AsyncSocket>(_: S) {}
    accepts_socket(s);
}
