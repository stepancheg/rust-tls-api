use std::cell::Cell;
use std::ptr;
use std::task::Context;

thread_local! {
    pub static CONTEXT: Cell<*mut ()> = Cell::new(ptr::null_mut());
}

struct RestoreOnDrop(*mut ());

impl Drop for RestoreOnDrop {
    fn drop(&mut self) {
        CONTEXT.with(|cell| {
            cell.set(self.0);
        })
    }
}

/// Store future context in the thread local.
pub fn save_context<R>(context: &mut Context<'_>, callback: impl FnOnce() -> R) -> R {
    CONTEXT.with(|cell| {
        let prev = cell.replace(context as *mut Context<'_> as *mut ());
        let _restore_on_drop = RestoreOnDrop(prev);
        callback()
    })
}

/// Fetch future context from the thread local.
pub fn restore_context<R>(callback: impl FnOnce(&mut Context<'_>) -> R) -> R {
    CONTEXT.with(|cell| {
        let context = cell.replace(ptr::null_mut());
        let _restore_on_drop = RestoreOnDrop(context);
        assert!(!context.is_null());
        cell.set(ptr::null_mut());
        callback(unsafe { &mut *(context as *mut Context) })
    })
}
