#![allow(dead_code)]

pub(crate) fn assert_sync<T: Sync>() {}
pub(crate) fn assert_send<T: Send>() {}
pub(crate) fn assert_send_value<T: Send>(t: T) -> T {
    t
}
