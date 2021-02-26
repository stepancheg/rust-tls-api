#![cfg(all(rustc_nightly, feature = "runtime-tokio"))]
#![feature(test)]

include!(concat!(env!("OUT_DIR"), "/benches_generated.rs"));

#[bench] // Tell Idea this file is a bench
fn dummy(_b: &mut test::Bencher) {}
