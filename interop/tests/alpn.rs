//! Invoke `tls_api_test::alpn` with various implementations

// Dummy test to help Idea regognise this file is a test
#[test]
fn dummy() {}

// All permutations.
include!(concat!(env!("OUT_DIR"), "/alpn.rs"));
