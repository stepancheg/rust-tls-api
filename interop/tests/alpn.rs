//! Invoke `tls_api_test::alpn` with various implementations

// All permutations.
include!(concat!(env!("OUT_DIR"), "/alpn.rs"));
