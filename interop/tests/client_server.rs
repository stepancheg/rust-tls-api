//! Invoke `tls_api_test::server` with various implementations

// Dummy test to help Idea regognise this file is a test
#[test]
fn dummy() {}

// All permutations.
include!(concat!(env!("OUT_DIR"), "/client_server.rs"));
