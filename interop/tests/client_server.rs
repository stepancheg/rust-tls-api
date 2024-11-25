//! Invoke `tls_api_test::server` with various implementations

// All permutations.
include!(concat!(env!("OUT_DIR"), "/client_server.rs"));
