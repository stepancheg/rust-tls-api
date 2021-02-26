use std::env;

fn main() {
    // Keep in sync with
    // https://github.com/sfackler/rust-openssl/blob/master/openssl-sys/build/main.rs

    // `openssl` crate could export that instead of `openssl-sys`, we need
    // https://github.com/rust-lang/cargo/issues/3544 for this.
    match (
        env::var("DEP_OPENSSL_VERSION").as_deref(),
        env::var("DEP_OPENSSL_LIBRESSL_VERSION").as_deref(),
    ) {
        (_, Ok(v)) => {
            assert_eq!(3, v.len());
            if v >= "261" {
                println!("cargo:rustc-cfg=has_alpn");
            }
        }
        (Ok(v), _) => {
            assert_eq!(3, v.len());
            if v >= "102" {
                println!("cargo:rustc-cfg=has_alpn");
            }
        }
        (Err(_), Err(_)) => panic!("tls-api-openssl: Unable to detect OpenSSL version"),
    }

    tls_api_test::gen_tests_and_benches();
}
