use std::env;

fn main() {
    match env::var("DEP_OPENSSL_VERSION") {
        Ok(ref v) if v == "101" => {}
        Ok(ref v) if v >= &"102".to_string() => {
            println!("cargo:rustc-cfg=has_alpn");
        }
        _ => panic!("tls-api-openssl: Unable to detect OpenSSL version"),
    }
}
