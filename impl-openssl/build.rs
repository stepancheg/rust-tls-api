use std::env;

fn main() {
    match env::var("DEP_OPENSSL_VERSION").as_deref() {
        Ok("101") => {}
        Ok(v) if v >= "102" => {
            println!("cargo:rustc-cfg=has_alpn");
        }
        _ => panic!("tls-api-openssl: Unable to detect OpenSSL version"),
    }
}
