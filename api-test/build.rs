use std::env;
use std::io::Read;
use std::process;

fn export_rustc_cfg() {
    let rustc = env::var("RUSTC").expect("RUSTC unset");

    let mut child = process::Command::new(rustc)
        .args(["--version"])
        .stdin(process::Stdio::null())
        .stdout(process::Stdio::piped())
        .spawn()
        .expect("spawn rustc");

    let mut rustc_version = String::new();

    child
        .stdout
        .as_mut()
        .expect("stdout")
        .read_to_string(&mut rustc_version)
        .expect("read_to_string");
    assert!(child.wait().expect("wait").success());
}

fn main() {
    export_rustc_cfg();
}
