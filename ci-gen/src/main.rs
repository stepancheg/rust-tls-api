use std::fs;
use std::path::Path;

use gh_actions_gen::actions::cargo_doc;
use gh_actions_gen::actions::cargo_test;
use gh_actions_gen::actions::checkout_sources;
use gh_actions_gen::actions::checkout_sources_depth;
use gh_actions_gen::actions::rust_install_toolchain;
use gh_actions_gen::actions::RustToolchain;
use gh_actions_gen::ghwf::Env;
use gh_actions_gen::ghwf::Job;
use gh_actions_gen::ghwf::Step;

fn crates_list() -> Vec<String> {
    assert!(Path::new("./ci-gen").exists());
    let mut r = Vec::new();
    for p in fs::read_dir(".").unwrap() {
        let p = p.unwrap();
        if Path::new(&format!("{}/Cargo.toml", p.path().display())).exists() {
            r.push(p.path().file_name().unwrap().to_str().unwrap().to_owned());
        }
    }
    r.sort();
    assert!(r.len() > 3);
    r
}

fn steps(rt: &str, channel: RustToolchain) -> Vec<Step> {
    let mut r = vec![checkout_sources(), rust_install_toolchain(channel)];
    for c in crates_list() {
        let mut args = format!("--manifest-path={}/Cargo.toml", c);
        match c.as_str() {
            "ci-gen" | "test-cert-gen" => {}
            _ => {
                args.push_str(&format!(" --no-default-features --features={}", rt));
            }
        }
        let mut step = cargo_test(&format!("cargo test {}", c), &args);
        step.timeout_minutes = Some(5);
        r.push(step);
    }
    r
}

fn runtimes() -> Vec<&'static str> {
    vec!["runtime-tokio", "runtime-async-std"]
}

#[derive(PartialEq, Eq, Copy, Clone)]
struct Os {
    name: &'static str,
    ghwf: Env,
}

const LINUX: Os = Os {
    name: "linux",
    ghwf: Env::UbuntuLatest,
};
const MACOS: Os = Os {
    name: "macos",
    ghwf: Env::MacosLatest,
};
const _WINDOWS: Os = Os {
    name: "windows",
    ghwf: Env::WindowsLatest,
};

fn super_linter_job() -> Job {
    let mut steps = Vec::new();
    steps.push(checkout_sources_depth(Some(0)));
    steps.push(
        Step::uses("super-linter", "github/super-linter@v3")
            .env("VALIDATE_ALL_CODEBASE", "false")
            .env("DEFAULT_BRANCH", "master")
            .env("GITHUB_TOKEN", "${{ secrets.GITHUB_TOKEN }}")
            // Too many false positives
            .env("VALIDATE_JSCPD", "false")
            // Too many dull reports like how we should pluralise variable names
            .env("VALIDATE_PROTOBUF", "false"),
    );
    Job {
        id: "super-linter".to_owned(),
        name: "super-linter".to_owned(),
        runs_on: LINUX.ghwf,
        steps,
        ..Default::default()
    }
}

fn rustfmt_job() -> Job {
    let os = LINUX;
    let mut steps = Vec::new();
    steps.push(checkout_sources());
    Job {
        id: "rustfmt-check".to_owned(),
        name: "rustfmt check".to_owned(),
        runs_on: os.ghwf,
        steps,
        ..Default::default()
    }
}

fn cargo_doc_job() -> Job {
    let os = LINUX;
    let mut steps = Vec::new();
    steps.push(checkout_sources());
    steps.push(rust_install_toolchain(RustToolchain::Stable));
    steps.push(cargo_doc("cargo doc", ""));
    Job {
        id: "cargo-doc".to_owned(),
        name: "cargo doc".to_owned(),
        runs_on: os.ghwf,
        steps,
        ..Default::default()
    }
}

fn jobs() -> Vec<Job> {
    let mut r = Vec::new();
    for rt in runtimes() {
        for &channel in &[
            RustToolchain::Stable,
            RustToolchain::Beta,
            RustToolchain::Nightly,
        ] {
            for &os in &[LINUX, MACOS] {
                if channel == RustToolchain::Beta && os == MACOS {
                    // skip some jobs because macos is expensive
                    continue;
                }
                r.push(Job {
                    id: format!("{}-{}-{}", rt, os.name, channel),
                    name: format!("{} {} {}", rt, os.name, channel),
                    runs_on: os.ghwf,
                    steps: steps(rt, channel),
                    ..Default::default()
                });
            }
        }
    }

    r.push(cargo_doc_job());

    r.push(rustfmt_job());
    r.push(super_linter_job());

    r
}

fn main() {
    gh_actions_gen::write(jobs());
}
