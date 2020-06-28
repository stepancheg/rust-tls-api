use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::Path;

#[derive(Clone)]
enum Yaml {
    String(String),
    List(Vec<Yaml>),
    Map(Vec<(String, Yaml)>),
}

impl From<&Yaml> for Yaml {
    fn from(y: &Yaml) -> Self {
        y.clone()
    }
}

impl From<&str> for Yaml {
    fn from(s: &str) -> Self {
        Yaml::String(s.to_owned())
    }
}

impl From<&&str> for Yaml {
    fn from(s: &&str) -> Self {
        Yaml::String((*s).to_owned())
    }
}

impl<T: Into<Yaml>> From<Vec<T>> for Yaml {
    fn from(v: Vec<T>) -> Self {
        Yaml::List(v.into_iter().map(|t| t.into()).collect())
    }
}

impl Yaml {
    fn map<K: Into<String>, V: Into<Yaml>, E: IntoIterator<Item = (K, V)>>(entries: E) -> Yaml {
        Yaml::Map(
            entries
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        )
    }

    fn list<V: Into<Yaml>, E: IntoIterator<Item = V>>(values: E) -> Yaml {
        Yaml::List(values.into_iter().map(|v| v.into()).collect())
    }

    fn string<S: Into<String>>(s: S) -> Yaml {
        Yaml::String(s.into())
    }
}

#[derive(Default)]
struct Writer {
    buffer: String,
    indent: u32,
    minus: MinusState,
}

#[derive(Eq, PartialEq)]
enum MinusState {
    No,
    Yes,
    Already,
}

impl Default for MinusState {
    fn default() -> Self {
        MinusState::No
    }
}

impl Writer {
    fn write_line(&mut self, line: &str) {
        if line.is_empty() {
            self.buffer.push_str("\n");
        } else {
            for _ in 0..self.indent {
                self.buffer.push_str("    ");
            }

            match self.minus {
                MinusState::No => {}
                MinusState::Yes => {
                    self.buffer.push_str("- ");
                    self.minus = MinusState::Already;
                }
                MinusState::Already => {
                    self.buffer.push_str("  ");
                }
            }

            self.buffer.push_str(line);
            self.buffer.push_str("\n");
        }
    }

    fn write_yaml(&mut self, yaml: &Yaml) {
        match yaml {
            Yaml::String(s) => {
                self.write_line(s);
            }
            Yaml::List(l) => {
                for x in l {
                    assert!(self.minus == MinusState::No);
                    self.minus = MinusState::Yes;
                    self.write_yaml(x);
                    assert!(self.minus != MinusState::No);
                    self.minus = MinusState::No;
                }
            }
            Yaml::Map(m) => {
                for (k, v) in m {
                    match v {
                        Yaml::String(v) => {
                            self.write_line(&format!("{}: {}", k, v));
                        }
                        _ => {
                            self.write_line(&format!("{}:", k));
                            self.indent += 1;
                            self.write_yaml(v);
                            self.indent -= 1;
                        }
                    }
                }
            }
        }
    }
}

fn name_uses(name: &str, uses: &str) -> Yaml {
    Yaml::map(vec![("name", name), ("uses", uses)])
}

fn name_uses_with(name: &str, uses: &str, with: Yaml) -> Yaml {
    Yaml::map(vec![
        ("name", Yaml::string(name)),
        ("uses", Yaml::string(uses)),
        ("with", with),
    ])
}

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

fn steps(rt: &str) -> Vec<Yaml> {
    let mut r = vec![
        name_uses("Checkout sources", "actions/checkout@v2"),
        name_uses_with(
            "Install toolchain",
            "actions-rs/toolchain@v1",
            Yaml::map(vec![
                ("profile", "minimal"),
                ("toolchain", "${{ matrix.channel }}"),
                ("override", "true"),
            ]),
        ),
    ];
    for c in crates_list() {
        let mut args = format!("--manifest-path={}/Cargo.toml", c);
        if c != "ci-gen" {
            args.push_str(&format!(" --no-default-features --features={}", rt));
        }
        r.push(name_uses_with(
            &format!("cargo test {}", c),
            "actions-rs/cargo@v1",
            Yaml::map(vec![("command", "test"), ("args", &args)]),
        ));
    }
    r
}

fn runtimes() -> Vec<&'static str> {
    vec!["runtime-tokio", "runtime-async-std"]
}

fn jobs() -> Yaml {
    let mut r = Vec::new();
    for rt in runtimes() {
        r.push((
            format!("{}", rt),
            Yaml::map(vec![
                (
                    "name",
                    Yaml::string(format!("{} ${{{{ matrix.channel }}}}", rt)),
                ),
                ("runs-on", Yaml::string("ubuntu-latest")),
                (
                    "strategy",
                    Yaml::map(vec![(
                        "matrix",
                        Yaml::map(vec![(
                            "channel",
                            Yaml::list(&["stable", "beta", "nightly"]),
                        )]),
                    )]),
                ),
                ("steps", Yaml::list(steps(rt))),
            ]),
        ))
    }
    Yaml::map(r)
}

fn main() {
    let yaml = Yaml::map(vec![
        ("on", Yaml::list(vec!["push", "pull_request"])),
        ("name", Yaml::string("CI")),
        ("jobs", jobs()),
    ]);

    let mut writer = Writer::default();
    writer.write_line(&format!(
        "# @generated by {}, do not edit",
        env!("CARGO_PKG_NAME")
    ));
    writer.write_line("");
    writer.write_yaml(&yaml);
    File::create(".github/workflows/ci.yml")
        .unwrap()
        .write_all(writer.buffer.as_bytes())
        .unwrap();
}
