use crate::yaml::Yaml;

/// Github workflow step
pub struct Step(pub Yaml);

impl Step {
    pub fn name_uses(name: &str, uses: &str) -> Step {
        Step(Yaml::map(vec![("name", name), ("uses", uses)]))
    }

    pub fn name_uses_with(name: &str, uses: &str, with: Yaml) -> Step {
        Step(Yaml::map(vec![
            ("name", Yaml::string(name)),
            ("uses", Yaml::string(uses)),
            ("with", with),
        ]))
    }
}

impl Into<Yaml> for Step {
    fn into(self) -> Yaml {
        self.0
    }
}
