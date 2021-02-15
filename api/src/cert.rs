#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Pem(pub String);
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Der(pub Vec<u8>);

// X.509 certificate
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum Cert {
    Pem(Pem),
    Der(Der),
}

impl Cert {
    pub fn into_der(self) -> Option<Der> {
        // TODO: there are methods to convert PEM->DER which might be used here
        match self {
            Cert::Der(d) => Some(d),
            _ => None,
        }
    }
    pub fn into_pem(self) -> Option<Pem> {
        // TODO: there are methods to convert DER->PEM which might be used here
        match self {
            Cert::Pem(p) => Some(p),
            _ => None,
        }
    }
}
