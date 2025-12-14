use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub type ScalarField = Fr;
pub type PairingCurve = Bn254;

#[derive(Error, Debug)]
pub enum SerdeError {
    #[error("serialization error: {0}")]
    Serialize(#[from] SerializationError),
    #[error("base64 error: {0}")]
    Base64(#[from] base64::DecodeError),
}

fn to_base64<T: CanonicalSerialize>(value: &T) -> Result<String, SerializationError> {
    let mut bytes = Vec::new();
    value.serialize_compressed(&mut bytes)?;
    Ok(BASE64.encode(bytes))
}

fn from_base64<T: CanonicalDeserialize>(value: &str) -> Result<T, SerdeError> {
    let bytes = BASE64.decode(value)?;
    let mut slice = bytes.as_slice();
    Ok(T::deserialize_compressed(&mut slice)?)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SerdeAsBase64<T>(pub T);

impl<T> Serialize for SerdeAsBase64<T>
where
    T: CanonicalSerialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let encoded = to_base64(&self.0).map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&encoded)
    }
}

impl<'de, T> Deserialize<'de> for SerdeAsBase64<T>
where
    T: CanonicalDeserialize,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        let value = from_base64(&encoded).map_err(serde::de::Error::custom)?;
        Ok(Self(value))
    }
}

pub type SerdeFr = SerdeAsBase64<ScalarField>;
pub type SerdeG1Affine = SerdeAsBase64<G1Affine>;
pub type SerdeG2Affine = SerdeAsBase64<G2Affine>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProofKind {
    Main,
    BallotInclusion,
    Receipt,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditPolyState {
    pub label: String,
    pub blinding_coeffs: Vec<SerdeFr>,
    pub poly_coeffs: Vec<SerdeFr>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditState {
    pub rho_a: SerdeFr,
    pub rho_m: SerdeFr,
    pub polys: Vec<AuditPolyState>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitmentWrapper {
    pub value: SerdeG1Affine,
}

impl From<G1Affine> for CommitmentWrapper {
    fn from(cm: G1Affine) -> Self {
        Self {
            value: SerdeAsBase64(cm),
        }
    }
}

impl TryFrom<CommitmentWrapper> for G1Affine {
    type Error = SerdeError;

    fn try_from(value: CommitmentWrapper) -> Result<Self, Self::Error> {
        Ok(value.value.0)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenEval {
    pub value: SerdeFr,
    pub blinding: SerdeFr,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchOpening {
    pub point: SerdeFr,
    pub gamma: SerdeFr,
    pub witness: SerdeG1Affine,
    pub polys: Vec<String>,
    pub evaluations: Vec<OpenEval>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NamedCommitment {
    pub label: String,
    pub commitment: CommitmentWrapper,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicInputs {
    pub n: usize,
    pub candidates: usize,
    pub sum_a_ballots: u64,
    pub sum_m: u64,
    pub tally: Vec<u64>,
    #[serde(default)]
    pub shuffle_hash: Option<String>,
    #[serde(default)]
    pub receipt_root: Option<String>,
    #[serde(default)]
    pub disputed_code: Option<u64>,
    #[serde(default)]
    pub ballot_index: Option<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof {
    pub kind: ProofKind,
    pub commitments: Vec<NamedCommitment>,
    pub openings: Vec<BatchOpening>,
    pub alpha: SerdeFr,
    pub zeta: SerdeFr,
    #[serde(default)]
    pub beta: Option<SerdeFr>,
    pub public: PublicInputs,
    #[serde(default)]
    pub r: Option<SerdeFr>,
    #[serde(default)]
    pub audit_state: Option<AuditState>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::AffineRepr;

    #[test]
    fn serde_roundtrip_fr() {
        let fr = ScalarField::from(42u64);
        let encoded = to_base64(&fr).unwrap();
        let decoded: ScalarField = from_base64(&encoded).unwrap();
        assert_eq!(fr, decoded);
    }

    #[test]
    fn serde_roundtrip_commitment_wrapper() {
        let cm = G1Affine::generator();
        let wrapper = CommitmentWrapper::from(cm);
        let back: G1Affine = wrapper.try_into().unwrap();
        assert_eq!(cm, back);
    }
}
