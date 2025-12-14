use std::collections::HashMap;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use ark_bn254::{Bn254, Fr, G1Affine};
use ark_ff::UniformRand;
use ark_poly::{DenseUVPolynomial, EvaluationDomain, Radix2EvaluationDomain};
use ark_poly_commit::kzg10::{Commitment, Randomness};
use ark_poly_commit::PCRandomness;
use zeeperio_core::load_election;
use zeeperio_kzg::{batch_check, batch_open, Srs, UniPoly};
use zeeperio_types::{BatchOpening, Proof};

#[derive(serde::Serialize, serde::Deserialize)]
pub struct AuditOpeningBundle {
    pub openings: Vec<BatchOpening>,
    pub audited_indices: Vec<usize>,
    pub ballots: Vec<String>,
}

pub fn generate_audit_openings(
    election_path: &Path,
    proof: &Proof,
    srs: &Srs,
    audit_ids: &[String],
    audit_state: &zeeperio_types::AuditState,
) -> Result<AuditOpeningBundle> {
    let data = load_election(election_path, proof.public.candidates).context("load election")?;
    let n = proof.public.n;
    let domain = Radix2EvaluationDomain::<Fr>::new(n).ok_or_else(|| anyhow!("invalid domain"))?;

    let to_poly = |label: &str| -> Result<UniPoly> {
        let entry = audit_state
            .polys
            .iter()
            .find(|p| p.label == label)
            .ok_or_else(|| anyhow!("missing poly {label}"))?;
        Ok(UniPoly::from_coefficients_vec(
            entry.poly_coeffs.iter().map(|c| c.0).collect(),
        ))
    };
    let masked_a = to_poly("A")?;
    let masked_m = to_poly("M")?;

    let mut rand_map: HashMap<String, Randomness<Fr, UniPoly>> = HashMap::new();
    for p in &audit_state.polys {
        let coeffs = p.blinding_coeffs.iter().map(|c| c.0).collect::<Vec<_>>();
        let rand_poly = UniPoly::from_coefficients_vec(coeffs);
        let mut base = Randomness::<Fr, UniPoly>::empty();
        base.blinding_polynomial = rand_poly;
        rand_map.insert(p.label.clone(), base);
    }

    let mut openings = Vec::<BatchOpening>::new();
    let mut audited_indices = Vec::<usize>::new();
    let mut ballots = Vec::<String>::new();

    for bid in audit_ids {
        if let Some((row_idx, _)) = data
            .rows
            .iter()
            .enumerate()
            .find(|(_, r)| &r.ballot_id == bid)
        {
            let start = (row_idx / proof.public.candidates) * proof.public.candidates;
            ballots.push(bid.clone());
            for offset in 0..proof.public.candidates {
                let idx = start + offset;
                audited_indices.push(idx);
                let point = domain.element(idx);
                let polys_ref = vec![&masked_a, &masked_m];
                let rand_ref = vec![
                    rand_map.get("A").ok_or_else(|| anyhow!("missing rand A"))?,
                    rand_map.get("M").ok_or_else(|| anyhow!("missing rand M"))?,
                ];
                let gamma = Fr::rand(&mut rand::thread_rng());
                let (witness, evals, gamma) = batch_open(srs, &polys_ref, &rand_ref, point, gamma)?;
                openings.push(BatchOpening {
                    point: zeeperio_types::SerdeAsBase64(point),
                    gamma: zeeperio_types::SerdeAsBase64(gamma),
                    witness: zeeperio_kzg::wrap_witness(&witness),
                    polys: vec!["A".to_string(), "M".to_string()],
                    evaluations: evals,
                });
            }
        }
    }

    Ok(AuditOpeningBundle {
        openings,
        audited_indices,
        ballots,
    })
}

pub fn verify_audit_openings(proof: &Proof, srs: &Srs, bundle: &AuditOpeningBundle) -> Result<()> {
    let vk = srs.verifier_key();
    let commitment_map: HashMap<String, Commitment<Bn254>> = proof
        .commitments
        .iter()
        .map(|c| {
            (
                c.label.clone(),
                Commitment::<Bn254>(
                    G1Affine::try_from(c.commitment.clone()).expect("commitment parse"),
                ),
            )
        })
        .collect();

    batch_check(&vk, &bundle.openings, &commitment_map).map_err(|_| anyhow!("pairing check failed"))
}
