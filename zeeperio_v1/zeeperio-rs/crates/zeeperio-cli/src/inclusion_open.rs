use std::collections::HashMap;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use ark_bn254::{Bn254, Fr};
use ark_ff::{One, UniformRand, Zero};
use ark_poly::{DenseUVPolynomial, EvaluationDomain, Radix2EvaluationDomain};
use ark_poly_commit::kzg10::{Commitment, Randomness};
use ark_poly_commit::PCRandomness;
use zeeperio_core::{derive_inclusion_permutation, load_election};
use zeeperio_kzg::{batch_check, batch_open, Srs, UniPoly};
use zeeperio_types::{AuditPolyState, AuditState, BatchOpening, Proof, SerdeAsBase64, SerdeFr};

#[derive(serde::Serialize, serde::Deserialize)]
pub struct InclusionOpeningsBundle {
    pub ballot_index: usize,
    pub ballot_id: String,
    pub positions: Vec<usize>,
    pub openings: Vec<BatchOpening>,
    pub candidates: usize,
    pub bid: SerdeFr,
}

fn poly_and_random(state: &AuditState, label: &str) -> Result<(UniPoly, Randomness<Fr, UniPoly>)> {
    let entry: &AuditPolyState = state
        .polys
        .iter()
        .find(|p| p.label == label)
        .ok_or_else(|| anyhow!("missing poly {label} in private state"))?;
    let poly = UniPoly::from_coefficients_vec(entry.poly_coeffs.iter().map(|c| c.0).collect());
    let mut rand = Randomness::<Fr, UniPoly>::empty();
    rand.blinding_polynomial =
        UniPoly::from_coefficients_vec(entry.blinding_coeffs.iter().map(|c| c.0).collect());
    Ok((poly, rand))
}

pub fn generate_inclusion_openings(
    proof: &Proof,
    election_path: &Path,
    srs: &Srs,
    ballot_index: usize,
    state: &AuditState,
) -> Result<InclusionOpeningsBundle> {
    if proof.kind != zeeperio_types::ProofKind::BallotInclusion {
        return Err(anyhow!("proof kind must be BallotInclusion"));
    }
    let data = load_election(election_path, proof.public.candidates).context("load election")?;
    let n = proof.public.n;
    let domain = Radix2EvaluationDomain::<Fr>::new(n).ok_or_else(|| anyhow!("invalid domain size"))?;

    let start = ballot_index
        .checked_mul(proof.public.candidates)
        .ok_or_else(|| anyhow!("ballot index overflow"))?;
    if start + proof.public.candidates > data.rows.len() {
        return Err(anyhow!("ballot index out of range for election data"));
    }
    let ballot_id = data.rows[start].ballot_id.clone();
    let bid_target = *data
        .bid_evals
        .get(start)
        .ok_or_else(|| anyhow!("missing bid evaluation for ballot"))?;

    let perm = derive_inclusion_permutation(&proof.public)?;
    if perm.len() != n {
        return Err(anyhow!("permutation length mismatch"));
    }
    let mut bid_shuffled = vec![Fr::zero(); perm.len()];
    let mut confirm_shuffled = vec![Fr::zero(); perm.len()];
    let mut mark_shuffled = vec![Fr::zero(); perm.len()];
    for (i, idx) in perm.iter().enumerate() {
        bid_shuffled[i] = data
            .bid_evals
            .get(*idx)
            .cloned()
            .ok_or_else(|| anyhow!("perm index out of range"))?;
        confirm_shuffled[i] = data
            .confirm_evals
            .get(*idx)
            .cloned()
            .ok_or_else(|| anyhow!("perm index out of range"))?;
        mark_shuffled[i] = data
            .mark_evals
            .get(*idx)
            .cloned()
            .ok_or_else(|| anyhow!("perm index out of range"))?;
    }
    let mut positions = Vec::<usize>::new();
    for (idx, val) in bid_shuffled.iter().enumerate() {
        if val == &bid_target {
            positions.push(idx);
        }
    }
    if positions.len() != proof.public.candidates {
        return Err(anyhow!(
            "expected {} positions for ballot, found {}",
            proof.public.candidates,
            positions.len()
        ));
    }

    let (poly_bid, rand_bid) = poly_and_random(state, "BIDSh")?;
    let (poly_confirm, rand_confirm) = poly_and_random(state, "CconfirmSh")?;
    let (poly_m, rand_m) = poly_and_random(state, "MSh")?;

    let mut openings = Vec::<BatchOpening>::new();
    let mut open_rng = rand::thread_rng();
    for pos in &positions {
        let point = domain.element(*pos);
        let polys_ref = vec![&poly_bid, &poly_confirm, &poly_m];
        let rands_ref = vec![&rand_bid, &rand_confirm, &rand_m];
        let gamma = Fr::rand(&mut open_rng);
        let (witness, evals, gamma) = batch_open(srs, &polys_ref, &rands_ref, point, gamma)?;
        openings.push(BatchOpening {
            point: SerdeAsBase64(point),
            gamma: SerdeAsBase64(gamma),
            witness: zeeperio_kzg::wrap_witness(&witness),
            polys: vec![
                "BIDSh".to_string(),
                "CconfirmSh".to_string(),
                "MSh".to_string(),
            ],
            evaluations: evals,
        });
    }

    Ok(InclusionOpeningsBundle {
        ballot_index,
        ballot_id,
        positions,
        openings,
        candidates: proof.public.candidates,
        bid: SerdeAsBase64(bid_target),
    })
}

pub fn verify_inclusion_openings(
    proof: &Proof,
    srs: &Srs,
    election_path: &Path,
    bundle: &InclusionOpeningsBundle,
) -> Result<()> {
    if proof.kind != zeeperio_types::ProofKind::BallotInclusion {
        return Err(anyhow!("proof kind must be BallotInclusion"));
    }
    let data = load_election(election_path, proof.public.candidates).context("load election")?;
    let n = proof.public.n;
    let domain =
        Radix2EvaluationDomain::<Fr>::new(n).ok_or_else(|| anyhow!("invalid domain size"))?;

    if bundle.candidates != proof.public.candidates {
        return Err(anyhow!(
            "candidate count mismatch: bundle {}, proof {}",
            bundle.candidates,
            proof.public.candidates
        ));
    }

    let start = bundle
        .ballot_index
        .checked_mul(proof.public.candidates)
        .ok_or_else(|| anyhow!("ballot index overflow"))?;
    if start + proof.public.candidates > data.rows.len() {
        return Err(anyhow!("ballot index out of range for election data"));
    }
    let expected_id = data.rows[start].ballot_id.clone();
    if bundle.ballot_id != expected_id {
        return Err(anyhow!("ballot id mismatch"));
    }
    let bid_target = data
        .bid_evals
        .get(start)
        .cloned()
        .ok_or_else(|| anyhow!("missing bid evaluation"))?;
    if bid_target != bundle.bid.0 {
        return Err(anyhow!("bundle bid does not match election data"));
    }

    let perm = derive_inclusion_permutation(&proof.public)?;
    let mut bid_shuffled = vec![Fr::zero(); perm.len()];
    let mut confirm_shuffled = vec![Fr::zero(); perm.len()];
    let mut mark_shuffled = vec![Fr::zero(); perm.len()];
    for (i, idx) in perm.iter().enumerate() {
        let src = *idx;
        bid_shuffled[i] = data
            .bid_evals
            .get(src)
            .cloned()
            .ok_or_else(|| anyhow!("perm index out of range"))?;
        confirm_shuffled[i] = data
            .confirm_evals
            .get(src)
            .cloned()
            .ok_or_else(|| anyhow!("perm index out of range"))?;
        mark_shuffled[i] = data
            .mark_evals
            .get(src)
            .cloned()
            .ok_or_else(|| anyhow!("perm index out of range"))?;
    }
    let mut expected_positions = Vec::<usize>::new();
    for (idx, val) in bid_shuffled.iter().enumerate() {
        if val == &bid_target {
            expected_positions.push(idx);
        }
    }
    if expected_positions.len() != proof.public.candidates {
        return Err(anyhow!(
            "expected {} positions, found {}",
            proof.public.candidates,
            expected_positions.len()
        ));
    }

    let mut bundle_positions_sorted = bundle.positions.clone();
    bundle_positions_sorted.sort_unstable();
    let mut expected_sorted = expected_positions.clone();
    expected_sorted.sort_unstable();
    if bundle_positions_sorted != expected_sorted {
        return Err(anyhow!("positions do not match shuffled ballot locations"));
    }
    if bundle.positions.len() != bundle.openings.len() {
        return Err(anyhow!("positions/openings length mismatch"));
    }

    let vk = srs.verifier_key();
    let commitment_map: HashMap<String, Commitment<Bn254>> = proof
        .commitments
        .iter()
        .map(|c| {
            (
                c.label.clone(),
                Commitment::<Bn254>(
                    ark_bn254::G1Affine::try_from(c.commitment.clone()).expect("commitment parse"),
                ),
            )
        })
        .collect();
    batch_check(&vk, &bundle.openings, &commitment_map)
        .map_err(|_| anyhow!("pairing check failed"))?;

    let mut mark_sum = Fr::zero();
    for (pos, opening) in bundle.positions.iter().zip(bundle.openings.iter()) {
        let expected_point = domain.element(*pos);
        if opening.point.0 != expected_point {
            return Err(anyhow!("opening point mismatch for position {}", pos));
        }
        let mut bid_val = None;
        let mut mark_val = None;
        let mut confirm_val = None;
        for (idx, label) in opening.polys.iter().enumerate() {
            if label == "BIDSh" {
                bid_val = Some(opening.evaluations[idx].value.0);
            } else if label == "MSh" || label == "MShuffled" {
                mark_val = Some(opening.evaluations[idx].value.0);
            } else if label == "CconfirmSh" {
                confirm_val = Some(opening.evaluations[idx].value.0);
            }
        }
        let bid_val = bid_val.ok_or_else(|| anyhow!("missing BIDSh value"))?;
        if bid_val != bid_target {
            return Err(anyhow!("opened BID does not match target ballot"));
        }
        let expected_confirm = confirm_shuffled
            .get(*pos)
            .cloned()
            .ok_or_else(|| anyhow!("confirm position out of range"))?;
        let confirm_val = confirm_val.ok_or_else(|| anyhow!("missing CconfirmSh value"))?;
        if confirm_val != expected_confirm {
            return Err(anyhow!("confirmation value mismatch at position {}", pos));
        }
        let expected_mark = mark_shuffled
            .get(*pos)
            .cloned()
            .ok_or_else(|| anyhow!("mark position out of range"))?;
        let mark_val = mark_val.ok_or_else(|| anyhow!("missing MSh value"))?;
        if mark_val != expected_mark {
            return Err(anyhow!("mark value mismatch at position {}", pos));
        }
        if mark_val * (mark_val - Fr::one()) != Fr::zero() {
            return Err(anyhow!("mark value not boolean"));
        }
        mark_sum += mark_val;
    }

    if mark_sum != Fr::one() {
        return Err(anyhow!("expected exactly one mark = 1 for ballot"));
    }

    Ok(())
}
