use ark_bn254::Fr;
use ark_ff::{Field, One, Zero};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Polynomial,
    Radix2EvaluationDomain,
};
use ark_poly_commit::kzg10::{Commitment, Randomness};
use std::collections::{BTreeMap, HashMap};

use crate::{
    fr_key, load_election, mask_poly_simple_poly, poly_divide_qr, poly_is_zero, poly_mul,
    poly_scale_x, CoreError, PublicInputs, Transcript, POLY_ACC_SEL, POLY_CONFIRM, POLY_D, POLY_Q,
    POLY_SEL,
};
use zeeperio_kzg::{
    batch_open, commit, derive_batch_challenge, wrap_commitment, wrap_witness, Srs,
};
use zeeperio_types::{BatchOpening, NamedCommitment, Proof, ProofKind, SerdeAsBase64};

fn build_selector(n: usize, ballot_index: usize, candidates: usize) -> Vec<Fr> {
    let start = ballot_index * candidates;
    let end = start + candidates;
    (0..n)
        .map(|i| {
            if (start..end).contains(&i) {
                Fr::one()
            } else {
                Fr::zero()
            }
        })
        .collect()
}

fn build_accumulator(sel: &[Fr], d: &[Fr]) -> Vec<Fr> {
    let n = sel.len();
    let mut acc = vec![Fr::zero(); n];
    for i in (0..n).rev() {
        let term = sel[i] * d[i];
        if i + 1 < n {
            acc[i] = term + acc[i + 1];
        } else {
            acc[i] = term;
        }
    }
    acc
}

pub fn prove_receipt(
    election_path: &std::path::Path,
    public_inputs: &PublicInputs,
    srs: &Srs,
) -> Result<Proof, CoreError> {
    let disputed_code = public_inputs
        .disputed_code
        .ok_or(CoreError::MissingDisputeInput("disputed_code"))?;
    let ballot_index = public_inputs
        .ballot_index
        .ok_or(CoreError::MissingDisputeInput("ballot_index"))?;

    let data = load_election(election_path, public_inputs.candidates)?;
    let mut public = public_inputs.clone();
    public.n = data.n;
    public.candidates = data.candidates;

    let domain = Radix2EvaluationDomain::<Fr>::new(data.n).expect("domain");
    let confirm_poly =
        ark_poly::Evaluations::from_vec_and_domain(data.confirm_evals.clone(), domain)
            .interpolate();

    let disputed_fr = Fr::from(disputed_code);
    let d_evals: Vec<Fr> = data
        .confirm_evals
        .iter()
        .map(|c| {
            if (*c - disputed_fr).is_zero() {
                Fr::one()
            } else {
                Fr::zero()
            }
        })
        .collect();
    let d_poly = ark_poly::Evaluations::from_vec_and_domain(d_evals.clone(), domain).interpolate();

    let sel_evals = build_selector(domain.size(), ballot_index, public.candidates);
    let mut sel_poly =
        ark_poly::Evaluations::from_vec_and_domain(sel_evals.clone(), domain).interpolate();
    let acc_sel_evals = build_accumulator(&sel_evals, &d_evals);
    let mut acc_sel_poly =
        ark_poly::Evaluations::from_vec_and_domain(acc_sel_evals.clone(), domain).interpolate();

    let z_h_dense = DensePolynomial::from(domain.vanishing_polynomial());

    let mut transcript = Transcript::new();
    transcript.append_u64_as_fr(public.n as u64);
    transcript.append_u64_as_fr(public.candidates as u64);
    transcript.append_u64_as_fr(disputed_code);
    transcript.append_u64_as_fr(ballot_index as u64);

    let mut mask_counter = crate::ChallengeCounter::new("receipt-mask");
    sel_poly = mask_poly_simple_poly(&sel_poly, &z_h_dense, mask_counter.next(&transcript, "sel"));
    acc_sel_poly = mask_poly_simple_poly(
        &acc_sel_poly,
        &z_h_dense,
        mask_counter.next(&transcript, "acc_sel"),
    );

    let mut commitment_table: HashMap<
        String,
        (Commitment<ark_bn254::Bn254>, Randomness<Fr, crate::UniPoly>),
    > = HashMap::new();
    let mut named_commitments = Vec::<NamedCommitment>::new();
    let append_cm = |label: &str,
                     cm: &Commitment<ark_bn254::Bn254>,
                     list: &mut Vec<NamedCommitment>,
                     tr: &mut Transcript| {
        tr.append_commitment(&cm.0);
        list.push(NamedCommitment {
            label: label.to_string(),
            commitment: wrap_commitment(cm),
        });
    };

    let mut commit_counter = crate::ChallengeCounter::new("receipt-commit");
    for (label, poly) in [
        (POLY_CONFIRM, &confirm_poly),
        (POLY_D, &d_poly),
        (POLY_SEL, &sel_poly),
        (POLY_ACC_SEL, &acc_sel_poly),
    ] {
        let blinding =
            crate::derive_blinding_poly(&transcript, &mut commit_counter, label, poly.degree());
        let (cm, rand) = commit(poly, srs, Some(blinding))?;
        commitment_table.insert(label.to_string(), (cm, rand));
        append_cm(label, &cm, &mut named_commitments, &mut transcript);
    }

    let alpha = transcript.challenge_scalar(b"receipt-alpha");

    // Constraints
    let omega = domain.element(1);
    let last = omega.pow([(domain.size() - 1) as u64]);
    let z_h = DensePolynomial::from(domain.vanishing_polynomial());
    let lin_last = DensePolynomial::from_coefficients_vec(vec![-last, Fr::one()]);
    let (z1, _) = crate::poly_divide_qr(&z_h, &lin_last).expect("z1");
    let z2 = DensePolynomial::from_coefficients_vec(vec![-last, Fr::one()]);
    let lin_one = DensePolynomial::from_coefficients_vec(vec![-Fr::one(), Fr::one()]);
    let (z3, _) = crate::poly_divide_qr(&z_h, &lin_one).expect("z3");

    let sel_times_d = poly_mul(&sel_poly, &d_poly);
    let acc_shift = poly_scale_x(&acc_sel_poly, omega);

    let base_diff = crate::poly_sub(&acc_sel_poly, &sel_times_d);
    let p1 = poly_mul(&base_diff, &z1);
    let base_diff_shifted = crate::poly_sub(&base_diff, &acc_shift);
    let p2 = poly_mul(&base_diff_shifted, &z2);
    let p3 = poly_mul(&acc_sel_poly, &z3);

    let one_poly = crate::poly_const(Fr::one());
    let eq_d_bool = poly_mul(&d_poly, &crate::poly_sub(&d_poly, &one_poly));

    let pvanish = crate::aggregate_constraints_poly(alpha, vec![p1, p2, p3, eq_d_bool]);

    let (q_poly, remainder) = poly_divide_qr(&pvanish, &z_h_dense)?;
    if !poly_is_zero(&remainder) {
        return Err(CoreError::ConstraintViolation);
    }

    let blinding_q =
        crate::derive_blinding_poly(&transcript, &mut commit_counter, POLY_Q, q_poly.degree());
    let (cm_q, rand_q) = commit(&q_poly, srs, Some(blinding_q))?;
    append_cm(POLY_Q, &cm_q, &mut named_commitments, &mut transcript);
    commitment_table.insert(POLY_Q.to_string(), (cm_q.clone(), rand_q));

    let zeta = transcript.challenge_scalar(b"receipt-zeta");
    let confirm_at_zeta = confirm_poly.evaluate(&zeta);
    let d_at_zeta = d_poly.evaluate(&zeta);
    transcript.append_fr(&confirm_at_zeta);
    transcript.append_fr(&d_at_zeta);

    // Openings
    let mut openings = Vec::new();
    let mut point_map: BTreeMap<String, (Fr, Vec<String>)> = BTreeMap::new();
    let mut add_point = |pt: Fr, labels: Vec<String>| {
        let key = fr_key(&pt);
        point_map
            .entry(key)
            .and_modify(|(_, existing)| existing.extend(labels.iter().cloned()))
            .or_insert((pt, labels));
    };

    add_point(
        zeta,
        vec![
            POLY_CONFIRM.to_string(),
            POLY_D.to_string(),
            POLY_SEL.to_string(),
            POLY_ACC_SEL.to_string(),
            POLY_Q.to_string(),
        ],
    );
    add_point(zeta * omega, vec![POLY_ACC_SEL.to_string()]);

    let mut poly_map: HashMap<String, (&crate::UniPoly, &Randomness<Fr, crate::UniPoly>)> =
        HashMap::new();
    for (label, poly) in [
        (POLY_CONFIRM.to_string(), &confirm_poly),
        (POLY_D.to_string(), &d_poly),
        (POLY_SEL.to_string(), &sel_poly),
        (POLY_ACC_SEL.to_string(), &acc_sel_poly),
        (POLY_Q.to_string(), &q_poly),
    ] {
        let (_, blind) = commitment_table.get(&label).expect("blind");
        poly_map.insert(label, (poly, blind));
    }

    let mut opening_counter = crate::ChallengeCounter::new("receipt-open");
    for (idx, (_key, (point, mut labels))) in point_map.into_iter().enumerate() {
        labels.sort();
        labels.dedup();
        let mut polys_ref = Vec::new();
        let mut randoms = Vec::new();
        for label in &labels {
            let (poly, blind) = poly_map.get(label).unwrap();
            polys_ref.push(*poly);
            randoms.push(*blind);
        }
        let gamma = opening_counter.next(&transcript, &format!("opening-{idx}"));
        let (witness, evals, gamma) = batch_open(srs, &polys_ref, &randoms, point, gamma)?;
        openings.push(BatchOpening {
            point: SerdeAsBase64(point),
            gamma: SerdeAsBase64(gamma),
            witness: wrap_witness(&witness),
            polys: labels,
            evaluations: evals,
        });
    }

    let r = derive_batch_challenge(&openings);

    Ok(Proof {
        kind: ProofKind::Receipt,
        commitments: named_commitments,
        openings,
        alpha: SerdeAsBase64(alpha),
        zeta: SerdeAsBase64(zeta),
        beta: None,
        public,
        r: Some(SerdeAsBase64(r)),
        audit_state: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PublicInputs;
    use ark_bn254::{Bn254, G1Affine};
    use ark_ff::PrimeField;
    use ark_poly::Radix2EvaluationDomain;
    use std::path::PathBuf;
    use zeeperio_kzg::{batch_check, derive_batch_challenge};
    use zeeperio_types::ProofKind;

    fn workspace_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .unwrap()
            .to_path_buf()
    }

    fn srs_path() -> PathBuf {
        workspace_root().join("srs")
    }

    fn load_receipt_inputs(candidates: usize, election_path: &PathBuf) -> PublicInputs {
        let data = crate::load_election(election_path, candidates).unwrap();
        let mut sum_a = 0u64;
        let mut idx = 0;
        while idx < data.rows.len() {
            if data.rows[idx].audit_bit == 1 {
                sum_a += 1;
            }
            idx += candidates;
        }
        let sum_m = data.rows.iter().map(|r| r.mark_bit).sum::<u64>();
        let mut tally = vec![0u64; candidates];
        for (idx, row) in data.rows.iter().enumerate() {
            tally[idx % candidates] += row.mark_bit;
        }
        PublicInputs {
            n: data.n,
            candidates: data.candidates,
            sum_a_ballots: sum_a,
            sum_m,
            tally,
            shuffle_hash: None,
            receipt_root: None,
            disputed_code: None,
            ballot_index: None,
        }
    }

    fn get_eval(openings: &[BatchOpening], label: &str, point: &Fr) -> Option<Fr> {
        for opening in openings {
            if opening.point.0 != *point {
                continue;
            }
            for (idx, l) in opening.polys.iter().enumerate() {
                if l == label {
                    return Some(opening.evaluations[idx].value.0);
                }
            }
        }
        None
    }

    fn constraints_at_zeta_receipt(
        alpha: Fr,
        zeta: Fr,
        omega: Fr,
        pub_inputs: &PublicInputs,
        openings: &[BatchOpening],
    ) -> Result<(Fr, Fr, Fr, Fr, Fr), String> {
        let confirm = get_eval(openings, POLY_CONFIRM, &zeta).ok_or("confirm missing")?;
        let d = get_eval(openings, POLY_D, &zeta).ok_or("d missing")?;
        let sel = get_eval(openings, POLY_SEL, &zeta).ok_or("sel missing")?;
        let acc_sel = get_eval(openings, POLY_ACC_SEL, &zeta).ok_or("acc sel missing")?;
        let acc_sel_shift =
            get_eval(openings, POLY_ACC_SEL, &(zeta * omega)).ok_or("acc sel shift missing")?;
        let q_eval = get_eval(openings, POLY_Q, &zeta).ok_or("q missing")?;

        let n = pub_inputs.n;
        let zh = zeta.pow([n as u64]) - Fr::one();
        let last = omega.pow([(n - 1) as u64]);
        let z1 = zh
            * (zeta - last)
                .inverse()
                .ok_or_else(|| "z1 div by zero".to_string())?;
        let z2 = zeta - last;
        let z3 = zh
            * (zeta - Fr::one())
                .inverse()
                .ok_or_else(|| "z3 div by zero".to_string())?;

        let sel_times_d = sel * d;
        let p1 = (acc_sel - sel_times_d) * z1;
        let p2 = (acc_sel - sel_times_d - acc_sel_shift) * z2;
        let p3 = acc_sel * z3;

        let p4 = d * (d - Fr::one());

        let mut alpha_pow = Fr::one();
        let mut pvanish = Fr::zero();
        for term in [p1, p2, p3, p4] {
            pvanish += term * alpha_pow;
            alpha_pow *= alpha;
        }
        Ok((pvanish, q_eval, zh, confirm, d))
    }

    fn verify_receipt(proof: &Proof, srs: &Srs) -> Result<(), String> {
        if proof.kind != ProofKind::Receipt {
            return Err("wrong kind".into());
        }
        let mut transcript = crate::Transcript::new();
        transcript.append_u64_as_fr(proof.public.n as u64);
        transcript.append_u64_as_fr(proof.public.candidates as u64);
        transcript.append_u64_as_fr(proof.public.disputed_code.ok_or("missing disputed")?);
        transcript
            .append_u64_as_fr(proof.public.ballot_index.ok_or("missing ballot index")? as u64);

        let mut q_cm: Option<G1Affine> = None;
        for c in &proof.commitments {
            let g1: G1Affine = c
                .commitment
                .clone()
                .try_into()
                .map_err(|_| "commitment parse")?;
            if c.label == POLY_Q {
                q_cm = Some(g1);
            } else {
                transcript.append_commitment(&g1);
            }
        }
        let alpha = transcript.challenge_scalar(b"receipt-alpha");
        let q_cm = q_cm.ok_or("missing Q commitment")?;
        transcript.append_commitment(&q_cm);
        let zeta = transcript.challenge_scalar(b"receipt-zeta");
        if proof.alpha.0 != alpha || proof.zeta.0 != zeta {
            return Err("transcript mismatch".into());
        }
        let r = proof.r.as_ref().map(|v| v.0).ok_or("missing r")?;
        let derived_r = derive_batch_challenge(&proof.openings);
        if derived_r != r {
            return Err("r mismatch".into());
        }

        let vk = srs.verifier_key();
        let commitment_map: HashMap<String, Commitment<Bn254>> = proof
            .commitments
            .iter()
            .map(|c| {
                (
                    c.label.clone(),
                    Commitment::<Bn254>(
                        ark_bn254::G1Affine::try_from(c.commitment.clone())
                            .expect("commitment parse"),
                    ),
                )
            })
            .collect();
        batch_check(&vk, &proof.openings, &commitment_map)
            .map_err(|_| "pairing failed".to_string())?;

        let domain = Radix2EvaluationDomain::<Fr>::new(proof.public.n).ok_or("invalid domain")?;
        let omega = domain.element(1);
        let (pvanish, q_eval, zh, confirm_zeta, d_zeta) =
            constraints_at_zeta_receipt(alpha, zeta, omega, &proof.public, &proof.openings)?;
        if pvanish != q_eval * zh {
            return Err(format!(
                "constraint product mismatch lhs={} rhs={}",
                pvanish.into_bigint(),
                (q_eval * zh).into_bigint()
            ));
        }
        let disputed = Fr::from(
            proof
                .public
                .disputed_code
                .ok_or("missing disputed code for eq check")?,
        );
        let delta = confirm_zeta - disputed;
        let fermat = if delta.is_zero() {
            Fr::zero()
        } else {
            Fr::one()
        };
        let expected_d = Fr::one() - fermat;
        if d_zeta != expected_d {
            return Err("receipt fermat relation mismatch".into());
        }
        Ok(())
    }

    #[test]
    fn receipt_proof_roundtrip() {
        let root = workspace_root();
        let election_path = root.join("election.json");
        let srs = Srs::load_from_dir(srs_path()).unwrap();
        let mut public_inputs = load_receipt_inputs(3, &election_path);
        let data = crate::load_election(&election_path, 3).unwrap();
        public_inputs.disputed_code = Some(data.rows.iter().map(|r| r.code).max().unwrap_or(0) + 1);
        public_inputs.ballot_index = Some(0);
        let proof = prove_receipt(&election_path, &public_inputs, &srs).unwrap();
        if let Err(err) = verify_receipt(&proof, &srs) {
            let domain = Radix2EvaluationDomain::<Fr>::new(proof.public.n).unwrap();
            let omega = domain.element(1);
            let (pvanish, q_eval, zh, confirm_zeta, d_zeta) = constraints_at_zeta_receipt(
                proof.alpha.0,
                proof.zeta.0,
                omega,
                &proof.public,
                &proof.openings,
            )
            .unwrap();
            let diff = q_eval * zh - pvanish;
            let zh_inv = zh.inverse().unwrap();
            let disputed = Fr::from(proof.public.disputed_code.unwrap());
            let delta = confirm_zeta - disputed;
            let fermat = if delta.is_zero() {
                Fr::zero()
            } else {
                Fr::one()
            };
            assert_eq!(d_zeta, Fr::one() - fermat, "receipt fermat relation holds");
            panic!(
                "valid proof should verify: {err}; diff={}, diff_scaled={}",
                diff.into_bigint(),
                (diff * zh_inv * zh_inv).into_bigint()
            );
        }
    }
}
