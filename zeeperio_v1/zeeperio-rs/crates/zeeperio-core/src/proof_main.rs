use ark_bn254::Fr;
use ark_ff::Field;
use ark_poly::{univariate::DensePolynomial, EvaluationDomain, Polynomial};

use crate::{
    apply_z_masking, build_polynomials, cand_selector_label, compute_pvanish_poly, fr_key,
    load_election, poly_divide_qr, poly_is_zero, CoreError, ProofWithState, ProverOpts,
    PublicInputs, Transcript, POLY_A, POLY_ACC_A, POLY_ACC_M, POLY_M, POLY_Q, POLY_SBLK_A,
    POLY_SBLK_M, POLY_SEL_BLK_A, POLY_TAIL_KEEP, POLY_TAIL_SKIP, POLY_TALLY_ACC, POLY_Z1A,
    POLY_Z1M, POLY_Z2A, POLY_Z2M, POLY_Z3A, POLY_Z3M, POLY_ZPAD,
};
use ark_poly_commit::kzg10::{Commitment, Randomness};
use std::collections::{BTreeMap, HashMap};
use zeeperio_kzg::{
    batch_open, commit, derive_batch_challenge, wrap_commitment, wrap_witness, Srs,
};
use zeeperio_types::{BatchOpening, NamedCommitment, Proof, ProofKind, SerdeAsBase64};

pub fn prove_main(
    election_path: &std::path::Path,
    public_inputs: &PublicInputs,
    srs: &Srs,
    opts: ProverOpts,
) -> Result<ProofWithState, CoreError> {
    if public_inputs.candidates == 0 {
        return Err(CoreError::InvalidCandidates);
    }
    let data = load_election(election_path, public_inputs.candidates)?;
    let mut public = public_inputs.clone();
    public.n = data.n;
    public.candidates = data.candidates;
    let (mut polys, ctx) = build_polynomials(&data, &public)?;

    let max_degree_needed = ctx.n * 2;
    if srs.max_degree() < max_degree_needed {
        return Err(CoreError::SrsTooSmall {
            needed: max_degree_needed,
            available: srs.max_degree(),
        });
    }

    let mut transcript = Transcript::new();
    transcript.append_u64_as_fr(public.n as u64);
    transcript.append_u64_as_fr(public.candidates as u64);
    transcript.append_u64_as_fr(public.sum_a_ballots);
    transcript.append_u64_as_fr(public.sum_m);
    for tally in &public.tally {
        transcript.append_u64_as_fr(*tally);
    }

    let z_h_dense = DensePolynomial::from(ctx.domain.vanishing_polynomial());
    let mut mask_counter = crate::ChallengeCounter::new("main-zmask");
    let (rho_a, rho_m) = apply_z_masking(&mut polys, &z_h_dense, |label| {
        mask_counter.next(&transcript, label)
    });

    let mut commitment_table: HashMap<
        String,
        (Commitment<ark_bn254::Bn254>, Randomness<Fr, crate::UniPoly>),
    > = HashMap::new();
    let mut commit_counter = crate::ChallengeCounter::new("main-commit");
    for (label, poly) in [
        (POLY_A, &polys.a),
        (POLY_M, &polys.m),
        (POLY_SBLK_A, &polys.sblk_a),
        (POLY_SBLK_M, &polys.sblk_m),
        (POLY_ACC_A, &polys.acc_a),
        (POLY_ACC_M, &polys.acc_m),
        (POLY_TALLY_ACC, &polys.tally_acc),
        (POLY_ZPAD, &polys.z_pad),
        (POLY_SEL_BLK_A, &polys.sel_blk_a),
        (POLY_Z1A, &polys.z1a),
        (POLY_Z2A, &polys.z2a),
        (POLY_Z3A, &polys.z3a),
        (POLY_Z1M, &polys.z1m),
        (POLY_Z2M, &polys.z2m),
        (POLY_Z3M, &polys.z3m),
        (POLY_TAIL_KEEP, &polys.tail_keep),
        (POLY_TAIL_SKIP, &polys.tail_skip),
    ] {
        let blinding =
            crate::derive_blinding_poly(&transcript, &mut commit_counter, label, poly.degree());
        let (cm, rand) = commit(poly, srs, Some(blinding))?;
        commitment_table.insert(label.to_string(), (cm, rand));
    }
    for (idx, poly) in polys.candidate_selectors.iter().enumerate() {
        let label = cand_selector_label(idx);
        let blinding =
            crate::derive_blinding_poly(&transcript, &mut commit_counter, &label, poly.degree());
        let (cm, rand) = commit(poly, srs, Some(blinding))?;
        commitment_table.insert(label, (cm, rand));
    }

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

    for label in [
        POLY_A,
        POLY_M,
        POLY_SBLK_A,
        POLY_SBLK_M,
        POLY_ACC_A,
        POLY_ACC_M,
        POLY_TALLY_ACC,
        POLY_ZPAD,
        POLY_SEL_BLK_A,
        POLY_Z1A,
        POLY_Z2A,
        POLY_Z3A,
        POLY_Z1M,
        POLY_Z2M,
        POLY_Z3M,
        POLY_TAIL_KEEP,
        POLY_TAIL_SKIP,
    ] {
        let (cm, _) = commitment_table.get(label).expect("commitments present");
        append_cm(label, cm, &mut named_commitments, &mut transcript);
    }

    for idx in 0..public.candidates {
        let label = cand_selector_label(idx);
        let (cm, _) = commitment_table.get(&label).expect("candidate commitment");
        append_cm(&label, cm, &mut named_commitments, &mut transcript);
    }

    let alpha = transcript.challenge_scalar(b"alpha");
    let pvanish_poly = compute_pvanish_poly(alpha, &ctx, &polys);

    let (q_poly, remainder) = poly_divide_qr(&pvanish_poly, &z_h_dense)?;
    if !poly_is_zero(&remainder) {
        return Err(CoreError::ConstraintViolation);
    }
    let blinding_q =
        crate::derive_blinding_poly(&transcript, &mut commit_counter, POLY_Q, q_poly.degree());
    let (cm_q, rand_q) = commit(&q_poly, srs, Some(blinding_q))?;
    append_cm(POLY_Q, &cm_q, &mut named_commitments, &mut transcript);
    commitment_table.insert(POLY_Q.to_string(), (cm_q.clone(), rand_q));
    let zeta = transcript.challenge_scalar(b"zeta");

    let omega = ctx.domain.element(1);
    let mut openings = Vec::new();
    let mut point_map: BTreeMap<String, (Fr, Vec<String>)> = BTreeMap::new();
    let mut add_point = |pt: Fr, labels: Vec<String>| {
        let key = fr_key(&pt);
        point_map
            .entry(key)
            .and_modify(|(_, existing)| existing.extend(labels.iter().cloned()))
            .or_insert((pt, labels));
    };

    let mut all_at_zeta = vec![
        POLY_A.to_string(),
        POLY_M.to_string(),
        POLY_SBLK_A.to_string(),
        POLY_SBLK_M.to_string(),
        POLY_ACC_A.to_string(),
        POLY_ACC_M.to_string(),
        POLY_TALLY_ACC.to_string(),
        POLY_Q.to_string(),
        POLY_ZPAD.to_string(),
        POLY_SEL_BLK_A.to_string(),
        POLY_Z1A.to_string(),
        POLY_Z2A.to_string(),
        POLY_Z3A.to_string(),
        POLY_Z1M.to_string(),
        POLY_Z2M.to_string(),
        POLY_Z3M.to_string(),
        POLY_TAIL_KEEP.to_string(),
        POLY_TAIL_SKIP.to_string(),
    ];
    for idx in 0..public.candidates {
        all_at_zeta.push(cand_selector_label(idx));
    }
    add_point(zeta, all_at_zeta);

    let zeta_omega = zeta * omega;
    add_point(
        zeta_omega,
        vec![
            POLY_A.to_string(),
            POLY_M.to_string(),
            POLY_ACC_A.to_string(),
            POLY_ACC_M.to_string(),
        ],
    );

    for k in 1..public.candidates {
        let point = zeta * omega.pow([k as u64]);
        add_point(point, vec![POLY_A.to_string(), POLY_M.to_string()]);
    }

    let zeta_omega_c = zeta * omega.pow([public.candidates as u64]);
    add_point(zeta_omega_c, vec![POLY_TALLY_ACC.to_string()]);

    let mut poly_map: HashMap<String, (&crate::UniPoly, &Randomness<Fr, crate::UniPoly>)> =
        HashMap::new();
    for (label, poly) in [
        (POLY_A.to_string(), &polys.a),
        (POLY_M.to_string(), &polys.m),
        (POLY_SBLK_A.to_string(), &polys.sblk_a),
        (POLY_SBLK_M.to_string(), &polys.sblk_m),
        (POLY_ACC_A.to_string(), &polys.acc_a),
        (POLY_ACC_M.to_string(), &polys.acc_m),
        (POLY_TALLY_ACC.to_string(), &polys.tally_acc),
        (POLY_ZPAD.to_string(), &polys.z_pad),
        (POLY_SEL_BLK_A.to_string(), &polys.sel_blk_a),
        (POLY_Z1A.to_string(), &polys.z1a),
        (POLY_Z2A.to_string(), &polys.z2a),
        (POLY_Z3A.to_string(), &polys.z3a),
        (POLY_Z1M.to_string(), &polys.z1m),
        (POLY_Z2M.to_string(), &polys.z2m),
        (POLY_Z3M.to_string(), &polys.z3m),
        (POLY_TAIL_KEEP.to_string(), &polys.tail_keep),
        (POLY_TAIL_SKIP.to_string(), &polys.tail_skip),
        (POLY_Q.to_string(), &q_poly),
    ] {
        let (_, blind) = commitment_table.get(&label).expect("blind present");
        poly_map.insert(label, (poly, blind));
    }
    for (idx, poly) in polys.candidate_selectors.iter().enumerate() {
        let label = cand_selector_label(idx);
        let (_, blind) = commitment_table.get(&label).expect("candidate blind");
        poly_map.insert(label, (poly, blind));
    }

    let mut opening_counter = crate::ChallengeCounter::new("main-open");
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
        let opening = BatchOpening {
            point: SerdeAsBase64(point),
            gamma: SerdeAsBase64(gamma),
            witness: wrap_witness(&witness),
            polys: labels,
            evaluations: evals,
        };
        openings.push(opening);
    }

    let r = derive_batch_challenge(&openings);

    let private_state = if opts.embed_private_state || opts.return_private_state {
        let blind_a = commitment_table
            .get(POLY_A)
            .map(|(_, rand)| {
                rand.blinding_polynomial
                    .coeffs
                    .clone()
                    .into_iter()
                    .map(SerdeAsBase64)
                    .collect()
            })
            .unwrap_or_default();
        let poly_a = polys
            .a
            .coeffs
            .iter()
            .cloned()
            .map(SerdeAsBase64)
            .collect::<Vec<_>>();
        let blind_m = commitment_table
            .get(POLY_M)
            .map(|(_, rand)| {
                rand.blinding_polynomial
                    .coeffs
                    .clone()
                    .into_iter()
                    .map(SerdeAsBase64)
                    .collect()
            })
            .unwrap_or_default();
        let poly_m = polys
            .m
            .coeffs
            .iter()
            .cloned()
            .map(SerdeAsBase64)
            .collect::<Vec<_>>();
        Some(zeeperio_types::AuditState {
            rho_a: SerdeAsBase64(rho_a),
            rho_m: SerdeAsBase64(rho_m),
            polys: vec![
                zeeperio_types::AuditPolyState {
                    label: POLY_A.to_string(),
                    blinding_coeffs: blind_a,
                    poly_coeffs: poly_a,
                },
                zeeperio_types::AuditPolyState {
                    label: POLY_M.to_string(),
                    blinding_coeffs: blind_m,
                    poly_coeffs: poly_m,
                },
            ],
        })
    } else {
        None
    };

    let audit_state_for_proof = private_state.clone().filter(|_| opts.embed_private_state);

    Ok(ProofWithState {
        proof: Proof {
            kind: ProofKind::Main,
            commitments: named_commitments,
            openings,
            alpha: SerdeAsBase64(alpha),
            zeta: SerdeAsBase64(zeta),
            beta: None,
            public,
            r: Some(SerdeAsBase64(r)),
            audit_state: audit_state_for_proof,
        },
        private_state: private_state
            .filter(|_| opts.return_private_state || opts.embed_private_state),
    })
}
