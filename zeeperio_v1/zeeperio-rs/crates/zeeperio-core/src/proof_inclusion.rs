use ark_bn254::Fr;
use ark_ff::{Field, One, Zero};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Evaluations, Polynomial,
    Radix2EvaluationDomain,
};
use ark_serialize::CanonicalSerialize;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::collections::{BTreeMap, HashMap};

use crate::{
    build_polynomials, fr_key, poly_add3_scaled, poly_divide_qr, poly_is_zero, CoreError,
    EvalContext, PolySet, ProofWithState, ProverOpts, PublicInputs, Transcript, POLY_ACC_T1,
    POLY_ACC_T2, POLY_BID, POLY_BID_SHUFFLED, POLY_CONFIRM, POLY_CONFIRM_SHUFFLED, POLY_M,
    POLY_M_SHUFFLED, POLY_Q, POLY_T, POLY_T1, POLY_T2, POLY_T_PRIME,
};
use ark_poly_commit::kzg10::{Commitment, Randomness};
use zeeperio_kzg::{
    batch_open, commit, derive_batch_challenge, wrap_commitment, wrap_witness, Srs,
};
use zeeperio_types::{
    AuditPolyState, AuditState, BatchOpening, NamedCommitment, Proof, ProofKind, SerdeAsBase64,
};

pub fn prove_inclusion(
    election_path: &std::path::Path,
    public_inputs: &PublicInputs,
    srs: &Srs,
    opts: ProverOpts,
) -> Result<ProofWithState, CoreError> {
    let data = crate::load_election(election_path, public_inputs.candidates)?;
    let mut public = public_inputs.clone();
    public.n = data.n;
    public.candidates = data.candidates;
    let (mut polys, ctx) = build_polynomials(&data, &public)?;

    let z_h_dense = DensePolynomial::from(ctx.domain.vanishing_polynomial());

    //transcript 
    let mut transcript = Transcript::new();
    transcript.append_u64_as_fr(public.n as u64);
    transcript.append_u64_as_fr(public.candidates as u64);
    if let Some(shuffle_hash) = &public.shuffle_hash {
        transcript.bytes.extend_from_slice(shuffle_hash.as_bytes());
    }

    //fisher-yates shuffle from fiat–shamir
    let shuffle_seed = transcript.challenge_scalar(b"inclusion-shuffle");
    let mut seed_bytes = [0u8; 32];
    shuffle_seed
        .serialize_compressed(&mut seed_bytes.as_mut_slice())
        .expect("seed serialize");
    let mut shuffle_rng = ChaCha20Rng::from_seed(seed_bytes);
    let mut perm: Vec<usize> = (0..ctx.n).collect();
    for i in (1..ctx.n).rev() {
        let j = (shuffle_rng.next_u64() as usize) % (i + 1);
        perm.swap(i, j);
    }
    let apply_perm = |evals: &[Fr],
                      perm: &[usize],
                      domain: &Radix2EvaluationDomain<Fr>|
     -> DensePolynomial<Fr> {
        let mut out = vec![Fr::zero(); perm.len()];
        for (i, idx) in perm.iter().enumerate() {
            out[i] = evals[*idx];
        }
        Evaluations::from_vec_and_domain(out, *domain).interpolate()
    };

    polys.bid_shuffled = apply_perm(&ctx.bid_evals, &perm, &ctx.domain);
    polys.confirm_shuffled = apply_perm(&ctx.confirm_evals, &perm, &ctx.domain);
    polys.m_shuffled = apply_perm(&ctx.m_evals, &perm, &ctx.domain);

    let mut mask_counter = crate::ChallengeCounter::new("inclusion-mask");
    polys.bid = crate::mask_poly_simple_poly(
        &polys.bid,
        &z_h_dense,
        mask_counter.next(&transcript, "bid"),
    );
    polys.confirm = crate::mask_poly_simple_poly(
        &polys.confirm,
        &z_h_dense,
        mask_counter.next(&transcript, "confirm"),
    );
    polys.m =
        crate::mask_poly_simple_poly(&polys.m, &z_h_dense, mask_counter.next(&transcript, "m"));
    polys.bid_shuffled = crate::mask_poly_simple_poly(
        &polys.bid_shuffled,
        &z_h_dense,
        mask_counter.next(&transcript, "bid_sh"),
    );
    polys.confirm_shuffled = crate::mask_poly_simple_poly(
        &polys.confirm_shuffled,
        &z_h_dense,
        mask_counter.next(&transcript, "confirm_sh"),
    );
    polys.m_shuffled = crate::mask_poly_simple_poly(
        &polys.m_shuffled,
        &z_h_dense,
        mask_counter.next(&transcript, "m_sh"),
    );

    let mut commitment_table: HashMap<
        String,
        (Commitment<ark_bn254::Bn254>, Randomness<Fr, crate::UniPoly>),
    > = HashMap::new();
    let mut named_commitments = Vec::<NamedCommitment>::new();
    let mut commit_counter = crate::ChallengeCounter::new("inclusion-commit");
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

    for (label, poly) in [
        (POLY_BID, &polys.bid),
        (POLY_CONFIRM, &polys.confirm),
        (POLY_M, &polys.m),
        (POLY_BID_SHUFFLED, &polys.bid_shuffled),
        (POLY_CONFIRM_SHUFFLED, &polys.confirm_shuffled),
        (POLY_M_SHUFFLED, &polys.m_shuffled),
    ] {
        let blinding =
            crate::derive_blinding_poly(&transcript, &mut commit_counter, label, poly.degree());
        let (cm, rand) = commit(poly, srs, Some(blinding))?;
        commitment_table.insert(label.to_string(), (cm, rand));
        append_cm(label, &cm, &mut named_commitments, &mut transcript);
    }

    let alpha = transcript.challenge_scalar(b"inclusion-alpha");
    let r = transcript.challenge_scalar(b"inclusion-r");

    //regular and shuffled polynomial
    polys.t = poly_add3_scaled(&polys.bid, &polys.confirm, &polys.m, alpha);
    polys.t_prime = poly_add3_scaled(
        &polys.bid_shuffled,
        &polys.confirm_shuffled,
        &polys.m_shuffled,
        alpha,
    );
    polys.t1 = crate::poly_sub(&crate::poly_const(r), &polys.t);
    polys.t2 = crate::poly_sub(&crate::poly_const(r), &polys.t_prime);

    //accumulators
    polys.acc_t1 = build_backward_product(&polys.t1, &ctx.domain);
    polys.acc_t2 = build_backward_product(&polys.t2, &ctx.domain);

    //mask polynomials
    polys.t =
        crate::mask_poly_simple_poly(&polys.t, &z_h_dense, mask_counter.next(&transcript, "t"));
    polys.t_prime = crate::mask_poly_simple_poly(
        &polys.t_prime,
        &z_h_dense,
        mask_counter.next(&transcript, "t_prime"),
    );
    polys.t1 =
        crate::mask_poly_simple_poly(&polys.t1, &z_h_dense, mask_counter.next(&transcript, "t1"));
    polys.t2 =
        crate::mask_poly_simple_poly(&polys.t2, &z_h_dense, mask_counter.next(&transcript, "t2"));
    polys.acc_t1 = crate::mask_poly_simple_poly(
        &polys.acc_t1,
        &z_h_dense,
        mask_counter.next(&transcript, "acc_t1"),
    );
    polys.acc_t2 = crate::mask_poly_simple_poly(
        &polys.acc_t2,
        &z_h_dense,
        mask_counter.next(&transcript, "acc_t2"),
    );

    for (label, poly) in [
        (POLY_T, &polys.t),
        (POLY_T_PRIME, &polys.t_prime),
        (POLY_T1, &polys.t1),
        (POLY_T2, &polys.t2),
        (POLY_ACC_T1, &polys.acc_t1),
        (POLY_ACC_T2, &polys.acc_t2),
    ] {
        let blinding =
            crate::derive_blinding_poly(&transcript, &mut commit_counter, label, poly.degree());
        let (cm, rand) = commit(poly, srs, Some(blinding))?;
        commitment_table.insert(label.to_string(), (cm, rand));
        append_cm(label, &cm, &mut named_commitments, &mut transcript);
    }

    let beta = transcript.challenge_scalar(b"inclusion-beta");

    let pvanish = build_inclusion_constraints(beta, r, &ctx, &polys);
    let (q_poly, remainder) = poly_divide_qr(&pvanish, &z_h_dense)?;
    if !poly_is_zero(&remainder) {
        return Err(CoreError::ConstraintViolation);
    }
    let blinding_q =
        crate::derive_blinding_poly(&transcript, &mut commit_counter, POLY_Q, q_poly.degree());
    let (cm_q, rand_q) = commit(&q_poly, srs, Some(blinding_q))?;
    append_cm(POLY_Q, &cm_q, &mut named_commitments, &mut transcript);
    commitment_table.insert(POLY_Q.to_string(), (cm_q.clone(), rand_q));
    let zeta = transcript.challenge_scalar(b"inclusion-zeta");

    //openings
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

    let all_at_zeta = vec![
        POLY_BID.to_string(),
        POLY_CONFIRM.to_string(),
        POLY_M.to_string(),
        POLY_BID_SHUFFLED.to_string(),
        POLY_CONFIRM_SHUFFLED.to_string(),
        POLY_M_SHUFFLED.to_string(),
        POLY_T.to_string(),
        POLY_T_PRIME.to_string(),
        POLY_T1.to_string(),
        POLY_T2.to_string(),
        POLY_ACC_T1.to_string(),
        POLY_ACC_T2.to_string(),
        POLY_Q.to_string(),
    ];
    add_point(zeta, all_at_zeta);

    let zeta_omega = zeta * omega;
    add_point(
        zeta_omega,
        vec![POLY_ACC_T1.to_string(), POLY_ACC_T2.to_string()],
    );

    let mut poly_map: HashMap<String, (&crate::UniPoly, &Randomness<Fr, crate::UniPoly>)> =
        HashMap::new();
    for (label, poly) in [
        (POLY_BID.to_string(), &polys.bid),
        (POLY_CONFIRM.to_string(), &polys.confirm),
        (POLY_M.to_string(), &polys.m),
        (POLY_BID_SHUFFLED.to_string(), &polys.bid_shuffled),
        (POLY_CONFIRM_SHUFFLED.to_string(), &polys.confirm_shuffled),
        (POLY_M_SHUFFLED.to_string(), &polys.m_shuffled),
        (POLY_T.to_string(), &polys.t),
        (POLY_T_PRIME.to_string(), &polys.t_prime),
        (POLY_T1.to_string(), &polys.t1),
        (POLY_T2.to_string(), &polys.t2),
        (POLY_ACC_T1.to_string(), &polys.acc_t1),
        (POLY_ACC_T2.to_string(), &polys.acc_t2),
        (POLY_Q.to_string(), &q_poly),
    ] {
        let (_, blind) = commitment_table.get(&label).expect("blind present");
        poly_map.insert(label, (poly, blind));
    }

    let mut opening_counter = crate::ChallengeCounter::new("inclusion-open");
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

    let batch_r = derive_batch_challenge(&openings);

    let private_state = if opts.embed_private_state || opts.return_private_state {
        let mut polys_state = Vec::new();
        for (label, poly) in [
            (POLY_BID_SHUFFLED, &polys.bid_shuffled),
            (POLY_CONFIRM_SHUFFLED, &polys.confirm_shuffled),
            (POLY_M_SHUFFLED, &polys.m_shuffled),
        ] {
            let blind = commitment_table
                .get(label)
                .map(|(_, rand)| rand.blinding_polynomial.coeffs.clone())
                .unwrap_or_default();
            polys_state.push(AuditPolyState {
                label: label.to_string(),
                blinding_coeffs: blind.into_iter().map(SerdeAsBase64).collect(),
                poly_coeffs: poly.coeffs.iter().cloned().map(SerdeAsBase64).collect(),
            });
        }
        Some(AuditState {
            rho_a: SerdeAsBase64(Fr::zero()),
            rho_m: SerdeAsBase64(Fr::zero()),
            polys: polys_state,
        })
    } else {
        None
    };

    let audit_state_for_proof = private_state.clone().filter(|_| opts.embed_private_state);

    Ok(ProofWithState {
        proof: Proof {
            kind: ProofKind::BallotInclusion,
            commitments: named_commitments,
            openings,
            alpha: SerdeAsBase64(alpha),
            zeta: SerdeAsBase64(zeta),
            beta: Some(SerdeAsBase64(beta)),
            public,
            r: Some(SerdeAsBase64(batch_r)),
            audit_state: audit_state_for_proof,
        },
        private_state: private_state
            .filter(|_| opts.return_private_state || opts.embed_private_state),
    })
}

fn build_backward_product(
    poly: &DensePolynomial<Fr>,
    domain: &Radix2EvaluationDomain<Fr>,
) -> DensePolynomial<Fr> {
    let evals = poly.evaluate_over_domain_by_ref(*domain);
    let mut acc = vec![Fr::one(); domain.size()];
    for i in (0..domain.size()).rev() {
        if i == domain.size() - 1 {
            acc[i] = evals.evals[i];
        } else {
            acc[i] = evals.evals[i] * acc[i + 1];
        }
    }
    ark_poly::Evaluations::from_vec_and_domain(acc, *domain).interpolate()
}

fn build_inclusion_constraints(
    beta: Fr,
    r: Fr,
    ctx: &EvalContext,
    polys: &PolySet,
) -> DensePolynomial<Fr> {
    //vanishing polynomails
    let omega = ctx.domain.element(1);
    let last = omega.pow([(ctx.n - 1) as u64]);
    let z_h = DensePolynomial::from(ctx.domain.vanishing_polynomial());
    let lin_last = DensePolynomial::from_coefficients_vec(vec![-last, Fr::one()]);
    let (z1_poly, _) = crate::poly_divide_qr(&z_h, &lin_last).expect("z1 divide");
    let z2_poly = DensePolynomial::from_coefficients_vec(vec![-last, Fr::one()]);
    let lin_one = DensePolynomial::from_coefficients_vec(vec![-Fr::one(), Fr::one()]);
    let (z3_poly, _) = crate::poly_divide_qr(&z_h, &lin_one).expect("z3 divide");

    let mut constraints: Vec<DensePolynomial<Fr>> = Vec::new();

    constraints.push(crate::poly_mul(
        &crate::poly_sub(&polys.acc_t1, &polys.t1),
        &z1_poly,
    ));
    constraints.push(crate::poly_mul(
        &crate::poly_sub(&polys.acc_t2, &polys.t2),
        &z1_poly,
    ));
    let acc_t1_shift = crate::poly_scale_x(&polys.acc_t1, omega);
    let diff_t1 = crate::poly_sub(&polys.acc_t1, &crate::poly_mul(&polys.t1, &acc_t1_shift));
    constraints.push(crate::poly_mul(&diff_t1, &z2_poly));
    let acc_t2_shift = crate::poly_scale_x(&polys.acc_t2, omega);
    let diff_t2 = crate::poly_sub(&polys.acc_t2, &crate::poly_mul(&polys.t2, &acc_t2_shift));
    constraints.push(crate::poly_mul(&diff_t2, &z2_poly));
    constraints.push(crate::poly_mul(
        &crate::poly_sub(&polys.acc_t1, &polys.acc_t2),
        &z3_poly,
    ));
    constraints.push(crate::poly_sub(
        &polys.t1,
        &crate::poly_sub(&crate::poly_const(r), &polys.t),
    ));
    constraints.push(crate::poly_sub(
        &polys.t2,
        &crate::poly_sub(&crate::poly_const(r), &polys.t_prime),
    ));

    //batching
    let mut acc = DensePolynomial::from_coefficients_vec(vec![Fr::zero()]);
    let mut beta_pow = Fr::one();
    for c in constraints {
        acc = &acc + &crate::poly_scale(&c, beta_pow);
        beta_pow *= beta;
    }
    acc
}
