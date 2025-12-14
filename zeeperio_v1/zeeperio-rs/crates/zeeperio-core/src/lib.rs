use std::fs;
use std::path::Path;

use ark_bn254::{Fr, G1Affine};
use ark_ff::{Field, One, PrimeField, Zero};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Evaluations};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_serialize::CanonicalSerialize;
use blake3::hash;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeeperio_kzg::{KzgError, UniPoly};
use zeeperio_types::{AuditState, Proof, PublicInputs};

#[derive(Clone, Debug, Default)]
pub struct ProverOpts {
    pub embed_private_state: bool,
    pub return_private_state: bool,
}

#[derive(Clone, Debug)]
pub struct ProofWithState {
    pub proof: Proof,
    pub private_state: Option<AuditState>,
}

impl From<Proof> for ProofWithState {
    fn from(proof: Proof) -> Self {
        ProofWithState {
            proof,
            private_state: None,
        }
    }
}

mod proof_main;
pub use proof_main::prove_main;
mod proof_inclusion;
pub use proof_inclusion::prove_inclusion;
mod proof_receipt;
pub use proof_receipt::prove_receipt;

const POLY_BID: &str = "BID";
const POLY_CONFIRM: &str = "Cconfirm";
const POLY_CONFIRM_SHUFFLED: &str = "CconfirmSh";
const POLY_BID_SHUFFLED: &str = "BIDSh";
const POLY_M_SHUFFLED: &str = "MSh";
const POLY_T: &str = "T";
const POLY_T_PRIME: &str = "TPrime";
const POLY_T1: &str = "T1";
const POLY_T2: &str = "T2";
const POLY_ACC_T1: &str = "AccT1";
const POLY_ACC_T2: &str = "AccT2";
const POLY_D: &str = "D";
const POLY_SEL: &str = "Sel";
const POLY_ACC_SEL: &str = "AccSel";
const POLY_A: &str = "A";
const POLY_M: &str = "M";
const POLY_SBLK_A: &str = "SblkA";
const POLY_SBLK_M: &str = "SblkM";
const POLY_ACC_A: &str = "AccA";
const POLY_ACC_M: &str = "AccM";
const POLY_TALLY_ACC: &str = "TallyAcc";
const POLY_ZPAD: &str = "ZPad";
const POLY_SEL_BLK_A: &str = "SelBlkA";
const POLY_Z1A: &str = "Z1A";
const POLY_Z2A: &str = "Z2A";
const POLY_Z3A: &str = "Z3A";
const POLY_Z1M: &str = "Z1M";
const POLY_Z2M: &str = "Z2M";
const POLY_Z3M: &str = "Z3M";
const POLY_TAIL_KEEP: &str = "TailKeep";
const POLY_TAIL_SKIP: &str = "TailSkip";
const POLY_Q: &str = "Q";

fn cand_selector_label(idx: usize) -> String {
    format!("CandSel{}", idx)
}

#[derive(Error, Debug)]
pub enum CoreError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("kzg error: {0}")]
    Kzg(#[from] KzgError),
    #[error("constraint system not satisfied")]
    ConstraintViolation,
    #[error("SRS too small: need {needed}, have {available}")]
    SrsTooSmall { needed: usize, available: usize },
    #[error("missing evaluation for {0}")]
    MissingEvaluation(String),
    #[error("public input length mismatch")]
    PublicInputLength,
    #[error("invalid candidates count")]
    InvalidCandidates,
    #[error("missing dispute input: {0}")]
    MissingDisputeInput(&'static str),
}

#[derive(Clone, Debug)]
pub struct ElectionData {
    pub candidates: usize,
    pub rows: Vec<Row>,
    pub n: usize,
    pub bid_evals: Vec<Fr>,
    pub confirm_evals: Vec<Fr>,
    pub audit_evals: Vec<Fr>,
    pub mark_evals: Vec<Fr>,
    pub code_evals: Vec<Fr>,
}

#[derive(Clone, Debug)]
pub struct Row {
    pub ballot_id: String,
    pub audit_bit: u64,
    pub mark_bit: u64,
    pub code: u64,
}

#[derive(Deserialize)]
struct RawRow {
    #[serde(default)]
    ballot_id: serde_json::Value,
    #[serde(default)]
    audit: serde_json::Value,
    #[serde(default)]
    mark: serde_json::Value,
    #[serde(default)]
    code: serde_json::Value,
}

fn poly_is_zero<F: Field>(p: &DensePolynomial<F>) -> bool {
    p.coeffs.iter().all(|c| c.is_zero())
}

fn poly_const(c: Fr) -> UniPoly {
    DensePolynomial::from_coefficients_vec(vec![c])
}

fn poly_sub(a: &UniPoly, b: &UniPoly) -> UniPoly {
    let mut out = a.clone();
    out -= b;
    out
}

fn poly_mul(a: &UniPoly, b: &UniPoly) -> UniPoly {
    a * b 
}

fn poly_add3_scaled(a: &UniPoly, b: &UniPoly, c: &UniPoly, alpha: Fr) -> UniPoly {
    let mut out = poly_scale(a, alpha);
    out += &poly_scale(b, alpha * alpha);
    out += c;
    out
}


fn poly_scale_x(p: &UniPoly, scale: Fr) -> UniPoly {
    let mut coeffs = p.coeffs.clone();
    let mut pow = Fr::one();
    for ci in &mut coeffs {
        *ci *= pow;
        pow *= scale;
    }
    DensePolynomial::from_coefficients_vec(coeffs)
}

//scalar mult
fn poly_scale(p: &UniPoly, s: Fr) -> UniPoly {
    let mut coeffs = p.coeffs.clone();
    for ci in &mut coeffs {
        *ci *= s;
    }
    DensePolynomial::from_coefficients_vec(coeffs)
}

fn aggregate_constraints_poly(alpha: Fr, polys: Vec<UniPoly>) -> UniPoly {
    let mut out = poly_const(Fr::zero());
    let mut alpha_pow = Fr::one();
    for p in polys {
        let term = poly_scale(&p, alpha_pow);
        out += &term;
        alpha_pow *= alpha;
    }
    out
}

fn compute_pvanish_poly(alpha: Fr, ctx: &EvalContext, polys: &PolySet) -> UniPoly {
    let omega = ctx.domain.element(1);
    let c = ctx.candidates;

    //block sums
    let mut block_a_sum = poly_const(Fr::zero());
    let mut block_m_sum = poly_const(Fr::zero());
    for k in 0..c {
        let w = omega.pow([k as u64]);
        block_a_sum = &block_a_sum + &poly_scale_x(&polys.a, w);
        block_m_sum = &block_m_sum + &poly_scale_x(&polys.m, w);
    }

    let acc_a_shift = poly_scale_x(&polys.acc_a, omega);
    let acc_m_shift = poly_scale_x(&polys.acc_m, omega);
    let tally_shift = poly_scale_x(&polys.tally_acc, omega.pow([c as u64]));

    let one = poly_const(Fr::one());
    let c_fr = Fr::from(c as u64);

    let sum_a_total = poly_const(ctx.pub_inputs.sum_a_total);
    let sum_m_total = poly_const(ctx.pub_inputs.sum_m_total);

    let mut constraints = Vec::<UniPoly>::new();


    // constraints
    constraints.push(poly_mul(&polys.a, &polys.z_pad));

    let a_minus_one = poly_sub(&polys.a, &one);
    constraints.push(poly_mul(&polys.a, &a_minus_one));

    let sblk_diff = poly_sub(&polys.sblk_a, &block_a_sum);
    constraints.push(poly_mul(&sblk_diff, &polys.sel_blk_a));

    let sblk_masked = poly_mul(&polys.sblk_a, &polys.sel_blk_a);
    let sblk_masked_minus_c = poly_sub(&sblk_masked, &poly_const(c_fr));
    constraints.push(poly_mul(&sblk_masked, &sblk_masked_minus_c));

    let tmp = poly_sub(&polys.acc_a, &polys.a);
    let tmp = poly_sub(&tmp, &acc_a_shift);
    constraints.push(poly_mul(&tmp, &polys.z1a));

    let tmp = poly_sub(&polys.acc_a, &polys.a);
    constraints.push(poly_mul(&tmp, &polys.z2a));

    let tmp = poly_sub(&polys.acc_a, &sum_a_total);
    constraints.push(poly_mul(&tmp, &polys.z3a));

    constraints.push(poly_mul(&polys.m, &polys.z_pad));

    let m_minus_one = poly_sub(&polys.m, &one);
    constraints.push(poly_mul(&polys.m, &m_minus_one));

    constraints.push(poly_sub(&polys.sblk_m, &block_m_sum));

    let sblk_m_minus_one = poly_sub(&polys.sblk_m, &one);
    constraints.push(poly_mul(&polys.sblk_m, &sblk_m_minus_one));

    let tmp = poly_sub(&polys.acc_m, &polys.m);
    let tmp = poly_sub(&tmp, &acc_m_shift);
    constraints.push(poly_mul(&tmp, &polys.z1m));

    let tmp = poly_sub(&polys.acc_m, &polys.m);
    constraints.push(poly_mul(&tmp, &polys.z2m));

    let tmp = poly_sub(&polys.acc_m, &sum_m_total);
    constraints.push(poly_mul(&tmp, &polys.z3m));

    constraints.push(poly_mul(&polys.a, &polys.m));

    let tmp = poly_sub(&polys.tally_acc, &polys.m);
    constraints.push(poly_mul(&tmp, &polys.tail_keep));

    let tmp = poly_sub(&polys.tally_acc, &polys.m);
    let tmp = poly_sub(&tmp, &tally_shift);
    constraints.push(poly_mul(&tmp, &polys.tail_skip));

    for (cand_idx, sel_poly) in polys.candidate_selectors.iter().enumerate() {
        let target = poly_const(ctx.pub_inputs.candidate_sums[cand_idx]);
        let tmp = poly_sub(&polys.tally_acc, &target);
        constraints.push(poly_mul(&tmp, sel_poly));
    }

    aggregate_constraints_poly(alpha, constraints)
}

fn mask_poly_with(poly: &UniPoly, z_h: &DensePolynomial<Fr>, mask: Fr) -> UniPoly {
    let mut masked = poly.clone();
    masked += &poly_scale(z_h, mask);
    masked
}

fn mask_poly(poly: &UniPoly, z_h: &DensePolynomial<Fr>, mask: Fr) -> UniPoly {
    mask_poly_with(poly, z_h, mask)
}

fn mask_poly_simple_poly(poly: &UniPoly, z_h: &DensePolynomial<Fr>, mask: Fr) -> UniPoly {
    mask_poly(poly, z_h, mask)
}

fn apply_z_masking<F>(polys: &mut PolySet, z_h: &DensePolynomial<Fr>, mut sampler: F) -> (Fr, Fr)
where
    F: FnMut(&str) -> Fr,
{
    let rho_a = sampler("rho_a");
    let rho_m = sampler("rho_m");
    polys.a = mask_poly_with(&polys.a, z_h, rho_a);
    polys.m = mask_poly_with(&polys.m, z_h, rho_m);
    polys.sblk_a = mask_poly(&polys.sblk_a, z_h, sampler("sblk_a"));
    polys.sblk_m = mask_poly(&polys.sblk_m, z_h, sampler("sblk_m"));
    polys.acc_a = mask_poly(&polys.acc_a, z_h, sampler("acc_a"));
    polys.acc_m = mask_poly(&polys.acc_m, z_h, sampler("acc_m"));
    polys.tally_acc = mask_poly(&polys.tally_acc, z_h, sampler("tally_acc"));
    polys.z_pad = mask_poly(&polys.z_pad, z_h, sampler("z_pad"));
    polys.sel_blk_a = mask_poly(&polys.sel_blk_a, z_h, sampler("sel_blk_a"));
    polys.z1a = mask_poly(&polys.z1a, z_h, sampler("z1a"));
    polys.z2a = mask_poly(&polys.z2a, z_h, sampler("z2a"));
    polys.z3a = mask_poly(&polys.z3a, z_h, sampler("z3a"));
    polys.z1m = mask_poly(&polys.z1m, z_h, sampler("z1m"));
    polys.z2m = mask_poly(&polys.z2m, z_h, sampler("z2m"));
    polys.z3m = mask_poly(&polys.z3m, z_h, sampler("z3m"));
    polys.tail_keep = mask_poly(&polys.tail_keep, z_h, sampler("tail_keep"));
    polys.tail_skip = mask_poly(&polys.tail_skip, z_h, sampler("tail_skip"));
    for (idx, poly) in polys.candidate_selectors.iter_mut().enumerate() {
        let label = format!("cand_sel_{idx}");
        *poly = mask_poly(poly, z_h, sampler(&label));
    }
    (rho_a, rho_m)
}

fn derive_blinding_poly(
    transcript: &Transcript,
    counter: &mut ChallengeCounter,
    label: &str,
    hiding_bound: usize,
) -> UniPoly {
    let degree = hiding_bound + 1;
    let mut coeffs = Vec::with_capacity(degree + 1);
    for idx in 0..=degree {
        let tag = format!("{label}-coeff-{idx}");
        coeffs.push(counter.next(transcript, &tag));
    }
    UniPoly::from_coefficients_vec(coeffs)
}

fn poly_divide_qr<F: Field>(
    num: &DensePolynomial<F>,
    den: &DensePolynomial<F>,
) -> Result<(DensePolynomial<F>, DensePolynomial<F>), CoreError> {
    if poly_is_zero(den) {
        return Err(CoreError::ConstraintViolation);
    }

    let mut rem = num.coeffs().to_vec();
    if rem.is_empty() {
        return Ok((
            DensePolynomial::from_coefficients_vec(vec![F::zero()]),
            DensePolynomial::from_coefficients_vec(vec![F::zero()]),
        ));
    }

    let mut rem_deg = rem.len() - 1;
    while rem_deg > 0 && rem[rem_deg].is_zero() {
        rem_deg -= 1;
    }

    let den_coeffs = den.coeffs();
    let den_deg = den.coeffs.iter().rposition(|c| !c.is_zero()).unwrap_or(0);

    if rem_deg < den_deg {
        return Ok((
            DensePolynomial::from_coefficients_vec(vec![F::zero()]),
            DensePolynomial::from_coefficients_vec(rem),
        ));
    }

    let lead = den_coeffs[den_deg];
    let lead_inv = lead.inverse().ok_or(CoreError::ConstraintViolation)?;

    let mut quot = vec![F::zero(); rem_deg - den_deg + 1];

    while rem_deg >= den_deg && !rem[rem_deg].is_zero() {
        let q_coeff = rem[rem_deg] * lead_inv;
        let shift = rem_deg - den_deg;

        quot[shift] += q_coeff;

        for j in 0..=den_deg {
            rem[shift + j] -= q_coeff * den_coeffs[j];
        }

        while rem_deg > 0 && rem[rem_deg].is_zero() {
            rem_deg -= 1;
        }
        if rem_deg < den_deg {
            break;
        }
    }

    Ok((
        DensePolynomial::from_coefficients_vec(quot),
        DensePolynomial::from_coefficients_vec(rem),
    ))
}

pub fn load_election(path: &Path, candidates: usize) -> Result<ElectionData, CoreError> {
    let contents = fs::read_to_string(path)?;
    let json_val: serde_json::Value =
        serde_json::from_str(&contents).unwrap_or_else(|_| serde_json::Value::Array(vec![]));
    let mut rows = Vec::new();
    if let serde_json::Value::Array(items) = json_val {
        for item in items {
            if let Ok(raw) = serde_json::from_value::<RawRow>(item) {
                let ballot_id = stringify_value(&raw.ballot_id);
                let audit_bit = coerce_bit(&raw.audit);
                let mark_bit = coerce_bit(&raw.mark);
                let code = coerce_u64(&raw.code);
                rows.push(Row {
                    ballot_id,
                    audit_bit,
                    mark_bit,
                    code,
                });
            }
        }
    }

    let p = rows.len();
    let n = if p == 0 { 1 } else { p.next_power_of_two() };
    let mut bid_evals = vec![Fr::zero(); n];
    let mut audit_evals = vec![Fr::zero(); n];
    let mut mark_evals = vec![Fr::zero(); n];
    let mut code_evals = vec![Fr::zero(); n];
    let mut confirm_evals = vec![Fr::zero(); n];

    for (i, row) in rows.iter().enumerate() {
        bid_evals[i] = hash_to_field(&row.ballot_id);
        audit_evals[i] = Fr::from(row.audit_bit);
        mark_evals[i] = Fr::from(row.mark_bit);
        code_evals[i] = Fr::from(row.code);
        confirm_evals[i] = Fr::from(row.code);
    }

    Ok(ElectionData {
        candidates,
        rows,
        n,
        bid_evals,
        audit_evals,
        mark_evals,
        code_evals,
        confirm_evals,
    })
}

fn stringify_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        _ => String::new(),
    }
}

fn coerce_bit(value: &serde_json::Value) -> u64 {
    match value {
        serde_json::Value::Bool(b) => {
            if *b {
                1
            } else {
                0
            }
        }
        serde_json::Value::Number(num) => {
            if let Some(u) = num.as_u64() {
                if u == 0 {
                    0
                } else {
                    1
                }
            } else if let Some(f) = num.as_f64() {
                if f == 0f64 {
                    0
                } else {
                    1
                }
            } else {
                0
            }
        }
        serde_json::Value::String(s) => {
            let lower = s.to_ascii_lowercase();
            match lower.as_str() {
                "1" | "true" | "yes" => 1,
                "0" | "false" | "no" => 0,
                _ => {
                    if let Ok(v) = s.parse::<u64>() {
                        if v == 0 {
                            0
                        } else {
                            1
                        }
                    } else {
                        0
                    }
                }
            }
        }
        _ => 0,
    }
}

fn coerce_u64(value: &serde_json::Value) -> u64 {
    match value {
        serde_json::Value::Number(num) => num.as_u64().unwrap_or(0),
        serde_json::Value::Bool(b) => {
            if *b {
                1
            } else {
                0
            }
        }
        serde_json::Value::String(s) => s.parse::<u64>().unwrap_or(0),
        _ => 0,
    }
}

fn hash_to_field(input: &str) -> Fr {
    let digest = hash(input.as_bytes());
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest.as_bytes()[0..8]);
    Fr::from(u64::from_le_bytes(bytes))
}

#[derive(Clone)]
struct PolySet {
    bid: UniPoly,
    confirm: UniPoly,
    a: UniPoly,
    m: UniPoly,
    bid_shuffled: UniPoly,
    confirm_shuffled: UniPoly,
    m_shuffled: UniPoly,
    t: UniPoly,
    t_prime: UniPoly,
    t1: UniPoly,
    t2: UniPoly,
    acc_t1: UniPoly,
    acc_t2: UniPoly,
    sblk_a: UniPoly,
    sblk_m: UniPoly,
    acc_a: UniPoly,
    acc_m: UniPoly,
    tally_acc: UniPoly,
    z_pad: UniPoly,
    sel_blk_a: UniPoly,
    z1a: UniPoly,
    z2a: UniPoly,
    z3a: UniPoly,
    z1m: UniPoly,
    z2m: UniPoly,
    z3m: UniPoly,
    tail_keep: UniPoly,
    tail_skip: UniPoly,
    candidate_selectors: Vec<UniPoly>,
}

struct EvalContext {
    domain: Radix2EvaluationDomain<Fr>,
    n: usize,
    candidates: usize,
    pub_inputs: PublicFields,
    bid_evals: Vec<Fr>,
    confirm_evals: Vec<Fr>,
    m_evals: Vec<Fr>,
}

#[derive(Clone)]
struct PublicFields {
    sum_a_total: Fr,
    sum_m_total: Fr,
    candidate_sums: Vec<Fr>,
}

fn build_polynomials(
    data: &ElectionData,
    provided: &PublicInputs,
) -> Result<(PolySet, EvalContext), CoreError> {
    let domain = Radix2EvaluationDomain::<Fr>::new(data.n).expect("domain supported");
    if provided.tally.len() != data.candidates {
        return Err(CoreError::PublicInputLength);
    }

    let bid = Evaluations::from_vec_and_domain(data.bid_evals.clone(), domain).interpolate();
    let confirm =
        Evaluations::from_vec_and_domain(data.confirm_evals.clone(), domain).interpolate();
    let a = Evaluations::from_vec_and_domain(data.audit_evals.clone(), domain).interpolate();
    let m = Evaluations::from_vec_and_domain(data.mark_evals.clone(), domain).interpolate();
    let sblk_a_evals = build_block_sum(&data.audit_evals, data.candidates);
    let sblk_m_evals = build_block_sum(&data.mark_evals, data.candidates);
    let sblk_a = Evaluations::from_vec_and_domain(sblk_a_evals.clone(), domain).interpolate();
    let sblk_m = Evaluations::from_vec_and_domain(sblk_m_evals.clone(), domain).interpolate();

    let acc_a_evals = build_accumulator(&data.audit_evals);
    let acc_m_evals = build_accumulator(&data.mark_evals);
    let tally_acc_evals = build_strided_accumulator(&data.mark_evals, data.candidates);

    let acc_a = Evaluations::from_vec_and_domain(acc_a_evals.clone(), domain).interpolate();
    let acc_m = Evaluations::from_vec_and_domain(acc_m_evals.clone(), domain).interpolate();
    let tally_acc = Evaluations::from_vec_and_domain(tally_acc_evals.clone(), domain).interpolate();

    let z_pad_vec = build_padding_selector(data.n, data.rows.len());
    let sel_blk_a_vec = build_sel_blk_a(data.n, data.candidates);
    let z1a_vec = selector_skip_index(data.n, data.n - 1);
    let z2a_vec = selector_single(data.n, data.n - 1);
    let z3a_vec = selector_single(data.n, 0);
    let z1m_vec = selector_skip_index(data.n, data.n - 1);
    let z2m_vec = selector_single(data.n, data.n - 1);
    let z3m_vec = selector_single(data.n, 0);
    let tail_keep_vec = selector_tail(data.n, data.candidates, true);
    let tail_skip_vec = selector_tail(data.n, data.candidates, false);
    let candidate_selectors_vec = (0..data.candidates)
        .map(|c| selector_single(data.n, c))
        .collect::<Vec<_>>();

    let z_pad = Evaluations::from_vec_and_domain(z_pad_vec.clone(), domain).interpolate();
    let sel_blk_a = Evaluations::from_vec_and_domain(sel_blk_a_vec.clone(), domain).interpolate();
    let z1a = Evaluations::from_vec_and_domain(z1a_vec.clone(), domain).interpolate();
    let z2a = Evaluations::from_vec_and_domain(z2a_vec.clone(), domain).interpolate();
    let z3a = Evaluations::from_vec_and_domain(z3a_vec.clone(), domain).interpolate();
    let z1m = Evaluations::from_vec_and_domain(z1m_vec.clone(), domain).interpolate();
    let z2m = Evaluations::from_vec_and_domain(z2m_vec.clone(), domain).interpolate();
    let z3m = Evaluations::from_vec_and_domain(z3m_vec.clone(), domain).interpolate();
    let tail_keep = Evaluations::from_vec_and_domain(tail_keep_vec.clone(), domain).interpolate();
    let tail_skip = Evaluations::from_vec_and_domain(tail_skip_vec.clone(), domain).interpolate();
    let candidate_selectors = candidate_selectors_vec
        .iter()
        .map(|v| Evaluations::from_vec_and_domain(v.clone(), domain).interpolate())
        .collect::<Vec<_>>();

    let sum_a_total = Fr::from(provided.sum_a_ballots * data.candidates as u64);
    let sum_m_total = Fr::from(provided.sum_m);
    let candidate_sums = provided
        .tally
        .iter()
        .map(|v| Fr::from(*v))
        .collect::<Vec<_>>();

    Ok((
        PolySet {
            bid,
            confirm,
            a,
            m,
            bid_shuffled: UniPoly::zero(),
            confirm_shuffled: UniPoly::zero(),
            m_shuffled: UniPoly::zero(),
            t: UniPoly::zero(),
            t_prime: UniPoly::zero(),
            t1: UniPoly::zero(),
            t2: UniPoly::zero(),
            acc_t1: UniPoly::zero(),
            acc_t2: UniPoly::zero(),
            sblk_a,
            sblk_m,
            acc_a,
            acc_m,
            tally_acc,
            z_pad,
            sel_blk_a,
            z1a,
            z2a,
            z3a,
            z1m,
            z2m,
            z3m,
            tail_keep,
            tail_skip,
            candidate_selectors: candidate_selectors.clone(),
        },
        EvalContext {
            domain,
            n: data.n,
            candidates: data.candidates,
            pub_inputs: PublicFields {
                sum_a_total,
                sum_m_total,
                candidate_sums,
            },
            bid_evals: data.bid_evals.clone(),
            confirm_evals: data.confirm_evals.clone(),
            m_evals: data.mark_evals.clone(),
        },
    ))
}

fn build_block_sum(evals: &[Fr], candidates: usize) -> Vec<Fr> {
    let n = evals.len();
    (0..n)
        .map(|i| {
            let mut acc = Fr::zero();
            for k in 0..candidates {
                acc += evals[(i + k) % n];
            }
            acc
        })
        .collect()
}

fn build_accumulator(evals: &[Fr]) -> Vec<Fr> {
    let n = evals.len();
    let mut acc = vec![Fr::zero(); n];
    if n == 0 {
        return acc;
    }
    acc[n - 1] = evals[n - 1];
    for i in (0..n - 1).rev() {
        acc[i] = evals[i] + acc[i + 1];
    }
    acc
}

fn build_strided_accumulator(evals: &[Fr], stride: usize) -> Vec<Fr> {
    let n = evals.len();
    let mut acc = vec![Fr::zero(); n];
    for i in (0..n).rev() {
        if i + stride < n {
            acc[i] = evals[i] + acc[i + stride];
        } else {
            acc[i] = evals[i];
        }
    }
    acc
}

fn build_padding_selector(n: usize, p: usize) -> Vec<Fr> {
    (0..n)
        .map(|i| if i < p { Fr::zero() } else { Fr::one() })
        .collect()
}

fn build_sel_blk_a(n: usize, candidates: usize) -> Vec<Fr> {
    let mut v = vec![Fr::zero(); n];
    let mut idx = 0;
    while idx < n {
        v[idx] = Fr::one();
        idx += candidates;
    }
    v
}

fn selector_skip_index(n: usize, skip: usize) -> Vec<Fr> {
    (0..n)
        .map(|i| if i == skip { Fr::zero() } else { Fr::one() })
        .collect()
}

fn selector_single(n: usize, index: usize) -> Vec<Fr> {
    (0..n)
        .map(|i| if i == index { Fr::one() } else { Fr::zero() })
        .collect()
}

fn selector_tail(n: usize, tail: usize, keep_tail: bool) -> Vec<Fr> {
    (0..n)
        .map(|i| {
            let in_tail = i >= n.saturating_sub(tail);
            match (in_tail, keep_tail) {
                (true, true) => Fr::one(),
                (true, false) => Fr::zero(),
                (false, true) => Fr::zero(),
                (false, false) => Fr::one(),
            }
        })
        .collect()
}

pub fn derive_inclusion_permutation(public: &PublicInputs) -> Result<Vec<usize>, CoreError> {
    if public.n == 0 {
        return Err(CoreError::ConstraintViolation);
    }
    let mut transcript = Transcript::new();
    transcript.append_u64_as_fr(public.n as u64);
    transcript.append_u64_as_fr(public.candidates as u64);
    if let Some(shuffle_hash) = &public.shuffle_hash {
        transcript.bytes.extend_from_slice(shuffle_hash.as_bytes());
    }
    let shuffle_seed = transcript.challenge_scalar(b"inclusion-shuffle");
    let mut seed_bytes = [0u8; 32];
    shuffle_seed
        .serialize_compressed(&mut seed_bytes.as_mut_slice())
        .expect("seed serialize");
    let mut shuffle_rng = ChaCha20Rng::from_seed(seed_bytes);
    let mut perm: Vec<usize> = (0..public.n).collect();
    for i in (1..public.n).rev() {
        let j = (shuffle_rng.next_u64() as usize) % (i + 1);
        perm.swap(i, j);
    }
    Ok(perm)
}

struct Transcript {
    bytes: Vec<u8>,
}

impl Transcript {
    fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    fn append_commitment(&mut self, cm: &G1Affine) {
        let mut buf = Vec::new();
        cm.serialize_compressed(&mut buf)
            .expect("serialize commitment");
        self.bytes.extend_from_slice(&buf);
    }

    fn append_fr(&mut self, fr: &Fr) {
        let mut buf = Vec::new();
        fr.serialize_compressed(&mut buf).expect("serialize field");
        self.bytes.extend_from_slice(&buf);
    }

    fn append_u64_as_fr(&mut self, val: u64) {
        self.append_fr(&Fr::from(val));
    }

    fn challenge_scalar(&self, label: &[u8]) -> Fr {
        let mut hasher = Sha256::new();
        hasher.update(&self.bytes);
        hasher.update(label);
        let digest = hasher.finalize();
        Fr::from_le_bytes_mod_order(&digest)
    }
}

fn fr_key(fr: &Fr) -> String {
    fr.into_bigint().to_string()
}

#[derive(Clone, Debug, Default)]
pub(crate) struct ChallengeCounter {
    base: String,
    counter: u64,
}

impl ChallengeCounter {
    pub(crate) fn new(base: impl Into<String>) -> Self {
        Self {
            base: base.into(),
            counter: 0,
        }
    }

    pub(crate) fn next(&mut self, transcript: &Transcript, label: &str) -> Fr {
        let full = format!("{}:{}:{}", self.base, label, self.counter);
        self.counter += 1;
        transcript.challenge_scalar(full.as_bytes())
    }
}
