use std::io::{Read, Seek, SeekFrom};
use std::{borrow::Cow, collections::HashMap, fs, io, path::Path};

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, One, PrimeField, Zero};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use ark_poly_commit::kzg10::{Commitment, Powers, Randomness, KZG10};
use ark_poly_commit::{Error as PolyError, PCRandomness};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use byteorder::{LittleEndian, ReadBytesExt};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeeperio_types::{BatchOpening, CommitmentWrapper, OpenEval, SerdeAsBase64};

pub type UniPoly = DensePolynomial<Fr>;

#[derive(Error, Debug)]
pub enum KzgError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] ark_serialize::SerializationError),
    #[error("poly-commit error: {0}")]
    Poly(#[from] PolyError),
    #[error("ptau parse error: {0}")]
    Ptau(String),
    #[error("ptau path is not utf-8")]
    PtauPath,
    #[error("SRS too short: need {needed}, have {available}")]
    SrsTooShort { needed: usize, available: usize },
    #[error("commitment missing for label {0}")]
    MissingCommitment(String),
    #[error("pairing check failed")]
    PairingCheck,
    #[error("division error")]
    Division,
}

#[derive(Clone)]
pub struct Srs {
    pub powers_of_g: Vec<G1Affine>,
    pub powers_of_gamma_g: Vec<G1Affine>,
    pub h: G2Affine,
    pub beta_h: G2Affine,
}

#[derive(Clone)]
pub struct KzgVerifierKey {
    pub g: G1Affine,
    pub gamma_g: G1Affine,
    pub h: G2Affine,
    pub beta_h: G2Affine,
}

impl Srs {
    pub fn import_from_ptau(ptau_path: &Path, degree: usize) -> Result<Self, KzgError> {
        let (tau_g1, alpha_g1, tau_g2, beta_g2) =
            read_ptau(ptau_path, degree + 1, 1, degree + 1, 1)?;
        if tau_g1.len() <= degree {
            return Err(KzgError::SrsTooShort {
                needed: degree + 1,
                available: tau_g1.len(),
            });
        }
        if tau_g2.is_empty() {
            return Err(KzgError::SrsTooShort {
                needed: 1,
                available: tau_g2.len(),
            });
        }
        if alpha_g1.len() <= degree {
            return Err(KzgError::SrsTooShort {
                needed: degree + 1,
                available: alpha_g1.len(),
            });
        }
        if beta_g2.is_empty() {
            return Err(KzgError::SrsTooShort {
                needed: 1,
                available: beta_g2.len(),
            });
        }

        Ok(Self {
            powers_of_g: tau_g1[..=degree].to_vec(),
            powers_of_gamma_g: alpha_g1[..=degree].to_vec(),
            h: tau_g2[0],
            beta_h: beta_g2[0],
        })
    }

    pub fn max_degree(&self) -> usize {
        self.powers_of_g.len().saturating_sub(1)
    }

    pub fn save_to_dir(&self, dir: impl AsRef<Path>) -> Result<(), KzgError> {
        let path = dir.as_ref();
        fs::create_dir_all(path)?;
        write_bin(path.join("powers_g1.bin"), &self.powers_of_g)?;
        write_bin(path.join("powers_gamma_g1.bin"), &self.powers_of_gamma_g)?;
        write_bin(path.join("h_g2.bin"), &self.h)?;
        write_bin(path.join("beta_h_g2.bin"), &self.beta_h)?;
        Ok(())
    }

    pub fn load_from_dir(dir: impl AsRef<Path>) -> Result<Self, KzgError> {
        let path = dir.as_ref();
        Ok(Self {
            powers_of_g: read_bin(path.join("powers_g1.bin"))?,
            powers_of_gamma_g: read_bin(path.join("powers_gamma_g1.bin"))?,
            h: read_bin(path.join("h_g2.bin"))?,
            beta_h: read_bin(path.join("beta_h_g2.bin"))?,
        })
    }

    pub fn verifier_key(&self) -> KzgVerifierKey {
        KzgVerifierKey {
            g: self.powers_of_g[0],
            gamma_g: self.powers_of_gamma_g[0],
            h: self.h,
            beta_h: self.beta_h,
        }
    }

    pub fn to_powers(&self) -> Powers<'_, Bn254> {
        Powers {
            powers_of_g: Cow::Owned(self.powers_of_g.clone()),
            powers_of_gamma_g: Cow::Owned(self.powers_of_gamma_g.clone()),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum FqDecoding {
    Le,
    Be,
    LeMont,
    BeMont,
}

fn fq_r_inv() -> Fq {
    // R = 2^256 mod p (BN254 base field is 256-bit)
    // r_inv = R^{-1} mod p
    let mut r = Fq::from(1u64);
    for _ in 0..256 {
        r.double_in_place();
    }
    r.inverse().expect("2^256 mod p must be invertible")
}

fn decode_fq(buf: &[u8; 32], mode: FqDecoding, r_inv: &Fq) -> Fq {
    let x = match mode {
        FqDecoding::Le | FqDecoding::LeMont => Fq::from_le_bytes_mod_order(buf),
        FqDecoding::Be | FqDecoding::BeMont => Fq::from_be_bytes_mod_order(buf),
    };
    match mode {
        FqDecoding::LeMont | FqDecoding::BeMont => x * (*r_inv),
        _ => x,
    }
}

fn detect_g1_mode(xb: [u8; 32], yb: [u8; 32]) -> Option<FqDecoding> {
    let r_inv = fq_r_inv();
    let modes = [
        FqDecoding::Le,
        FqDecoding::Be,
        FqDecoding::LeMont,
        FqDecoding::BeMont,
    ];

    for mode in modes {
        let x = decode_fq(&xb, mode, &r_inv);
        let y = decode_fq(&yb, mode, &r_inv);
        let p = G1Affine::new_unchecked(x, y);
        if p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve() {
            return Some(mode);
        }
    }
    None
}

fn read_ptau(
    ptau_file: &Path,
    num_g1_points: usize,
    num_g2_points: usize,
    num_alpha_points: usize,
    num_beta_g2_points: usize,
) -> Result<(Vec<G1Affine>, Vec<G1Affine>, Vec<G2Affine>, Vec<G2Affine>), KzgError> {
    use std::collections::BTreeMap;

    let mut f = fs::File::open(ptau_file)?;

    let mut magic = [0u8; 4];
    f.read_exact(&mut magic)?;
    if std::str::from_utf8(&magic).unwrap_or("") != "ptau" {
        return Err(KzgError::Ptau("invalid magic string".into()));
    }

    let version = f.read_u32::<LittleEndian>()?;
    if version != 1 {
        return Err(KzgError::Ptau(format!("unsupported version {version}")));
    }

    let num_sections = f.read_u32::<LittleEndian>()?;
    if num_sections < 3 {
        return Err(KzgError::Ptau(format!("too few sections: {num_sections}")));
    }

    let mut sections: BTreeMap<usize, Vec<(u64, u64)>> = BTreeMap::new();

    for _ in 0..num_sections {
        let id = f.read_u32::<LittleEndian>()? as usize;
        let size = f.read_u64::<LittleEndian>()?;
        let payload_off = f.stream_position()?;

        sections.entry(id).or_default().push((payload_off, size));

        let size_i64: i64 = size
            .try_into()
            .map_err(|_| KzgError::Ptau(format!("section {id} too large")))?;
        f.seek(SeekFrom::Current(size_i64))?;
    }

    for needed in [1usize, 2usize, 3usize, 4usize, 6usize] {
        if !sections.contains_key(&needed) {
            return Err(KzgError::Ptau(format!("missing section {needed}")));
        }
    }

    let (hdr_off, _) = *sections
        .get(&1)
        .and_then(|v| v.first())
        .ok_or_else(|| KzgError::Ptau("missing header".into()))?;
    f.seek(SeekFrom::Start(hdr_off))?;

    let n8 = f.read_u32::<LittleEndian>()?;
    let mut _q_buf = vec![0u8; n8 as usize];
    f.read_exact(&mut _q_buf)?;

    let power = f.read_u32::<LittleEndian>()?;
    let _ceremony_power = f.read_u32::<LittleEndian>()?;

    let max_g2_points = 1usize << power;
    let max_g1_points = max_g2_points * 2 - 1;

    if num_g1_points > max_g1_points {
        return Err(KzgError::Ptau("insufficient G1 powers in ptau".into()));
    }
    if num_g2_points > max_g2_points {
        return Err(KzgError::Ptau("insufficient G2 powers in ptau".into()));
    }

    let g1_segs = sections
        .get(&2)
        .ok_or_else(|| KzgError::Ptau("missing g1".into()))?;
    let (g1_first_off, _) = *g1_segs
        .first()
        .ok_or_else(|| KzgError::Ptau("missing g1".into()))?;

    f.seek(SeekFrom::Start(g1_first_off))?;
    let mut xb = [0u8; 32];
    let mut yb = [0u8; 32];
    f.read_exact(&mut xb)?;
    f.read_exact(&mut yb)?;

    let mode = detect_g1_mode(xb, yb)
        .ok_or_else(|| KzgError::Ptau("invalid g1 point (unknown encoding)".into()))?;
    let r_inv = fq_r_inv();

    let tau_g1 = read_g1_section(&mut f, g1_segs, num_g1_points, mode, &r_inv)?;

    let g2_segs = sections
        .get(&3)
        .ok_or_else(|| KzgError::Ptau("missing g2".into()))?;
    let tau_g2 = read_g2_section(&mut f, g2_segs, num_g2_points, mode, &r_inv)?;

    let alpha_segs = sections
        .get(&4)
        .ok_or_else(|| KzgError::Ptau("missing alpha tau g1 section".into()))?;
    let alpha_g1 = read_g1_section(&mut f, alpha_segs, num_alpha_points, mode, &r_inv)?;

    let beta_g2_segs = sections
        .get(&6)
        .ok_or_else(|| KzgError::Ptau("missing beta g2 section".into()))?;
    let beta_g2 = read_g2_section(&mut f, beta_g2_segs, num_beta_g2_points, mode, &r_inv)?;

    Ok((tau_g1, alpha_g1, tau_g2, beta_g2))
}

fn read_g1_section(
    f: &mut fs::File,
    segments: &[(u64, u64)],
    count: usize,
    mode: FqDecoding,
    r_inv: &Fq,
) -> Result<Vec<G1Affine>, KzgError> {
    let mut points = Vec::<G1Affine>::with_capacity(count);
    let mut remaining = count;

    for &(off, sz) in segments {
        if remaining == 0 {
            break;
        }
        if sz % 64 != 0 {
            return Err(KzgError::Ptau("g1 segment size not multiple of 64".into()));
        }

        let points_in_seg = (sz / 64) as usize;
        let to_read = remaining.min(points_in_seg);

        f.seek(SeekFrom::Start(off))?;
        for _ in 0..to_read {
            let mut x_buf = [0u8; 32];
            let mut y_buf = [0u8; 32];
            f.read_exact(&mut x_buf)?;
            f.read_exact(&mut y_buf)?;

            let x = decode_fq(&x_buf, mode, r_inv);
            let y = decode_fq(&y_buf, mode, r_inv);

            let p = G1Affine::new_unchecked(x, y);
            if !p.is_on_curve() {
                return Err(KzgError::Ptau("invalid g1 point".into()));
            }
            if !p.is_in_correct_subgroup_assuming_on_curve() {
                return Err(KzgError::Ptau("g1 not in correct subgroup".into()));
            }
            points.push(p);
        }

        remaining -= to_read;
    }

    if remaining != 0 {
        return Err(KzgError::Ptau("insufficient G1 powers in ptau".into()));
    }

    Ok(points)
}

fn read_g2_section(
    f: &mut fs::File,
    segments: &[(u64, u64)],
    count: usize,
    mode: FqDecoding,
    r_inv: &Fq,
) -> Result<Vec<G2Affine>, KzgError> {
    let mut points = Vec::<G2Affine>::with_capacity(count);
    let mut remaining = count;

    for &(off, sz) in segments {
        if remaining == 0 {
            break;
        }
        if sz % 128 != 0 {
            return Err(KzgError::Ptau("g2 segment size not multiple of 128".into()));
        }

        let points_in_seg = (sz / 128) as usize;
        let to_read = remaining.min(points_in_seg);

        f.seek(SeekFrom::Start(off))?;
        for _ in 0..to_read {
            let mut x0_buf = [0u8; 32];
            let mut x1_buf = [0u8; 32];
            let mut y0_buf = [0u8; 32];
            let mut y1_buf = [0u8; 32];
            f.read_exact(&mut x0_buf)?;
            f.read_exact(&mut x1_buf)?;
            f.read_exact(&mut y0_buf)?;
            f.read_exact(&mut y1_buf)?;

            let x0 = decode_fq(&x0_buf, mode, r_inv);
            let x1 = decode_fq(&x1_buf, mode, r_inv);
            let y0 = decode_fq(&y0_buf, mode, r_inv);
            let y1 = decode_fq(&y1_buf, mode, r_inv);

            let p = G2Affine::new_unchecked(Fq2::new(x0, x1), Fq2::new(y0, y1));
            if !p.is_on_curve() {
                return Err(KzgError::Ptau("invalid g2 point".into()));
            }
            if !p.is_in_correct_subgroup_assuming_on_curve() {
                return Err(KzgError::Ptau("g2 not in correct subgroup".into()));
            }
            points.push(p);
        }

        remaining -= to_read;
    }

    if remaining != 0 {
        return Err(KzgError::Ptau("insufficient G2 powers in ptau".into()));
    }

    Ok(points)
}

fn write_bin<T: CanonicalSerialize>(path: impl AsRef<Path>, value: &T) -> Result<(), io::Error> {
    let mut file = fs::File::create(path)?;
    value
        .serialize_uncompressed(&mut file)
        .map_err(io::Error::other)?;
    Ok(())
}

fn read_bin<T: CanonicalDeserialize>(path: impl AsRef<Path>) -> Result<T, KzgError> {
    let bytes = fs::read(path)?;
    let mut slice = bytes.as_slice();
    Ok(T::deserialize_uncompressed(&mut slice)?)
}

pub fn commit(
    poly: &UniPoly,
    srs: &Srs,
    blinding: Option<UniPoly>,
) -> Result<(Commitment<Bn254>, Randomness<Fr, UniPoly>), KzgError> {
    if poly.degree() > srs.max_degree() {
        return Err(KzgError::SrsTooShort {
            needed: poly.degree(),
            available: srs.max_degree(),
        });
    }

    let (num_leading_zeros, plain_coeffs) = skip_leading_zeros_and_convert_to_bigints(poly);
    let mut commitment = <G1Projective as VariableBaseMSM>::msm_bigint(
        &srs.powers_of_g[num_leading_zeros..],
        &plain_coeffs,
    );

    let mut randomness = Randomness::<Fr, UniPoly>::empty();
    if let Some(poly_blinding) = blinding {
        if poly_blinding.degree() >= srs.powers_of_gamma_g.len() {
            return Err(KzgError::SrsTooShort {
                needed: poly_blinding.degree(),
                available: srs.powers_of_gamma_g.len().saturating_sub(1),
            });
        }
        let coeffs = convert_to_bigints(poly_blinding.coeffs());
        let random_commitment = <G1Projective as VariableBaseMSM>::msm_bigint(
            srs.powers_of_gamma_g.as_ref(),
            coeffs.as_slice(),
        );
        commitment += &random_commitment;
        randomness.blinding_polynomial = poly_blinding;
    }

    Ok((Commitment(commitment.into()), randomness))
}

pub fn batch_open(
    srs: &Srs,
    polys: &[&UniPoly],
    randoms: &[&Randomness<Fr, UniPoly>],
    point: Fr,
    gamma: Fr,
) -> Result<(G1Projective, Vec<OpenEval>, Fr), KzgError> {
    assert_eq!(polys.len(), randoms.len());

    let mut w = UniPoly::zero();
    let mut rand_h = UniPoly::zero();
    let mut evals_out = Vec::<OpenEval>::with_capacity(polys.len());
    let mut gamma_pow = Fr::one();

    for (p, rand) in polys.iter().zip(randoms) {
        let eval = (*p).evaluate(&point);
        let blinding_eval = rand.blinding_polynomial.evaluate(&point);

        let (witness, random_witness) =
            KZG10::<Bn254, UniPoly>::compute_witness_polynomial(p, point, rand)?;

        let factor = gamma_pow;
        gamma_pow *= gamma;

        w = &w + &scale_poly(&witness, factor);
        if let Some(rw) = random_witness {
            rand_h = &rand_h + &scale_poly(&rw, factor);
        }

        evals_out.push(OpenEval {
            value: SerdeAsBase64(eval),
            blinding: SerdeAsBase64(blinding_eval),
        });
    }

    let (num_leading_zeros, witness_coeffs) = skip_leading_zeros_and_convert_to_bigints(&w);

    let mut proof = G1Projective::msm_bigint(
        &srs.powers_of_g[num_leading_zeros..],
        witness_coeffs.as_slice(),
    );

    let random_witness_coeffs = convert_to_bigints(rand_h.coeffs());
    proof += &<G1Projective as VariableBaseMSM>::msm_bigint(
        srs.powers_of_gamma_g.as_ref(),
        random_witness_coeffs.as_slice(),
    );

    Ok((proof, evals_out, gamma))
}

pub fn batch_check(
    vk: &KzgVerifierKey,
    openings: &[BatchOpening],
    commitments: &HashMap<String, Commitment<Bn254>>,
) -> Result<(), KzgError> {
    let mut left = G1Projective::zero();
    let mut right = G1Projective::zero();

    let r = derive_batch_challenge(openings);

    for (i, opening) in openings.iter().enumerate() {
        let gamma = opening.gamma.0;
        let point = opening.point.0;
        let witness = opening.witness.0.into_group();

        let mut sum_cm = G1Projective::zero();
        let mut sum_value = Fr::zero();
        let mut sum_blinding = Fr::zero();

        for (idx, label) in opening.polys.iter().enumerate() {
            let cm = commitments
                .get(label)
                .ok_or_else(|| KzgError::MissingCommitment(label.clone()))?;

            let eval = opening
                .evaluations
                .get(idx)
                .expect("proof must include all evaluations");

            let factor = gamma.pow([idx as u64]);

            sum_cm += cm.0 * factor;
            sum_value += eval.value.0 * factor;
            sum_blinding += eval.blinding.0 * factor;
        }

        let sum_committed_eval = (vk.g * sum_value) + (vk.gamma_g * sum_blinding);

        let factor = r.pow([i as u64]);
        let witness_factor = witness * factor;

        left += (sum_cm - sum_committed_eval) * factor;
        left += witness_factor * point;
        right += witness_factor;
    }

    let lhs = Bn254::pairing(left, vk.h);
    let rhs = Bn254::pairing(right, vk.beta_h);

    if lhs == rhs {
        Ok(())
    } else {
        Err(KzgError::PairingCheck)
    }
}

pub fn derive_batch_challenge(openings: &[BatchOpening]) -> Fr {
    let mut hasher = Sha256::new();
    for opening in openings {
        hash_fr(&opening.point.0, &mut hasher);
        hash_fr(&opening.gamma.0, &mut hasher);
        hash_g1(&opening.witness.0, &mut hasher);
        for eval in &opening.evaluations {
            hash_fr(&eval.value.0, &mut hasher);
            hash_fr(&eval.blinding.0, &mut hasher);
        }
    }
    let digest = hasher.finalize();
    Fr::from_le_bytes_mod_order(&digest)
}

fn hash_fr(fr: &Fr, hasher: &mut Sha256) {
    let mut buf = Vec::new();
    fr.serialize_compressed(&mut buf)
        .expect("serialize field element");
    hasher.update(&buf);
}

fn hash_g1(p: &G1Affine, hasher: &mut Sha256) {
    let mut buf = Vec::new();
    p.serialize_compressed(&mut buf)
        .expect("serialize g1 element");
    hasher.update(&buf);
}

fn skip_leading_zeros_and_convert_to_bigints<F: PrimeField, P: DenseUVPolynomial<F>>(
    p: &P,
) -> (usize, Vec<F::BigInt>) {
    let mut num_leading_zeros = 0;
    while num_leading_zeros < p.coeffs().len() && p.coeffs()[num_leading_zeros].is_zero() {
        num_leading_zeros += 1;
    }
    let coeffs = convert_to_bigints(&p.coeffs()[num_leading_zeros..]);
    (num_leading_zeros, coeffs)
}

fn scale_poly(poly: &UniPoly, factor: Fr) -> UniPoly {
    if factor.is_zero() {
        return UniPoly::zero();
    }
    let mut out = poly.clone();
    for c in out.coeffs.iter_mut() {
        *c *= factor;
    }
    out
}

fn convert_to_bigints<F: PrimeField>(p: &[F]) -> Vec<F::BigInt> {
    p.iter().map(|s| s.into_bigint()).collect()
}

pub fn wrap_commitment(cm: &Commitment<Bn254>) -> CommitmentWrapper {
    CommitmentWrapper::from(cm.0)
}

pub fn wrap_witness(w: &G1Projective) -> SerdeAsBase64<G1Affine> {
    SerdeAsBase64(w.into_affine())
}
