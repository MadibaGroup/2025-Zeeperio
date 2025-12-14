use std::path::PathBuf;

use ark_ff::One;
use zeeperio_cli::audit::{generate_audit_openings, verify_audit_openings};
use zeeperio_core::{load_election, prove_main, ProverOpts};
use zeeperio_kzg::Srs;
use zeeperio_types::PublicInputs;

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

fn small_public_inputs(candidates: usize, election_path: &PathBuf) -> PublicInputs {
    let data = load_election(election_path, candidates).unwrap();
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
        candidates,
        sum_a_ballots: sum_a,
        sum_m,
        tally,
        shuffle_hash: None,
        receipt_root: None,
        disputed_code: None,
        ballot_index: None,
    }
}

#[test]
fn test_print_audit_open_verify() {
    let root = workspace_root();
    let election_path = root.join("election.json");
    let srs = Srs::load_from_dir(srs_path()).unwrap();
    let pub_inputs = small_public_inputs(3, &election_path);
    let bundle_with_state = prove_main(
        &election_path,
        &pub_inputs,
        &srs,
        ProverOpts {
            embed_private_state: true,
            return_private_state: true,
        },
    )
    .unwrap();
    let proof = bundle_with_state.proof;
    let audit_state = bundle_with_state.private_state.as_ref().unwrap();
    assert!(proof.audit_state.is_some(), "audit_state missing");
    let bundle = generate_audit_openings(
        &election_path,
        &proof,
        &srs,
        &vec!["001".to_string()],
        audit_state,
    )
    .unwrap();
    verify_audit_openings(&proof, &srs, &bundle).unwrap();
}

#[test]
fn test_print_audit_open_detects_tamper() {
    let root = workspace_root();
    let election_path = root.join("election.json");
    let srs = Srs::load_from_dir(srs_path()).unwrap();
    let pub_inputs = small_public_inputs(3, &election_path);
    let bundle_with_state = prove_main(
        &election_path,
        &pub_inputs,
        &srs,
        ProverOpts {
            embed_private_state: true,
            return_private_state: true,
        },
    )
    .unwrap();
    let proof = bundle_with_state.proof;
    let audit_state = bundle_with_state.private_state.as_ref().unwrap();
    let mut bundle = generate_audit_openings(
        &election_path,
        &proof,
        &srs,
        &vec!["001".to_string()],
        audit_state,
    )
    .unwrap();
    // Tamper an evaluation
    if let Some(open) = bundle.openings.first_mut() {
        if let Some(eval) = open.evaluations.first_mut() {
            eval.value.0 += &ark_bn254::Fr::one();
        }
    }
    assert!(verify_audit_openings(&proof, &srs, &bundle).is_err());
}
