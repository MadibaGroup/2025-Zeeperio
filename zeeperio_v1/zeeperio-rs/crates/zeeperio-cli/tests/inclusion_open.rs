use std::path::PathBuf;

use zeeperio_cli::inclusion_open;
use zeeperio_core::{load_election, prove_inclusion, ProverOpts};
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
fn inclusion_open_roundtrip() {
    let root = workspace_root();
    let election_path = root.join("election.json");
    let srs = Srs::load_from_dir(srs_path()).unwrap();
    let pub_inputs = small_public_inputs(3, &election_path);
    let proof_bundle = prove_inclusion(
        &election_path,
        &pub_inputs,
        &srs,
        ProverOpts {
            embed_private_state: true,
            return_private_state: true,
        },
    )
    .unwrap();
    let proof = proof_bundle.proof;
    let state = proof_bundle.private_state.unwrap();
    let openings =
        inclusion_open::generate_inclusion_openings(&proof, &election_path, &srs, 0, &state)
            .unwrap();
    inclusion_open::verify_inclusion_openings(&proof, &srs, &election_path, &openings).unwrap();
}

#[test]
fn inclusion_open_tamper_detected() {
    let root = workspace_root();
    let election_path = root.join("election.json");
    let srs = Srs::load_from_dir(srs_path()).unwrap();
    let pub_inputs = small_public_inputs(3, &election_path);
    let proof_bundle = prove_inclusion(
        &election_path,
        &pub_inputs,
        &srs,
        ProverOpts {
            embed_private_state: true,
            return_private_state: true,
        },
    )
    .unwrap();
    let proof = proof_bundle.proof;
    let state = proof_bundle.private_state.unwrap();
    let mut openings =
        inclusion_open::generate_inclusion_openings(&proof, &election_path, &srs, 0, &state)
            .unwrap();
    if let Some(open) = openings.openings.first_mut() {
        if let Some(eval) = open.evaluations.first_mut() {
            eval.value.0 += ark_bn254::Fr::from(2u64);
        }
    }
    assert!(
        inclusion_open::verify_inclusion_openings(&proof, &srs, &election_path, &openings).is_err(),
        "tampering should be detected"
    );
}

#[test]
fn inclusion_open_rejects_wrong_ballot() {
    let root = workspace_root();
    let election_path = root.join("election.json");
    let srs = Srs::load_from_dir(srs_path()).unwrap();
    let pub_inputs = small_public_inputs(3, &election_path);
    let proof_bundle = prove_inclusion(
        &election_path,
        &pub_inputs,
        &srs,
        ProverOpts {
            embed_private_state: true,
            return_private_state: true,
        },
    )
    .unwrap();
    let proof = proof_bundle.proof;
    let state = proof_bundle.private_state.unwrap();
    let mut openings =
        inclusion_open::generate_inclusion_openings(&proof, &election_path, &srs, 0, &state)
            .unwrap();
    openings.ballot_index = 99;
    assert!(
        inclusion_open::verify_inclusion_openings(&proof, &srs, &election_path, &openings).is_err(),
        "wrong ballot index should fail"
    );
}
