use std::collections::HashMap;
use std::path::PathBuf;

use ark_bn254::Bn254;
use ark_poly_commit::kzg10::Commitment;
use zeeperio_kzg::{batch_check, Srs};
use zeeperio_types::Proof;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .unwrap()
        .to_path_buf()
}

#[test]
fn proof_main_openings_match_srs() {
    let root = workspace_root();
    let proof_path = root.join("../foundry/fixtures/proof_main.json");
    let proof_file: serde_json::Value =
        serde_json::from_reader(std::fs::File::open(&proof_path).unwrap()).unwrap();
    let proof: Proof = serde_json::from_value(proof_file.get("proof").cloned().unwrap()).unwrap();
    let srs = Srs::load_from_dir(root.join("srs")).unwrap();
    let vk = srs.verifier_key();
    let mut map = HashMap::<String, Commitment<Bn254>>::new();
    for c in proof.commitments {
        let g1: ark_bn254::G1Affine = c.commitment.clone().try_into().unwrap();
        map.insert(c.label.clone(), Commitment(g1));
    }
    batch_check(&vk, &proof.openings, &map).expect("batch check should pass for proof_main");
}
