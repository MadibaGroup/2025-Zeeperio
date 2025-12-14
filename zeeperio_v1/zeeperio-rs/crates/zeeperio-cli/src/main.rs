use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use ark_bn254::{Fr, G1Affine};
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::CanonicalSerialize;
use clap::{Parser, Subcommand};
use ethabi::ethereum_types::U256;
use ethabi::{encode, Token};
use serde::{Deserialize, Serialize};
use zeeperio_core::{
    load_election, prove_inclusion, prove_main, prove_receipt, ProofWithState, ProverOpts,
};
use zeeperio_kzg::Srs;
use zeeperio_types::{Proof, ProofKind, PublicInputs};

mod audit;
mod inclusion_open;

#[derive(Parser)]
#[command(name = "zeeperio", about = "Zeeperio reference CLI (BN254 only)")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Srs {
        #[command(subcommand)]
        command: SrsCommand,
    },
    //maint proof
    ProveMain(ProofArgs),
    //receipt correctness proof
    ProveReceipt(ProofArgs),
    //ballot-inclusion / shuffle proof
    ProveShuffle(ProofArgs),
    
    InclusionOpen {
        #[arg(long, value_name = "PATH")]
        proof: PathBuf,
        #[arg(long, value_name = "PATH")]
        election: PathBuf,
        #[arg(long, value_name = "PATH")]
        srs: PathBuf,
        #[arg(long, value_name = "NUM")]
        ballot_index: usize,
        #[arg(long, value_name = "PATH")]
        out: PathBuf,
        #[arg(long, value_name = "PATH")]
        state: Option<PathBuf>,
    },

    InclusionVerifyOpen {
        #[arg(long, value_name = "PATH")]
        proof: PathBuf,
        #[arg(long, value_name = "PATH")]
        openings: PathBuf,
        #[arg(long, value_name = "PATH")]
        election: PathBuf,
        #[arg(long, value_name = "PATH")]
        srs: PathBuf,
    },

    PrintAudit {
        #[command(subcommand)]
        command: PrintAuditCommand,
    },

    ExportSolidity {
        #[arg(long, value_name = "PATH")]
        proof: PathBuf,
        #[arg(long, value_name = "PATH")]
        out: PathBuf,
        #[arg(long, value_name = "PATH")]
        bin_out: Option<PathBuf>,
    },
 
    Fixtures {
        #[arg(long, value_name = "DIR")]
        out: PathBuf,
        #[arg(long, value_name = "DIR", default_value = "srs")]
        srs: PathBuf,
        #[arg(long, value_name = "NUM", default_value_t = 42)]
        seed: u64,
    },
}

#[derive(Subcommand)]
enum SrsCommand {
    //poweroftau import
    #[command(name = "import-ptau")]
    ImportPtau {
        #[arg(long, value_name = "PATH")]
        ptau: PathBuf,
        #[arg(long, value_name = "DIR")]
        out: PathBuf,
        #[arg(long, value_name = "NUM", default_value_t = 2048)]
        degree: usize,
    },
}

#[derive(Subcommand)]
enum PrintAuditCommand {
    Verify {
        #[arg(long, value_name = "PATH")]
        r#in: PathBuf,
        #[arg(long, value_name = "PATH")]
        audit: PathBuf,
        #[arg(long, value_name = "PATH")]
        public: PathBuf,
        #[arg(long, value_name = "NUM")]
        candidates: usize,
    },
    Open {
        #[arg(long, value_name = "PATH")]
        proof: PathBuf,
        #[arg(long, value_name = "PATH")]
        election: PathBuf,
        #[arg(long, value_name = "PATH")]
        audit: PathBuf,
        #[arg(long, value_name = "PATH")]
        srs: PathBuf,
        #[arg(long, value_name = "PATH")]
        out: PathBuf,
        #[arg(long, value_name = "PATH")]
        audit_state: Option<PathBuf>,
    },
    VerifyOpen {
        #[arg(long, value_name = "PATH")]
        proof: PathBuf,
        #[arg(long, value_name = "PATH")]
        openings: PathBuf,
        #[arg(long, value_name = "PATH")]
        srs: PathBuf,
    },
}

#[derive(Parser, Clone)]
struct ProofArgs {
    #[arg(long, value_name = "PATH")]
    r#in: PathBuf,
    #[arg(long, value_name = "DIR")]
    srs: PathBuf,
    #[arg(long, value_name = "NUM")]
    candidates: usize,
    #[arg(long, value_name = "NUM")]
    sum_a: u64,
    #[arg(long, value_name = "NUM")]
    sum_m: u64,
    #[arg(long, value_name = "LIST")]
    tally: String,
    #[arg(long, value_name = "PATH")]
    out: PathBuf,
    #[arg(long, value_name = "NUM")]
    disputed_code: Option<u64>,
    #[arg(long, value_name = "NUM")]
    ballot_index: Option<usize>,
    #[arg(long, value_name = "NUM")]
    seed: Option<u64>,
    #[arg(long, default_value_t = false)]
    emit_audit_state: bool,
    #[arg(long, value_name = "PATH")]
    audit_out: Option<PathBuf>,
}

#[derive(Serialize, Deserialize)]
struct ProofFile {
    proof: Proof,
}

#[derive(Serialize)]
struct SolidityCommitment {
    label: u16,
    x: String,
    y: String,
}

#[derive(Serialize)]
struct SolidityOpening {
    point: String,
    gamma: String,
    witness: (String, String),
    labels: Vec<u16>,
    values: Vec<String>,
    blindings: Vec<String>,
}

#[derive(Serialize)]
struct SolidityProof {
    kind: u8,
    public_inputs: serde_json::Value,
    commitments: Vec<SolidityCommitment>,
    openings: Vec<SolidityOpening>,
    alpha: String,
    beta: String,
    zeta: String,
    r: String,
    calldata: String,
}

fn parse_tally(input: &str, candidates: usize) -> Result<Vec<u64>> {
    let vals: Vec<u64> = input
        .split(',')
        .filter(|s| !s.trim().is_empty())
        .map(|s| {
            s.trim()
                .parse::<u64>()
                .map_err(|e| anyhow!("invalid tally entry {s}: {e}"))
        })
        .collect::<Result<_, _>>()?;
    if vals.len() != candidates {
        return Err(anyhow!(
            "tally length {} does not match candidates {}",
            vals.len(),
            candidates
        ));
    }
    Ok(vals)
}

fn build_public_inputs(args: &ProofArgs) -> Result<PublicInputs> {
    let tally_vals = parse_tally(&args.tally, args.candidates)?;
    Ok(PublicInputs {
        n: 0,
        candidates: args.candidates,
        sum_a_ballots: args.sum_a,
        sum_m: args.sum_m,
        tally: tally_vals,
        shuffle_hash: None,
        receipt_root: None,
        disputed_code: args.disputed_code,
        ballot_index: args.ballot_index,
    })
}

fn save_proof(path: &PathBuf, proof: &Proof) -> Result<()> {
    let wrapped = ProofFile {
        proof: proof.clone(),
    };
    let file = fs::File::create(path).context("create proof file")?;
    serde_json::to_writer_pretty(file, &wrapped).context("write proof")?;
    Ok(())
}

fn run_prove(args: ProofArgs, kind: ProofKind) -> Result<()> {
    let srs = Srs::load_from_dir(&args.srs).context("load srs")?;
    let mut public_inputs = build_public_inputs(&args)?;
    let state_opts = ProverOpts {
        embed_private_state: args.emit_audit_state,
        return_private_state: args.emit_audit_state || args.audit_out.is_some(),
    };
    let bundle: ProofWithState = match kind {
        ProofKind::Main => prove_main(&args.r#in, &public_inputs, &srs, state_opts)?,
        ProofKind::BallotInclusion => {
            prove_inclusion(&args.r#in, &public_inputs, &srs, state_opts)?
        }
        ProofKind::Receipt => {
            ProofWithState::from(prove_receipt(&args.r#in, &public_inputs, &srs)?)
        }
    };
    public_inputs.n = bundle.proof.public.n;
    if let Some(path) = args.audit_out.as_ref() {
        let state = bundle.private_state.as_ref().ok_or_else(|| {
            anyhow!("private state not available; re-run with --emit-audit-state")
        })?;
        let file = fs::File::create(path).context("create audit state file")?;
        serde_json::to_writer_pretty(file, state).context("write audit state file")?;
        println!("Private state written to {}", path.display());
    }
    save_proof(&args.out, &bundle.proof)?;
    println!(
        "Proof ({:?}) written to {} (n = {})",
        bundle.proof.kind,
        args.out.display(),
        public_inputs.n
    );
    Ok(())
}

fn run_print_audit(
    election: &PathBuf,
    audit: &PathBuf,
    public: &PathBuf,
    candidates: usize,
) -> Result<()> {
    let data = load_election(election, candidates).context("load election")?;
    let audit_ids: Vec<String> =
        serde_json::from_str(&fs::read_to_string(audit)?).context("parse audit file")?;
    let public_inputs: PublicInputs =
        serde_json::from_str(&fs::read_to_string(public)?).context("parse public inputs")?;

    let audited: Vec<&str> = data
        .rows
        .iter()
        .filter(|r| r.audit_bit == 1)
        .map(|r| r.ballot_id.as_str())
        .collect();

    let mut violations = Vec::new();
    for id in &audit_ids {
        if !audited.iter().any(|row_id| row_id == id) {
            violations.push(format!("audit id {id} not present as audited ballot"));
        }
    }
    if audited.len() != audit_ids.len() {
        violations.push(format!(
            "audit count mismatch: expected {}, found {}",
            audit_ids.len(),
            audited.len()
        ));
    }

    let sum_a: u64 = data.rows.iter().map(|r| r.audit_bit).sum();
    let sum_m: u64 = data.rows.iter().map(|r| r.mark_bit).sum();
    if public_inputs.sum_a_ballots != sum_a {
        violations.push(format!(
            "public sum_a mismatch: public {}, computed {}",
            public_inputs.sum_a_ballots, sum_a
        ));
    }
    if public_inputs.sum_m != sum_m {
        violations.push(format!(
            "public sum_m mismatch: public {}, computed {}",
            public_inputs.sum_m, sum_m
        ));
    }

    if violations.is_empty() {
        println!("Print audit: PASS ({} ballots checked)", data.rows.len());
    } else {
        println!("Print audit: FAIL");
        for v in violations {
            println!(" - {}", v);
        }
    }
    Ok(())
}

fn run_print_audit_open(
    proof_path: &PathBuf,
    election: &PathBuf,
    audit: &PathBuf,
    srs_dir: &PathBuf,
    out: &PathBuf,
    audit_state_path: &Option<PathBuf>,
) -> Result<()> {
    let proof_file: ProofFile =
        serde_json::from_reader(fs::File::open(proof_path)?).context("read proof")?;
    let audit_ids: Vec<String> =
        serde_json::from_str(&fs::read_to_string(audit)?).context("parse audit file")?;
    let srs = Srs::load_from_dir(srs_dir).context("load srs")?;
    let audit_state = if let Some(path) = audit_state_path {
        serde_json::from_reader(fs::File::open(path)?).context("read audit state file")?
    } else {
        proof_file.proof.audit_state.clone().ok_or_else(|| {
            anyhow!(
                "audit_state missing; pass --audit-state or generate proof with --emit-audit-state"
            )
        })?
    };
    let bundle = audit::generate_audit_openings(
        election,
        &proof_file.proof,
        &srs,
        &audit_ids,
        &audit_state,
    )?;
    let mut file = fs::File::create(out).context("create audit openings file")?;
    serde_json::to_writer_pretty(&mut file, &bundle).context("write openings")?;
    println!("Print-audit openings written to {}", out.display());
    Ok(())
}

fn run_print_audit_verify_open(
    proof_path: &PathBuf,
    openings: &PathBuf,
    srs_dir: &PathBuf,
) -> Result<()> {
    let proof_file: ProofFile =
        serde_json::from_reader(fs::File::open(proof_path)?).context("read proof")?;
    let bundle: audit::AuditOpeningBundle =
        serde_json::from_reader(fs::File::open(openings)?).context("read openings")?;
    let srs = Srs::load_from_dir(srs_dir).context("load srs")?;
    audit::verify_audit_openings(&proof_file.proof, &srs, &bundle).context("verify openings")?;
    println!("Print-audit openings verified");
    Ok(())
}

fn run_inclusion_open(
    proof_path: &PathBuf,
    election: &PathBuf,
    srs_dir: &PathBuf,
    ballot_index: usize,
    out: &PathBuf,
    state_path: &Option<PathBuf>,
) -> Result<()> {
    let proof_file: ProofFile =
        serde_json::from_reader(fs::File::open(proof_path)?).context("read proof")?;
    let state = if let Some(path) = state_path {
        serde_json::from_reader(fs::File::open(path)?).context("read inclusion state")?
    } else {
        proof_file.proof.audit_state.clone().ok_or_else(|| {
            anyhow!("private state missing; pass --state or generate proof with --emit-audit-state")
        })?
    };
    let srs = Srs::load_from_dir(srs_dir).context("load srs")?;
    let bundle = inclusion_open::generate_inclusion_openings(
        &proof_file.proof,
        election,
        &srs,
        ballot_index,
        &state,
    )
    .context("generate inclusion openings")?;
    let mut file = fs::File::create(out).context("create inclusion openings file")?;
    serde_json::to_writer_pretty(&mut file, &bundle).context("write inclusion openings")?;
    println!("Inclusion openings written to {}", out.display());
    Ok(())
}

fn run_inclusion_verify_open(
    proof_path: &PathBuf,
    openings: &PathBuf,
    election: &PathBuf,
    srs_dir: &PathBuf,
) -> Result<()> {
    let proof_file: ProofFile =
        serde_json::from_reader(fs::File::open(proof_path)?).context("read proof")?;
    let bundle: inclusion_open::InclusionOpeningsBundle =
        serde_json::from_reader(fs::File::open(openings)?).context("read openings")?;
    let srs = Srs::load_from_dir(srs_dir).context("load srs")?;
    inclusion_open::verify_inclusion_openings(&proof_file.proof, &srs, election, &bundle)
        .context("verify inclusion openings")?;
    println!("Inclusion openings verified");
    Ok(())
}

fn compute_public_inputs_from_data(
    data: &zeeperio_core::ElectionData,
    tally: Vec<u64>,
) -> PublicInputs {
    let mut sum_a_ballots = 0u64;
    let mut idx = 0;
    while idx < data.rows.len() {
        if data.rows[idx].audit_bit == 1 {
            sum_a_ballots += 1;
        }
        idx += data.candidates;
    }
    let sum_m = data.rows.iter().map(|r| r.mark_bit).sum::<u64>();
    PublicInputs {
        n: data.n,
        candidates: data.candidates,
        sum_a_ballots,
        sum_m,
        tally,
        shuffle_hash: None,
        receipt_root: None,
        disputed_code: None,
        ballot_index: None,
    }
}

fn generate_fixtures(out: &PathBuf, srs_dir: &PathBuf, _seed: u64) -> Result<()> {
    fs::create_dir_all(out).context("create fixtures dir")?;
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .ok_or_else(|| anyhow!("invalid manifest dir"))?
        .to_path_buf();
    let election_path = root.join("election.json");
    let srs = Srs::load_from_dir(srs_dir).context("load srs")?;
    let data = load_election(&election_path, 3).context("load election")?;

    // compute tally per candidate position
    let mut tally = vec![0u64; data.candidates];
    for (idx, row) in data.rows.iter().enumerate() {
        tally[idx % data.candidates] += row.mark_bit;
    }
    let public_inputs = compute_public_inputs_from_data(&data, tally.clone());

    let proof_main = prove_main(
        &election_path,
        &public_inputs,
        &srs,
        ProverOpts {
            embed_private_state: false,
            return_private_state: true,
        },
    )?;
    save_proof(&out.join("proof_main.json"), &proof_main.proof)?;
    if let Some(state) = proof_main.private_state.as_ref() {
        let file = fs::File::create(out.join("audit_state_main.json"))
            .context("create main audit state")?;
        serde_json::to_writer_pretty(file, state).context("write main audit state")?;
    }

    let proof_incl = prove_inclusion(
        &election_path,
        &public_inputs,
        &srs,
        ProverOpts {
            embed_private_state: false,
            return_private_state: true,
        },
    )?;
    save_proof(&out.join("proof_inclusion.json"), &proof_incl.proof)?;
    if let Some(state) = proof_incl.private_state.as_ref() {
        let file = fs::File::create(out.join("inclusion_state.json"))
            .context("create inclusion state file")?;
        serde_json::to_writer_pretty(file, state).context("write inclusion state")?;
    }

    let mut receipt_inputs = public_inputs.clone();
    let missing_code = data.rows.iter().map(|r| r.code).max().unwrap_or(0) + 1;
    receipt_inputs.disputed_code = Some(missing_code);
    receipt_inputs.ballot_index = Some(0);
    let proof_receipt = prove_receipt(&election_path, &receipt_inputs, &srs)?;
    save_proof(&out.join("proof_receipt.json"), &proof_receipt)?;

    export_solidity(
        &out.join("proof_main.json"),
        &out.join("calldata_main.json"),
        &Some(out.join("calldata_main.bin")),
    )?;
    export_solidity(
        &out.join("proof_inclusion.json"),
        &out.join("calldata_inclusion.json"),
        &Some(out.join("calldata_inclusion.bin")),
    )?;
    export_solidity(
        &out.join("proof_receipt.json"),
        &out.join("calldata_receipt.json"),
        &Some(out.join("calldata_receipt.bin")),
    )?;

    println!("Fixtures generated in {}", out.display());
    Ok(())
}

fn export_solidity(proof_path: &PathBuf, out: &PathBuf, bin_out: &Option<PathBuf>) -> Result<()> {
    let data: ProofFile =
        serde_json::from_reader(fs::File::open(proof_path)?).context("read proof")?;
    let proof = data.proof;
    let kind_code = match proof.kind {
        ProofKind::Main => 0u8,
        ProofKind::BallotInclusion => 1u8,
        ProofKind::Receipt => 2u8,
    };

    let commitments = proof
        .commitments
        .iter()
        .filter_map(|c| {
            label_code(&c.label, proof.kind.clone()).map(|code| {
                let g1: G1Affine = c.commitment.clone().try_into().expect("g1 parse");
                let (x, y) = g1_to_hex(&g1);
                SolidityCommitment { label: code, x, y }
            })
        })
        .collect::<Vec<_>>();

    let openings = proof
        .openings
        .iter()
        .map(|o| SolidityOpening {
            point: fr_to_hex(&o.point.0),
            gamma: fr_to_hex(&o.gamma.0),
            witness: g1_to_hex(&o.witness.0),
            labels: o
                .polys
                .iter()
                .filter_map(|l| label_code(l, proof.kind.clone()))
                .collect::<Vec<_>>(),
            values: o
                .evaluations
                .iter()
                .map(|e| fr_to_hex(&e.value.0))
                .collect(),
            blindings: o
                .evaluations
                .iter()
                .map(|e| fr_to_hex(&e.blinding.0))
                .collect(),
        })
        .collect::<Vec<_>>();

    let alpha_hex = fr_to_hex(&proof.alpha.0);
    let beta_hex = proof
        .beta
        .as_ref()
        .map(|b| fr_to_hex(&b.0))
        .unwrap_or_else(|| "0x0".into());
    let zeta_hex = fr_to_hex(&proof.zeta.0);
    let r_hex = proof
        .r
        .as_ref()
        .map(|v| fr_to_hex(&v.0))
        .unwrap_or_else(|| "0x0".into());

    let calldata_bytes = encode_proof_calldata(&proof)?;
    let calldata_hex = format!("0x{}", hex::encode(&calldata_bytes));
    if let Some(path) = bin_out {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).context("create bin dir")?;
        }
        fs::write(path, &calldata_hex).context("write calldata bytes")?;
        println!("Calldata bytes written to {}", path.display());
    }

    let public_json = serde_json::to_value(&proof.public)?;
    let sol_proof = SolidityProof {
        kind: kind_code,
        public_inputs: public_json,
        commitments,
        openings,
        alpha: alpha_hex,
        beta: beta_hex,
        zeta: zeta_hex,
        r: r_hex,
        calldata: calldata_hex,
    };

    let file = fs::File::create(out).context("create export file")?;
    serde_json::to_writer_pretty(file, &sol_proof).context("write export")?;
    println!("Solidity export written to {}", out.display());
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Srs { command } => match command {
            SrsCommand::ImportPtau { ptau, out, degree } => {
                let srs = Srs::import_from_ptau(&ptau, degree).context("import ptau")?;
                srs.save_to_dir(&out).context("store srs")?;
                println!(
                    "SRS imported from {} into {} (degree {})",
                    ptau.display(),
                    out.display(),
                    degree
                );
            }
        },
        Commands::ProveMain(args) => run_prove(args, ProofKind::Main)?,
        Commands::ProveReceipt(args) => run_prove(args, ProofKind::Receipt)?,
        Commands::ProveShuffle(args) => run_prove(args, ProofKind::BallotInclusion)?,
        Commands::InclusionOpen {
            proof,
            election,
            srs,
            ballot_index,
            out,
            state,
        } => run_inclusion_open(&proof, &election, &srs, ballot_index, &out, &state)?,
        Commands::InclusionVerifyOpen {
            proof,
            openings,
            election,
            srs,
        } => run_inclusion_verify_open(&proof, &openings, &election, &srs)?,
        Commands::PrintAudit { command } => match command {
            PrintAuditCommand::Verify {
                r#in,
                audit,
                public,
                candidates,
            } => run_print_audit(&r#in, &audit, &public, candidates)?,
            PrintAuditCommand::Open {
                proof,
                election,
                audit,
                srs,
                out,
                audit_state,
            } => run_print_audit_open(&proof, &election, &audit, &srs, &out, &audit_state)?,
            PrintAuditCommand::VerifyOpen {
                proof,
                openings,
                srs,
            } => run_print_audit_verify_open(&proof, &openings, &srs)?,
        },
        Commands::ExportSolidity {
            proof,
            out,
            bin_out,
        } => export_solidity(&proof, &out, &bin_out)?,
        Commands::Fixtures { out, srs, seed } => generate_fixtures(&out, &srs, seed)?,
    }
    Ok(())
}

fn encode_proof_calldata(proof: &Proof) -> Result<Vec<u8>> {
    let kind_code = match proof.kind {
        ProofKind::Main => 0u8,
        ProofKind::BallotInclusion => 1u8,
        ProofKind::Receipt => 2u8,
    };

    let commitments_tokens = proof
        .commitments
        .iter()
        .filter_map(|c| {
            label_code(&c.label, proof.kind.clone()).map(|code| {
                let g1: G1Affine = c.commitment.clone().try_into().expect("g1 parse");
                let (x, y) = g1_to_u256(&g1);
                Token::Tuple(vec![
                    Token::Uint(U256::from(code)),
                    Token::Tuple(vec![Token::Uint(x), Token::Uint(y)]),
                ])
            })
        })
        .collect::<Vec<_>>();

    let openings_tokens = proof
        .openings
        .iter()
        .map(|o| {
            let (wx, wy) = g1_to_u256(&o.witness.0);
            let label_tokens = o
                .polys
                .iter()
                .filter_map(|l| label_code(l, proof.kind.clone()))
                .map(|l| Token::Uint(U256::from(l)))
                .collect::<Vec<_>>();
            let value_tokens = o
                .evaluations
                .iter()
                .map(|e| Token::Uint(fr_to_u256(&e.value.0)))
                .collect::<Vec<_>>();
            let blinding_tokens = o
                .evaluations
                .iter()
                .map(|e| Token::Uint(fr_to_u256(&e.blinding.0)))
                .collect::<Vec<_>>();

            Token::Tuple(vec![
                Token::Tuple(vec![Token::Uint(wx), Token::Uint(wy)]),
                Token::Uint(fr_to_u256(&o.point.0)),
                Token::Uint(fr_to_u256(&o.gamma.0)),
                Token::Array(label_tokens),
                Token::Array(value_tokens),
                Token::Array(blinding_tokens),
            ])
        })
        .collect::<Vec<_>>();

    let public_tokens = public_inputs_tokens(&proof.public);

    let proof_tokens = Token::Tuple(vec![
        Token::Uint(U256::from(kind_code)),
        Token::Array(commitments_tokens),
        Token::Array(openings_tokens),
        Token::Tuple(public_tokens),
        Token::Uint(fr_to_u256(&proof.alpha.0)),
        Token::Uint(
            proof
                .beta
                .as_ref()
                .map(|b| fr_to_u256(&b.0))
                .unwrap_or_else(U256::zero),
        ),
        Token::Uint(fr_to_u256(&proof.zeta.0)),
        Token::Uint(
            proof
                .r
                .as_ref()
                .map(|v| fr_to_u256(&v.0))
                .unwrap_or_else(U256::zero),
        ),
    ]);

    Ok(encode(&[proof_tokens]))
}

fn public_inputs_tokens(public: &PublicInputs) -> Vec<Token> {
    vec![
        Token::Uint(U256::from(public.n as u64)),
        Token::Uint(U256::from(public.candidates as u64)),
        Token::Uint(U256::from(public.sum_a_ballots)),
        Token::Uint(U256::from(public.sum_m)),
        Token::Array(
            public
                .tally
                .iter()
                .map(|t| Token::Uint(U256::from(*t)))
                .collect(),
        ),
        Token::Uint(U256::from(public.disputed_code.unwrap_or(0))),
        Token::Uint(U256::from(public.ballot_index.unwrap_or(0) as u64)),
    ]
}

fn fr_to_u256(fr: &Fr) -> U256 {
    let mut bytes = Vec::new();
    fr.serialize_compressed(&mut bytes).expect("fr serialize");
    U256::from_little_endian(&bytes)
}

fn g1_to_u256(p: &G1Affine) -> (U256, U256) {
    (field_to_u256(&p.x), field_to_u256(&p.y))
}

fn field_to_u256<F: PrimeField>(value: &F) -> U256 {
    let mut bytes = value.into_bigint().to_bytes_be();
    if bytes.len() < 32 {
        let mut padded = vec![0u8; 32 - bytes.len()];
        padded.append(&mut bytes);
        bytes = padded;
    }
    U256::from_big_endian(&bytes)
}

fn fr_to_hex(fr: &Fr) -> String {
    let mut bytes = Vec::new();
    fr.serialize_compressed(&mut bytes).expect("fr serialize");
    format!("0x{}", hex::encode(bytes))
}

fn g1_to_hex(p: &G1Affine) -> (String, String) {
    let (x, y) = (p.x, p.y);
    (
        format!("0x{}", hex::encode(x.into_bigint().to_bytes_be())),
        format!("0x{}", hex::encode(y.into_bigint().to_bytes_be())),
    )
}

fn label_code(label: &str, kind: ProofKind) -> Option<u16> {
    match (label, kind) {
        ("A", ProofKind::Main) => Some(0),
        ("M", ProofKind::Main) => Some(1),
        ("SblkA", ProofKind::Main) => Some(2),
        ("SblkM", ProofKind::Main) => Some(3),
        ("AccA", ProofKind::Main) => Some(4),
        ("AccM", ProofKind::Main) => Some(5),
        ("TallyAcc", ProofKind::Main) => Some(6),
        ("ZPad", ProofKind::Main) => Some(7),
        ("SelBlkA", ProofKind::Main) => Some(8),
        ("Z1A", ProofKind::Main) => Some(9),
        ("Z2A", ProofKind::Main) => Some(10),
        ("Z3A", ProofKind::Main) => Some(11),
        ("Z1M", ProofKind::Main) => Some(12),
        ("Z2M", ProofKind::Main) => Some(13),
        ("Z3M", ProofKind::Main) => Some(14),
        ("TailKeep", ProofKind::Main) => Some(15),
        ("TailSkip", ProofKind::Main) => Some(16),
        ("Q", ProofKind::Main) => Some(17),
        (s, ProofKind::Main) if s.starts_with("CandSel") => {
            let idx: u16 = s.trim_start_matches("CandSel").parse().unwrap_or(0);
            Some(1000 + idx)
        }
        ("BID", ProofKind::BallotInclusion) => Some(200),
        ("Cconfirm", ProofKind::BallotInclusion) => Some(201),
        ("M", ProofKind::BallotInclusion) => Some(202),
        ("BIDSh", ProofKind::BallotInclusion) => Some(203),
        ("CconfirmSh", ProofKind::BallotInclusion) => Some(204),
        ("MSh", ProofKind::BallotInclusion) | ("MShuffled", ProofKind::BallotInclusion) => {
            Some(205)
        }
        ("T", ProofKind::BallotInclusion) => Some(206),
        ("TPrime", ProofKind::BallotInclusion) => Some(207),
        ("T1", ProofKind::BallotInclusion) => Some(208),
        ("T2", ProofKind::BallotInclusion) => Some(209),
        ("AccT1", ProofKind::BallotInclusion) => Some(210),
        ("AccT2", ProofKind::BallotInclusion) => Some(211),
        ("Q", ProofKind::BallotInclusion) => Some(212),
        ("D", ProofKind::Receipt) => Some(300),
        ("Cconfirm", ProofKind::Receipt) => Some(301),
        ("Inv", ProofKind::Receipt) => Some(305),
        ("Sel", ProofKind::Receipt) => Some(302),
        ("AccSel", ProofKind::Receipt) => Some(303),
        ("Q", ProofKind::Receipt) => Some(304),
        _ => None,
    }
}
