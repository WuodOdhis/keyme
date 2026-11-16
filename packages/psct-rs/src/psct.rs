//! PSCT v0 envelope, finalization and verification.

use std::collections::BTreeMap;

use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::{Message, Secp256k1};

use crate::cbor::{self, Value};
use crate::molecule::{
    blake160, ckb_hash, decode_raw_transaction, decode_witness_args, encode_transaction,
    encode_witness_args, script_hash, sighash_message, zero_lock_secp, zero_signature_region,
    Script, WitnessArgs,
};

pub const MAGIC: [u8; 4] = [0x70, 0x73, 0x63, 0x74];
pub const SECP_PROFILE: &str = "sighash-all/secp256k1-blake160/v1";
pub const MULTISIG_PROFILE: &str = "sighash-all/multisig-legacy/v1";
pub const MULTISIG_V2_PROFILE: &str = "sighash-all/multisig-v2/v1";

const SECP_CODE: &str = "9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8";
const MULTISIG_CODE: &str = "5c5069eb0857efc65e1bca0c07df34c31663b3622fd3876c876320fc9634e2a8";
const MULTISIG_V2_CODE: &str = "36c971b8d41fbd94aabca77dc75e826729ac98447b46f91e00796155dddb0d29";

#[derive(Debug, Clone)]
pub struct Template {
    pub input_type: Option<Vec<u8>>,
    pub output_type: Option<Vec<u8>>,
    pub lock_template: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct Proof {
    pub prev_tx: Vec<u8>,
    pub index: u32,
}

#[derive(Debug, Clone)]
pub struct Sig {
    pub signer: Vec<u8>,
    pub signature: Vec<u8>,
    pub profile: String,
}

#[derive(Debug, Clone)]
pub struct Psct {
    pub network: String,
    pub tx: Vec<u8>,
    pub templates: Vec<Template>,
    pub proofs: Vec<Proof>,
    pub sigs: BTreeMap<String, Vec<Sig>>,
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub fn decode_psct(bytes: &[u8]) -> Result<Psct, String> {
    if bytes.len() < 5 {
        return Err("PSCT too short".into());
    }
    if bytes[..4] != MAGIC {
        return Err("bad PSCT magic".into());
    }
    if bytes[4] != 0 {
        return Err(format!("unsupported PSCT version {}", bytes[4]));
    }
    let value = cbor::decode(&bytes[5..])?;
    let map = value.as_map()?;

    let field = |k: &str| map.get(k).ok_or_else(|| format!("missing {k}"));
    if field("psct")?.as_uint()? != 0 {
        return Err("psct version mismatch".into());
    }
    let network = field("network")?.as_text()?.to_string();
    if network != "ckb" && network != "ckt" {
        return Err(format!("unknown network {network}"));
    }
    let tx = field("tx")?.as_bytes()?.to_vec();

    let mut templates = Vec::new();
    for t in field("witness_templates")?.as_array()? {
        let m = t.as_map()?;
        templates.push(Template {
            input_type: m.get("input_type").map(|v| v.as_bytes().map(|b| b.to_vec())).transpose()?,
            output_type: m.get("output_type").map(|v| v.as_bytes().map(|b| b.to_vec())).transpose()?,
            lock_template: m.get("lock_template").map(|v| v.as_bytes().map(|b| b.to_vec())).transpose()?,
        });
    }

    let mut proofs = Vec::new();
    for p in field("input_proofs")?.as_array()? {
        let m = p.as_map()?;
        proofs.push(Proof {
            prev_tx: m.get("prev_tx").ok_or("missing prev_tx")?.as_bytes()?.to_vec(),
            index: m.get("index").ok_or("missing index")?.as_uint()? as u32,
        });
    }

    let mut sigs: BTreeMap<String, Vec<Sig>> = BTreeMap::new();
    for (key, list) in field("sigs")?.as_map()? {
        let key = key.strip_prefix("0x").unwrap_or(key).to_string();
        let mut out = Vec::new();
        for s in list.as_array()? {
            let m = s.as_map()?;
            out.push(Sig {
                signer: m.get("signer").ok_or("missing signer")?.as_bytes()?.to_vec(),
                signature: m.get("signature").ok_or("missing signature")?.as_bytes()?.to_vec(),
                profile: m.get("profile").ok_or("missing profile")?.as_text()?.to_string(),
            });
        }
        sigs.insert(key.clone(), out);
    }

    Ok(Psct {
        network,
        tx,
        templates,
        proofs,
        sigs,
    })
}

#[derive(Debug)]
pub struct GroupReport {
    pub script_hash: String,
    pub profile: String,
    pub verdict: String,
    pub signers: Vec<String>,
}

#[derive(Debug)]
pub struct Report {
    pub tx_hash: String,
    pub full_tx_hash: String,
    pub groups: Vec<GroupReport>,
}

fn profile_of(lock: &Script) -> Option<&'static str> {
    let code = hex(&lock.code_hash);
    if code == SECP_CODE && lock.hash_type == 1 {
        return Some(SECP_PROFILE);
    }
    if code == MULTISIG_CODE && lock.hash_type == 1 {
        return Some(MULTISIG_PROFILE);
    }
    if code == MULTISIG_V2_CODE && lock.hash_type == 2 {
        return Some(MULTISIG_V2_PROFILE);
    }
    None
}

fn recover(sig: &[u8], digest: &[u8; 32]) -> Result<[u8; 33], String> {
    if sig.len() != 65 {
        return Err(format!("expected 65-byte signature, got {}", sig.len()));
    }
    let secp = Secp256k1::new();
    let msg = Message::from_slice(digest).map_err(|e| e.to_string())?;
    let recid = RecoveryId::from_i32(sig[64] as i32).map_err(|e| e.to_string())?;
    let rsig =
        RecoverableSignature::from_compact(&sig[..64], recid).map_err(|e| e.to_string())?;
    Ok(secp.recover_ecdsa(&msg, &rsig).map_err(|e| e.to_string())?.serialize())
}

struct MultisigConfig {
    require_first_n: usize,
    threshold: usize,
    pubkeys: Vec<[u8; 20]>,
    script_len: usize,
}

fn parse_multisig(lock: &[u8]) -> Result<MultisigConfig, String> {
    if lock.len() < 4 {
        return Err("multisig lock too short".into());
    }
    let require_first_n = lock[1] as usize;
    let threshold = lock[2] as usize;
    let count = lock[3] as usize;
    if lock[0] != 0 || count == 0 || threshold == 0 || threshold > count || require_first_n > threshold {
        return Err("invalid multisig configuration".into());
    }
    let script_len = 4 + 20 * count;
    if lock.len() != script_len + 65 * threshold {
        return Err("multisig lock length mismatch".into());
    }
    let mut pubkeys = Vec::with_capacity(count);
    for i in 0..count {
        let mut p = [0u8; 20];
        p.copy_from_slice(&lock[4 + i * 20..4 + (i + 1) * 20]);
        pubkeys.push(p);
    }
    Ok(MultisigConfig {
        require_first_n,
        threshold,
        pubkeys,
        script_len,
    })
}

fn assemble_multisig(
    cfg: &MultisigConfig,
    template: &[u8],
    sigs: &[Sig],
) -> Result<Vec<u8>, String> {
    let mut chosen: Vec<Vec<u8>> = Vec::new();
    for pubkey in &cfg.pubkeys {
        if chosen.len() == cfg.threshold {
            break;
        }
        if let Some(sig) = sigs.iter().find(|s| s.signer == pubkey) {
            if sig.signature.len() != 65 {
                return Err("multisig signature is not 65 bytes".into());
            }
            chosen.push(sig.signature.clone());
        }
    }
    if chosen.len() < cfg.threshold {
        return Err("not enough multisig signatures".into());
    }
    for i in 0..cfg.require_first_n {
        if !sigs.iter().any(|s| s.signer == cfg.pubkeys[i]) {
            return Err(format!("require_first_n: signer {i} did not sign"));
        }
    }
    let mut out = template[..cfg.script_len].to_vec();
    for sig in chosen {
        out.extend_from_slice(&sig);
    }
    Ok(out)
}

pub fn finalize(psct: &Psct) -> Result<Report, String> {
    let tx = decode_raw_transaction(&psct.tx)?;
    if psct.proofs.len() != tx.inputs.len() {
        return Err("input proof count does not match inputs".into());
    }

    // script hash -> (indices, lock)
    let mut groups: BTreeMap<String, (Vec<usize>, Script)> = BTreeMap::new();
    for (i, input) in tx.inputs.iter().enumerate() {
        let proof = &psct.proofs[i];
        let prev = decode_raw_transaction(&proof.prev_tx)?;
        let expected = input.previous_output.tx_hash;
        if ckb_hash(&proof.prev_tx) != expected {
            return Err(format!("input {i}: prev tx hash mismatch"));
        }
        if proof.index != input.previous_output.index {
            return Err(format!("input {i}: proof index mismatch"));
        }
        let out = prev
            .outputs
            .get(proof.index as usize)
            .ok_or_else(|| format!("input {i}: prev tx has no output {}", proof.index))?;
        let key = hex(&script_hash(&out.lock));
        groups
            .entry(key)
            .or_insert_with(|| (Vec::new(), out.lock.clone()))
            .0
            .push(i);
    }

    let mut locks: BTreeMap<usize, Vec<u8>> = BTreeMap::new();
    let mut reports: Vec<GroupReport> = Vec::new();

    for (key, (indices, lock)) in &groups {
        let first = *indices.iter().min().unwrap();
        let profile = profile_of(lock).ok_or_else(|| format!("no profile for lock {key}"))?;
        let group_sigs = psct.sigs.get(key).cloned().unwrap_or_default();

        if profile == SECP_PROFILE {
            let sig = group_sigs
                .iter()
                .find(|s| s.profile == SECP_PROFILE)
                .ok_or_else(|| format!("missing secp signature for {key}"))?;
            locks.insert(first, sig.signature.clone());
        } else {
            let template = psct.templates[first]
                .lock_template
                .as_ref()
                .ok_or_else(|| format!("missing multisig lock template for {key}"))?;
            let cfg = parse_multisig(template)?;
            let assembled = assemble_multisig(&cfg, template, &group_sigs)?;
            locks.insert(first, assembled);
        }

        reports.push(GroupReport {
            script_hash: key.clone(),
            profile: profile.to_string(),
            verdict: "pending".into(),
            signers: vec![],
        });
    }

    // Build witnesses in the original order.
    let mut witnesses: Vec<Vec<u8>> = Vec::with_capacity(psct.templates.len());
    for (i, t) in psct.templates.iter().enumerate() {
        witnesses.push(encode_witness_args(
            locks.get(&i).map(|v| v.as_slice()),
            t.input_type.as_deref(),
            t.output_type.as_deref(),
        ));
    }

    let full = encode_transaction(&psct.tx, &witnesses);
    let tx_hash = ckb_hash(&psct.tx);
    let full_tx_hash = ckb_hash(&full);

    // Verify every group against the rebuilt witnesses.
    for (key, (indices, lock)) in &groups {
        let profile = profile_of(lock).unwrap();
        let first = *indices.iter().min().unwrap();
        let witness = &witnesses[first];
        let args = decode_witness_args(witness)?.lock.ok_or("missing lock field")?;

        let digest = if profile == SECP_PROFILE {
            sighash_message(&tx_hash, &witnesses, tx.inputs.len(), indices, zero_lock_secp)?
        } else {
            let cfg = parse_multisig(&args)?;
            sighash_message(&tx_hash, &witnesses, tx.inputs.len(), indices, |w| {
                zero_signature_region(w, 65 * cfg.threshold)
            })?
        };

        let report = reports
            .iter_mut()
            .find(|r| &r.script_hash == key)
            .ok_or("internal: group report missing")?;

        if profile == SECP_PROFILE {
            if args.len() != 65 {
                report.verdict = "no-signature".into();
                continue;
            }
            let pubkey = recover(&args, &digest)?;
            let signer = blake160(&pubkey);
            if signer.as_slice() == lock.args.as_slice() {
                report.verdict = "verified".into();
                report.signers = vec![hex(&signer)];
            } else {
                report.verdict = "bad-signature".into();
            }
        } else {
            let cfg = parse_multisig(&args)?;
            let script_len = cfg.script_len;
            let mut used = vec![false; cfg.pubkeys.len()];
            let mut signers = Vec::new();
            for chunk in args[script_len..].chunks(65) {
                if chunk.len() != 65 {
                    return Err("malformed multisig signature region".into());
                }
                let pubkey = recover(chunk, &digest)?;
                let signer = blake160(&pubkey);
                match cfg
                    .pubkeys
                    .iter()
                    .enumerate()
                    .find(|(i, p)| !used[*i] && p.as_slice() == signer.as_slice())
                {
                    Some((i, _)) => {
                        used[i] = true;
                        signers.push(hex(&signer));
                    }
                    None => {
                        report.verdict = "bad-signature".into();
                        break;
                    }
                }
            }
            if report.verdict != "bad-signature" {
                let ok = (0..cfg.require_first_n).all(|i| used[i]);
                report.verdict = if ok { "verified" } else { "bad-signature" }.into();
                report.signers = signers;
            }
        }
    }

    Ok(Report {
        tx_hash: format!("0x{}", hex(&tx_hash)),
        full_tx_hash: format!("0x{}", hex(&full_tx_hash)),
        groups: reports,
    })
}
