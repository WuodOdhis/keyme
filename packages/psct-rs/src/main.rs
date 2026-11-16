mod cbor;
mod molecule;
mod psct;

use std::fs;
use std::process::ExitCode;

use base64::Engine;
use serde_json::json;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: psct-rs <file.psct.b64> [...]");
        return ExitCode::from(2);
    }

    let mut failed = false;
    for path in args {
        let text = match fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("{path}: {e}");
                failed = true;
                continue;
            }
        };
        let bytes = match base64::engine::general_purpose::STANDARD.decode(text.trim()) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("{path}: base64: {e}");
                failed = true;
                continue;
            }
        };
        let psct = match psct::decode_psct(&bytes) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{path}: {e}");
                failed = true;
                continue;
            }
        };
        match psct::finalize(&psct) {
            Ok(report) => {
                let groups: Vec<_> = report
                    .groups
                    .iter()
                    .map(|g| {
                        json!({
                            "script_hash": g.script_hash,
                            "profile": g.profile,
                            "verdict": g.verdict,
                            "signers": g.signers,
                        })
                    })
                    .collect();
                let ok = report.groups.iter().all(|g| g.verdict == "verified");
                if !ok {
                    failed = true;
                }
                println!(
                    "{}",
                    json!({
                        "file": path,
                        "network": psct.network,
                        "tx_hash": report.tx_hash,
                        "full_tx_hash": report.full_tx_hash,
                        "groups": groups,
                        "ok": ok,
                    })
                );
            }
            Err(e) => {
                eprintln!("{path}: {e}");
                failed = true;
            }
        }
    }

    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
