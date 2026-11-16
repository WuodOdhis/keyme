//! Molecule codec for the CKB subset PSCT needs, plus sighash framing.

use blake2b_simd::Params;

pub fn ckb_hash(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let hash = Params::new()
        .hash_length(32)
        .personal(b"ckb-default-hash")
        .hash(data);
    out.copy_from_slice(hash.as_bytes());
    out
}

pub fn blake160(data: &[u8]) -> [u8; 20] {
    let h = ckb_hash(data);
    let mut out = [0u8; 20];
    out.copy_from_slice(&h[..20]);
    out
}

#[derive(Debug, Clone)]
pub struct Script {
    pub code_hash: [u8; 32],
    pub hash_type: u8,
    pub args: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct CellOutput {
    pub capacity: u64,
    pub lock: Script,
    pub type_: Option<Script>,
}

#[derive(Debug, Clone)]
pub struct OutPoint {
    pub tx_hash: [u8; 32],
    pub index: u32,
}

#[derive(Debug, Clone)]
pub struct CellInput {
    pub since: u64,
    pub previous_output: OutPoint,
}

#[derive(Debug, Clone)]
pub struct CellDep {
    pub out_point: OutPoint,
    pub dep_type: u8,
}

#[derive(Debug, Clone)]
pub struct RawTransaction {
    pub version: u32,
    pub cell_deps: Vec<CellDep>,
    pub header_deps: Vec<[u8; 32]>,
    pub inputs: Vec<CellInput>,
    pub outputs: Vec<CellOutput>,
    pub outputs_data: Vec<Vec<u8>>,
}

fn u32_at(buf: &[u8], off: usize) -> Result<u32, String> {
    buf.get(off..off + 4)
        .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
        .ok_or_else(|| "u32 out of bounds".into())
}

fn u64_at(buf: &[u8], off: usize) -> Result<u64, String> {
    buf.get(off..off + 8)
        .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
        .ok_or_else(|| "u64 out of bounds".into())
}

fn table_offsets(buf: &[u8], start: usize, count: usize) -> Result<Vec<usize>, String> {
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        out.push(start + u32_at(buf, start + 4 + 4 * i)? as usize);
    }
    Ok(out)
}

fn dyn_offsets(buf: &[u8], start: usize) -> Result<Vec<usize>, String> {
    let size = u32_at(buf, start)? as usize;
    if size == 4 {
        return Ok(vec![]);
    }
    let first = u32_at(buf, start + 4)? as usize;
    let count = (first - 4) / 4;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        out.push(start + u32_at(buf, start + 4 + 4 * i)? as usize);
    }
    Ok(out)
}

fn read_bytes(buf: &[u8], start: usize) -> Result<Vec<u8>, String> {
    let n = u32_at(buf, start)? as usize;
    buf.get(start + 4..start + 4 + n)
        .map(|s| s.to_vec())
        .ok_or_else(|| "Bytes out of bounds".into())
}

fn decode_script(buf: &[u8], start: usize) -> Result<Script, String> {
    let offs = table_offsets(buf, start, 3)?;
    let code = buf
        .get(offs[0]..offs[0] + 32)
        .ok_or_else(|| "code_hash out of bounds".to_string())?;
    let mut code_hash = [0u8; 32];
    code_hash.copy_from_slice(code);
    Ok(Script {
        code_hash,
        hash_type: *buf.get(offs[1]).ok_or("hash_type out of bounds")?,
        args: read_bytes(buf, offs[2])?,
    })
}

fn decode_cell_output(buf: &[u8], start: usize) -> Result<CellOutput, String> {
    let offs = table_offsets(buf, start, 3)?;
    let end = start + u32_at(buf, start)? as usize;
    Ok(CellOutput {
        capacity: u64_at(buf, offs[0])?,
        lock: decode_script(buf, offs[1])?,
        type_: if offs[2] >= end {
            None
        } else {
            Some(decode_script(buf, offs[2])?)
        },
    })
}

fn decode_out_point(buf: &[u8], start: usize) -> Result<OutPoint, String> {
    let h = buf
        .get(start..start + 32)
        .ok_or_else(|| "outpoint hash out of bounds".to_string())?;
    let mut tx_hash = [0u8; 32];
    tx_hash.copy_from_slice(h);
    Ok(OutPoint {
        tx_hash,
        index: u32_at(buf, start + 32)?,
    })
}

pub fn decode_raw_transaction(buf: &[u8]) -> Result<RawTransaction, String> {
    let offs = table_offsets(buf, 0, 6)?;
    let version = u32_at(buf, offs[0])?;

    let dep_count = u32_at(buf, offs[1])? as usize;
    let mut cell_deps = Vec::with_capacity(dep_count);
    for i in 0..dep_count {
        let at = offs[1] + 4 + i * 37;
        cell_deps.push(CellDep {
            out_point: decode_out_point(buf, at)?,
            dep_type: *buf.get(at + 36).ok_or("dep_type out of bounds")?,
        });
    }

    let header_count = u32_at(buf, offs[2])? as usize;
    let mut header_deps = Vec::with_capacity(header_count);
    for i in 0..header_count {
        let at = offs[2] + 4 + i * 32;
        let h = buf
            .get(at..at + 32)
            .ok_or_else(|| "header dep out of bounds".to_string())?;
        let mut hash = [0u8; 32];
        hash.copy_from_slice(h);
        header_deps.push(hash);
    }

    let input_count = u32_at(buf, offs[3])? as usize;
    let mut inputs = Vec::with_capacity(input_count);
    for i in 0..input_count {
        let at = offs[3] + 4 + i * 44;
        inputs.push(CellInput {
            since: u64_at(buf, at)?,
            previous_output: decode_out_point(buf, at + 8)?,
        });
    }

    let outputs = dyn_offsets(buf, offs[4])?
        .into_iter()
        .map(|o| decode_cell_output(buf, o))
        .collect::<Result<Vec<_>, _>>()?;
    let outputs_data = dyn_offsets(buf, offs[5])?
        .into_iter()
        .map(|o| read_bytes(buf, o))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(RawTransaction {
        version,
        cell_deps,
        header_deps,
        inputs,
        outputs,
        outputs_data,
    })
}

// ---------------------------------------------------------------- encoding

fn u32le(n: u32) -> Vec<u8> {
    n.to_le_bytes().to_vec()
}

fn u64le(n: u64) -> Vec<u8> {
    n.to_le_bytes().to_vec()
}

fn bytes_vec(b: &[u8]) -> Vec<u8> {
    let mut out = u32le(b.len() as u32);
    out.extend_from_slice(b);
    out
}

fn table(fields: Vec<Vec<u8>>) -> Vec<u8> {
    let header = 4 + 4 * fields.len();
    let total: usize = header + fields.iter().map(|f| f.len()).sum::<usize>();
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&u32le(total as u32));
    let mut off = header;
    for f in &fields {
        out.extend_from_slice(&u32le(off as u32));
        off += f.len();
    }
    for f in fields {
        out.extend_from_slice(&f);
    }
    out
}

fn dyn_vec(items: Vec<Vec<u8>>) -> Vec<u8> {
    if items.is_empty() {
        return u32le(4);
    }
    let header = 4 + 4 * items.len();
    let total: usize = header + items.iter().map(|f| f.len()).sum::<usize>();
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&u32le(total as u32));
    let mut off = header;
    for f in &items {
        out.extend_from_slice(&u32le(off as u32));
        off += f.len();
    }
    for f in items {
        out.extend_from_slice(&f);
    }
    out
}

pub fn encode_script(s: &Script) -> Vec<u8> {
    table(vec![
        s.code_hash.to_vec(),
        vec![s.hash_type],
        bytes_vec(&s.args),
    ])
}

pub fn script_hash(s: &Script) -> [u8; 32] {
    ckb_hash(&encode_script(s))
}

pub fn encode_witness_args(
    lock: Option<&[u8]>,
    input_type: Option<&[u8]>,
    output_type: Option<&[u8]>,
) -> Vec<u8> {
    let opt = |b: Option<&[u8]>| b.map(bytes_vec).unwrap_or_default();
    table(vec![opt(lock), opt(input_type), opt(output_type)])
}

pub fn encode_transaction(raw: &[u8], witnesses: &[Vec<u8>]) -> Vec<u8> {
    let witness_vec = dyn_vec(witnesses.iter().map(|w| bytes_vec(w)).collect());
    table(vec![raw.to_vec(), witness_vec])
}

// ---------------------------------------------------------------- witnesses

#[derive(Debug, Clone, Default)]
pub struct WitnessArgs {
    pub lock: Option<Vec<u8>>,
    pub input_type: Option<Vec<u8>>,
    pub output_type: Option<Vec<u8>>,
}

pub fn decode_witness_args(buf: &[u8]) -> Result<WitnessArgs, String> {
    let offs = table_offsets(buf, 0, 3)?;
    let end = u32_at(buf, 0)? as usize;
    let field = |i: usize| -> Result<Option<Vec<u8>>, String> {
        let start = offs[i];
        let stop = if i + 1 < offs.len() { offs[i + 1] } else { end };
        if stop <= start {
            Ok(None)
        } else {
            Ok(Some(read_bytes(buf, start)?))
        }
    };
    Ok(WitnessArgs {
        lock: field(0)?,
        input_type: field(1)?,
        output_type: field(2)?,
    })
}

/// Sighash-all framing. `transform` edits the group's first witness; the caller stops the message
/// at the first missing witness, matching the lock scripts.
pub fn sighash_message(
    tx_hash: &[u8; 32],
    witnesses: &[Vec<u8>],
    input_count: usize,
    group: &[usize],
    transform: impl Fn(&[u8]) -> Result<Vec<u8>, String>,
) -> Result<[u8; 32], String> {
    let mut data = Vec::new();
    data.extend_from_slice(tx_hash);

    let first = *group.iter().min().ok_or("empty group")?;
    let w0 = transform(
        witnesses
            .get(first)
            .map(|v| v.as_slice())
            .unwrap_or(&[]),
    )?;
    data.extend_from_slice(&u64le(w0.len() as u64));
    data.extend_from_slice(&w0);

    let mut sorted = group.to_vec();
    sorted.sort_unstable();
    for idx in sorted.iter().skip(1) {
        if *idx >= witnesses.len() {
            break;
        }
        let w = &witnesses[*idx];
        data.extend_from_slice(&u64le(w.len() as u64));
        data.extend_from_slice(w);
    }
    for w in witnesses.iter().skip(input_count) {
        data.extend_from_slice(&u64le(w.len() as u64));
        data.extend_from_slice(w);
    }

    Ok(ckb_hash(&data))
}

pub fn zero_lock_secp(witness: &[u8]) -> Result<Vec<u8>, String> {
    let args = if witness.is_empty() {
        WitnessArgs::default()
    } else {
        decode_witness_args(witness)?
    };
    Ok(encode_witness_args(
        Some(&[0u8; 65]),
        args.input_type.as_deref(),
        args.output_type.as_deref(),
    ))
}

pub fn zero_signature_region(witness: &[u8], sig_bytes: usize) -> Result<Vec<u8>, String> {
    if witness.is_empty() {
        return Err("empty witness: expected WitnessArgs".into());
    }
    let offs = table_offsets(witness, 0, 3)?;
    let lock_start = offs[0];
    let lock_len = u32_at(witness, lock_start)? as usize;
    if sig_bytes > lock_len {
        return Err("signature region exceeds lock length".into());
    }
    let mut out = witness.to_vec();
    let data_start = lock_start + 4;
    let from = data_start + lock_len - sig_bytes;
    let to = data_start + lock_len;
    out[from..to].fill(0);
    Ok(out)
}
