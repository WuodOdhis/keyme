//! Canonical CBOR subset for PSCT v0.
//!
//! Mirrors the TypeScript decoder: unsigned integers, bytes, text, arrays, text-keyed maps,
//! booleans and null. Indefinite lengths, tags, floats, negative integers, non-minimal integers,
//! unordered map keys and duplicate keys are all rejected.

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Uint(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    Map(BTreeMap<String, Value>),
    Bool(bool),
    Null,
}

impl Value {
    pub fn as_map(&self) -> Result<&BTreeMap<String, Value>, String> {
        match self {
            Value::Map(m) => Ok(m),
            _ => Err("expected map".into()),
        }
    }
    pub fn as_bytes(&self) -> Result<&[u8], String> {
        match self {
            Value::Bytes(b) => Ok(b),
            _ => Err("expected bytes".into()),
        }
    }
    pub fn as_array(&self) -> Result<&[Value], String> {
        match self {
            Value::Array(a) => Ok(a),
            _ => Err("expected array".into()),
        }
    }
    pub fn as_text(&self) -> Result<&str, String> {
        match self {
            Value::Text(s) => Ok(s),
            _ => Err("expected text".into()),
        }
    }
    pub fn as_uint(&self) -> Result<u64, String> {
        match self {
            Value::Uint(n) => Ok(*n),
            _ => Err("expected unsigned integer".into()),
        }
    }
}

struct Reader<'a> {
    buf: &'a [u8],
    off: usize,
}

impl<'a> Reader<'a> {
    fn byte(&mut self) -> Result<u8, String> {
        if self.off >= self.buf.len() {
            return Err("unexpected end of CBOR".into());
        }
        let b = self.buf[self.off];
        self.off += 1;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.off + n > self.buf.len() {
            return Err("unexpected end of CBOR".into());
        }
        let s = &self.buf[self.off..self.off + n];
        self.off += n;
        Ok(s)
    }

    fn uint(&mut self, info: u8) -> Result<u64, String> {
        match info {
            0..=23 => Ok(info as u64),
            24 => {
                let v = self.byte()? as u64;
                if v < 24 {
                    return Err("non-canonical integer".into());
                }
                Ok(v)
            }
            25 => {
                let v = ((self.byte()? as u64) << 8) | self.byte()? as u64;
                if v < 256 {
                    return Err("non-canonical integer".into());
                }
                Ok(v)
            }
            26 => {
                let mut v = 0u64;
                for _ in 0..4 {
                    v = (v << 8) | self.byte()? as u64;
                }
                if v < 65536 {
                    return Err("non-canonical integer".into());
                }
                Ok(v)
            }
            27 => {
                let mut v = 0u64;
                for _ in 0..8 {
                    v = (v << 8) | self.byte()? as u64;
                }
                if v < 4_294_967_296 {
                    return Err("non-canonical integer".into());
                }
                Ok(v)
            }
            31 => Err("indefinite length is not canonical".into()),
            _ => Err(format!("invalid additional info {info}")),
        }
    }

    fn read(&mut self) -> Result<Value, String> {
        let initial = self.byte()?;
        let major = initial >> 5;
        let info = initial & 0x1f;
        match major {
            0 => Ok(Value::Uint(self.uint(info)?)),
            2 => {
                let n = self.uint(info)? as usize;
                Ok(Value::Bytes(self.take(n)?.to_vec()))
            }
            3 => {
                let n = self.uint(info)? as usize;
                let s = std::str::from_utf8(self.take(n)?)
                    .map_err(|_| "invalid UTF-8 in CBOR text".to_string())?;
                Ok(Value::Text(s.to_string()))
            }
            4 => {
                let n = self.uint(info)? as usize;
                let mut out = Vec::with_capacity(n.min(1024));
                for _ in 0..n {
                    out.push(self.read()?);
                }
                Ok(Value::Array(out))
            }
            5 => {
                let n = self.uint(info)? as usize;
                let mut map = BTreeMap::new();
                let mut prev: Option<(usize, Vec<u8>)> = None;
                for _ in 0..n {
                    let key_start = self.off;
                    let key = self.read()?;
                    let key_bytes = self.buf[key_start..self.off].to_vec();
                    if let Some((len, bytes)) = &prev {
                        let ordered = key_bytes.len() > *len
                            || (key_bytes.len() == *len && key_bytes.as_slice() > bytes.as_slice());
                        if !ordered {
                            return Err("CBOR map keys are not in canonical order".into());
                        }
                    }
                    prev = Some((key_bytes.len(), key_bytes));
                    let name = match key {
                        Value::Text(s) => s,
                        _ => return Err("CBOR map keys must be text".into()),
                    };
                    if map.contains_key(&name) {
                        return Err(format!("duplicate CBOR key {name}"));
                    }
                    map.insert(name, self.read()?);
                }
                Ok(Value::Map(map))
            }
            7 => match info {
                20 => Ok(Value::Bool(false)),
                21 => Ok(Value::Bool(true)),
                22 => Ok(Value::Null),
                _ => Err(format!("unsupported simple value {info}")),
            },
            _ => Err(format!("unsupported major type {major}")),
        }
    }
}

pub fn decode(bytes: &[u8]) -> Result<Value, String> {
    let mut r = Reader { buf: bytes, off: 0 };
    let v = r.read()?;
    if r.off != bytes.len() {
        return Err("trailing bytes after CBOR value".into());
    }
    Ok(v)
}
