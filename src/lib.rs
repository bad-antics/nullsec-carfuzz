/// NullSec CarFuzz — Automotive Protocol Fuzzer
/// Core library: protocol definitions, frame builders, mutation engine
pub mod protocols;

use rand::Rng;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use std::fmt;

/// A raw CAN frame (11-bit or 29-bit arbitration ID, up to 8 bytes data).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanFrame {
    pub arb_id: u32,
    pub extended: bool,
    pub data: Vec<u8>,
}

impl CanFrame {
    pub fn new(arb_id: u32, data: Vec<u8>) -> Self {
        Self { arb_id, extended: arb_id > 0x7FF, data }
    }

    pub fn random(rng: &mut impl Rng) -> Self {
        let arb_id: u32 = rng.gen_range(0..0x800);
        let len: usize = rng.gen_range(1..=8);
        let data: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
        Self::new(arb_id, data)
    }
}

impl fmt::Display for CanFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{:03X}] {:?}", self.arb_id, self.data)
    }
}

/// Fuzzing result for a single frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzResult {
    pub frame: CanFrame,
    pub anomaly: Option<String>,
    pub timestamp_ms: u64,
}

/// Mutation strategies.
#[derive(Debug, Clone, PartialEq)]
pub enum FuzzMode {
    Random,
    Dict(Vec<Vec<u8>>),
    Mutate(Vec<Vec<u8>>),
    Protocol,
    Discovery { start: u32, end: u32 },
    Bruteforce { target: u32, service: u8 },
    Extract { target: u32, start: u32, end: u32 },
}

/// Mutate a byte vector with bit flips, byte substitution, boundary values.
pub fn mutate(data: &[u8], rng: &mut impl Rng) -> Vec<u8> {
    let mut out = data.to_vec();
    if out.is_empty() {
        return out;
    }
    match rng.gen_range(0u8..4) {
        0 => {
            // bit flip
            let idx = rng.gen_range(0..out.len());
            let bit = rng.gen_range(0u8..8);
            out[idx] ^= 1 << bit;
        }
        1 => {
            // byte replacement
            let idx = rng.gen_range(0..out.len());
            out[idx] = rng.gen();
        }
        2 => {
            // boundary insert
            let idx = rng.gen_range(0..out.len());
            out[idx] = *[0x00u8, 0xFF, 0x7F, 0x80, 0x01, 0xFE].choose(rng).unwrap();
        }
        _ => {
            // truncate or extend
            if out.len() > 1 && rng.gen_bool(0.5) {
                out.pop();
            } else if out.len() < 8 {
                out.push(rng.gen());
            }
        }
    }
    out
}

/// Detect anomalies in a response frame.
pub fn detect_anomaly(request: &CanFrame, response: &CanFrame) -> Option<String> {
    // NRC 0x78 (response pending) or negative response service 0x7F
    if response.data.first() == Some(&0x7F) {
        let nrc = response.data.get(2).copied().unwrap_or(0);
        return Some(format!("UDS Negative Response NRC=0x{:02X}", nrc));
    }
    // Unexpected silence or short data
    if response.data.is_empty() {
        return Some("Empty response — possible ECU hang".into());
    }
    // Timeout indicator (data = [0xDE, 0xAD])
    if response.data == [0xDE, 0xAD] {
        return Some(format!(
            "Timeout after request to 0x{:03X}",
            request.arb_id
        ));
    }
    None
}
