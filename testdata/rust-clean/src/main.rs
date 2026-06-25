// P-17/P-505 PASS: OsRng — cryptographically secure random source
use rand::rngs::OsRng;
use rand::RngCore;
// P-503 PASS: sha2 is the recommended hash family
use sha2::{Digest, Sha256};
// P-52 PASS: subtle::ConstantTimeEq for timing-safe comparison
use subtle::ConstantTimeEq;

// P-500 PASS: Result propagation with ? instead of unwrap/expect
fn get_config(key: &str) -> Result<String, std::env::VarError> {
    std::env::var(key)
}

// P-505 PASS: OsRng for token/key generation (cryptographically secure)
fn generate_session_id() -> Vec<u8> {
    let mut bytes = vec![0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

// P-52 PASS: constant-time equality check via subtle crate
fn verify_token(token: &[u8], expected: &[u8]) -> bool {
    token.ct_eq(expected).into()
}

// P-503 PASS: strong hash used for digests
fn hash_data(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

// P-502 PASS: no unsafe blocks
fn safe_write(buf: &mut [u8], val: u8, idx: usize) {
    if idx < buf.len() {
        buf[idx] = val;
    }
}

fn main() {}
