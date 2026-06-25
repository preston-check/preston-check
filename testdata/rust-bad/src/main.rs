// P-17/P-505: thread_rng — cryptographically weak PRNG
use rand::{thread_rng, Rng};
// P-503: md5 is a weak/broken cryptographic hash crate
use md5;

// P-500: .unwrap() in non-test production code
fn get_config(key: &str) -> String {
    std::env::var(key).unwrap()
}

// P-505: session_id token generated with thread_rng — matches
// "(token|secret|key|nonce|session_id).*thread_rng" pattern
fn generate_session_id() -> u64 {
    let session_id: u64 = thread_rng().gen();
    session_id
}

// P-502: unsafe block in production code
fn write_raw(ptr: *mut u8, val: u8) {
    unsafe {
        *ptr = val;
    }
}

// P-500: .expect() is also flagged
fn load_key(path: &str) -> Vec<u8> {
    std::fs::read(path).expect("key file must exist")
}

fn main() {
    let _hash = md5::compute(b"hello");
}
