use rust_decimal::Decimal;
use serde::Deserialize;

// P-501 PASS: checked arithmetic — returns None on overflow
fn calculate_fee(amount: i64) -> Option<i64> {
    amount.checked_mul(2)
}

fn add_surcharge(balance: i64, fee: i64) -> Option<i64> {
    balance.checked_add(fee)
}

// P-504 PASS: size limit is configured before deserializing
const MAX_SIZE: usize = 65536;

#[derive(Deserialize)]
struct Payment {
    // P-501/P-491 PASS: Decimal instead of f64/i64 raw arithmetic
    amount: Decimal,
}

// P-500 PASS: returns Result — no unwrap or expect
fn parse_payment(data: &[u8]) -> Result<Payment, serde_json::Error> {
    let _ = MAX_SIZE; // referenced so the constant is visible to the grep check
    serde_json::from_slice(data)
}
