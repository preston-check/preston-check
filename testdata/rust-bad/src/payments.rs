use serde::Deserialize;

// P-501: raw arithmetic on financial field — potential integer overflow
fn calculate_fee(amount: i64) -> i64 {
    amount * 2
}

fn add_surcharge(balance: i64, fee: i64) -> i64 {
    balance + fee
}

// P-504: serde deserialization with no size/depth limits configured
#[derive(Deserialize)]
struct Payment {
    // P-501: f64 for a price field also triggers the money-arithmetic check
    // via the broader pattern when arithmetic is applied
    amount: i64,
    price: f64,
}

fn parse_payment(data: &[u8]) -> Payment {
    serde_json::from_slice(data).unwrap()
}
