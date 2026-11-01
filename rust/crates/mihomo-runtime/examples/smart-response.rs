//! Compare response decisions with the frozen Go reference in Docker.
use mihomo_runtime::smart::response::{classify, Headers};
use serde::Deserialize;
#[derive(Deserialize)]
struct Case {
    status: u16,
    headers: Headers,
    body: String,
    now: u64,
}
fn main() {
    let input = std::env::args().nth(1).expect("fixtures JSON path");
    let cases: Vec<Case> = serde_json::from_slice(&std::fs::read(input).unwrap()).unwrap();
    let verdicts = cases
        .iter()
        .map(|case| classify(case.status, &case.headers, case.body.as_bytes(), case.now))
        .collect::<Vec<_>>();
    println!("{}", serde_json::to_string(&verdicts).unwrap());
}
