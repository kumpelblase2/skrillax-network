#![allow(unused)]
use skrillax_serde::Deserialize;

#[derive(Deserialize)]
struct LaterFieldCondition {
    #[silkroad(when = "enabled")]
    value: Option<u8>,
    enabled: bool,
}

fn main() {}
