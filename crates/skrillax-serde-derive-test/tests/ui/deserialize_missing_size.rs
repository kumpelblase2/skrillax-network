#![allow(unused)]
use skrillax_serde::Deserialize;

// This should fail because enums require a size attribute for deserialization
#[derive(Deserialize)]
enum MissingSizeEnum {
    A,
    B(u8),
    C { value: u16 },
}

fn main() {}
