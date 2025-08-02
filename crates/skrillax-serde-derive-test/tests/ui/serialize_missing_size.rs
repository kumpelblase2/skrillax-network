#![allow(unused)]
use skrillax_serde::{ByteSize, Serialize};

// This should fail because enums require a size attribute
#[derive(Serialize, ByteSize)]
enum MissingSizeEnum {
    A,
    B(u8),
    C { value: u16 },
}

fn main() {}
