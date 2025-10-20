#![allow(unused)]
use skrillax_serde::{ByteSize, Deserialize, Serialize};

struct Unrelated;

// This should fail because `Unrelated` is not supported by the derive macros
#[derive(Serialize, Deserialize, ByteSize)]
struct UnsupportedType {
    unrelated: Unrelated,
}

fn main() {}
