#![allow(unused)]
use skrillax_serde::{ByteSize, Deserialize, Serialize};

// This should fail because the field attribute is invalid
#[derive(Serialize, Deserialize, ByteSize)]
struct InvalidFieldAttribute {
    // This is not allowed: it should not be possible to use a `tag` attribute on a field in a
    // struct
    #[silkroad(tag)]
    value: u16,
}

fn main() {}
