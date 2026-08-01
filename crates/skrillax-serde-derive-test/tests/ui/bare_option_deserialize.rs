#![allow(unused)]
use skrillax_serde::Deserialize;

#[derive(Deserialize)]
struct BareOption {
    #[silkroad(size = 0)]
    value: Option<u8>,
}

fn main() {}
