#![allow(unused)]
use skrillax_serde::Deserialize;

// This should fail because we're using an invalid attribute combination
#[derive(Deserialize)]
struct InvalidDeserialize {
    // Using a deserialize-specific attribute that doesn't exist
    #[silkroad(invalid_attribute)]
    field: u32,
}

fn main() {}
