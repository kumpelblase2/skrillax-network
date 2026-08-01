#![allow(unused)]
use skrillax_serde::ByteSize;

#[derive(ByteSize)]
struct MissingCalculation {
    #[silkroad(list_type = "calculated")]
    values: Vec<u8>,
}

#[derive(ByteSize)]
struct CalculationWithoutFraming {
    #[silkroad(calculate = "count")]
    values: Vec<u8>,
    count: u8,
}

#[derive(ByteSize)]
struct CalculatedWithSize {
    count: u8,
    #[silkroad(list_type = "calculated", calculate = "count", size = 1)]
    values: Vec<u8>,
}

#[derive(ByteSize)]
struct ConflictingScalarCalculation {
    #[silkroad(calculate = "1", size = 1)]
    value: u8,
}

fn main() {}
