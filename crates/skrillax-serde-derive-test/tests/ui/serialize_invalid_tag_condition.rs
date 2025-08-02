#![allow(unused)]
use skrillax_serde::{ByteSize, Serialize};

// This should fail because the tag condition is invalid (missing tag field)
#[derive(Serialize, ByteSize)]
#[silkroad(size = 2)]
enum InvalidTagConditionEnum {
    #[silkroad(when = "tag < 100")]
    A,
    #[silkroad(when = "tag >= 100")]
    B,
}

fn main() {}
