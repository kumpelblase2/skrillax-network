#![allow(unused)]

use chrono::{DateTime, Utc};
use skrillax_serde::{ByteSize, Deserialize, Serialize};

#[derive(Serialize, Deserialize, ByteSize)]
struct BareDateTime {
    value: DateTime<Utc>,
}

fn main() {}
