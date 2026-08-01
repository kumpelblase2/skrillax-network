#![allow(unused)]
use skrillax_serde::{ByteSize, Deserialize, Serialize};

#[derive(ByteSize)]
#[silkroad(size = 1)]
struct SizedStruct(u8);

#[derive(ByteSize)]
struct NestedCollection(Vec<Vec<u8>>);

#[derive(ByteSize)]
struct NestedOption(Option<Option<u8>>);

#[derive(ByteSize)]
struct CollectionOfOptions(Vec<Option<u8>>);

#[derive(ByteSize)]
struct OptionOfCollection(Option<Vec<u8>>);

#[derive(Serialize)]
union SerializeUnion {
    value: u8,
}

#[derive(Deserialize)]
union DeserializeUnion {
    value: u8,
}

#[derive(ByteSize)]
union ByteSizeUnion {
    value: u8,
}

fn main() {}
