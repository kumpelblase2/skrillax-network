#![allow(unused)]
use skrillax_serde::ByteSize;

#[derive(ByteSize)]
struct CollectionWidth {
    #[silkroad(size = 3)]
    values: Vec<u8>,
}

#[derive(ByteSize)]
#[silkroad(size = 3)]
enum EnumWidth {
    #[silkroad(value = 1)]
    Value,
}

#[derive(ByteSize)]
struct OptionWidth {
    #[silkroad(size = 3)]
    value: Option<u8>,
}

#[derive(ByteSize)]
struct StringWidth {
    #[silkroad(size = 4)]
    value: String,
}

#[derive(ByteSize)]
struct UnknownFraming {
    #[silkroad(list_type = "mystery")]
    values: Vec<u8>,
}

fn main() {}
