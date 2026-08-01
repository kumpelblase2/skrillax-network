#![allow(unused)]
use skrillax_serde::ByteSize;

#[derive(ByteSize)]
#[silkroad(size = 1)]
enum MultipleTags {
    #[silkroad(when = "tag == 1")]
    Value(#[silkroad(tag)] u8, #[silkroad(tag)] u8),
}

#[derive(ByteSize)]
#[silkroad(size = 2)]
enum WrongTagType {
    #[silkroad(when = "tag == 1")]
    Value(#[silkroad(tag)] u8),
}

mod protocol {
    #[allow(non_camel_case_types)]
    pub struct u8;
}

#[derive(ByteSize)]
enum QualifiedLookalikeTag {
    #[silkroad(when = "tag == 1")]
    Value(#[silkroad(tag)] protocol::u8),
}

#[derive(ByteSize)]
enum FixedAndPredicateOnVariant {
    #[silkroad(value = 1, when = "tag == 1")]
    Value,
}

#[derive(ByteSize)]
enum FixedOverflow {
    #[silkroad(value = 256)]
    Value,
}

#[derive(ByteSize)]
enum DuplicateFixedValues {
    #[silkroad(value = 1)]
    First,
    #[silkroad(value = 1)]
    Second,
}

#[derive(ByteSize)]
enum MixedSelectors {
    #[silkroad(value = 1)]
    Fixed,
    #[silkroad(when = "tag == 2")]
    Predicate(#[silkroad(tag)] u8),
}

#[derive(ByteSize)]
#[silkroad(size = 0)]
enum ZeroWidthMissingWhen {
    Value,
}

#[derive(ByteSize)]
#[silkroad(size = 0)]
enum ZeroWidthValue {
    #[silkroad(value = 1)]
    Value,
}

#[derive(ByteSize)]
#[silkroad(size = 0)]
enum ZeroWidthTag {
    #[silkroad(when = "true")]
    Value(#[silkroad(tag)] u8),
}

#[derive(ByteSize)]
#[silkroad(size = 0)]
enum ZeroWidthTagExpression {
    #[silkroad(when = "tag == 0")]
    Value,
}

fn main() {}
