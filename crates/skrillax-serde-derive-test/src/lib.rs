#![cfg(test)]

use bytes::{Bytes, BytesMut};
use skrillax_serde::{ByteSize, Deserialize, Serialize};

#[derive(Serialize, ByteSize, Deserialize, Eq, PartialEq, Debug)]
struct Test {
    one: u8,
    two: u16,
    three: u32,
    four: u64,
}

#[derive(Serialize, ByteSize, Deserialize, Eq, PartialEq, Debug)]
enum TestEnum {
    #[silkroad(value = 1)]
    A,
    #[silkroad(value = 2)]
    B(u8),
}

#[derive(Serialize, ByteSize, Deserialize, Eq, PartialEq, Debug)]
struct Wrapped {
    inner: Test,
    inner2: TestEnum,
}

#[derive(Serialize, ByteSize, Deserialize, Eq, PartialEq, Debug)]
struct NormalString(String);

#[derive(Serialize, ByteSize, Deserialize, Eq, PartialEq, Debug)]
struct DoubleString(#[silkroad(size = 2)] String);

#[derive(Serialize, ByteSize, Deserialize, Eq, PartialEq, Debug)]
struct WithVec(Vec<u32>);

#[derive(Serialize, ByteSize, Deserialize, Eq, PartialEq, Debug)]
struct TestCond {
    cond: u8,
    unrelated: String,
    #[silkroad(when = "cond == 1")]
    value: Option<u8>,
}

#[derive(Serialize, ByteSize, Deserialize, Eq, PartialEq, Debug)]
#[silkroad(size = 2)]
enum LargerEnum {
    #[silkroad(value = 1)]
    A,
    #[silkroad(value = 0xFFF)]
    B,
}

macro_rules! test_serialize_deserialize {
    ($ty:ty, $init:expr, $size:literal) => {
        let start = $init;
        assert_eq!($size, start.byte_size());
        let mut out_buff = BytesMut::with_capacity($size);
        start.write_to(&mut out_buff);
        let output = out_buff.freeze();
        let result = <$ty>::try_from(output);
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(start, result);
    };
}

#[test]
pub fn test_simple() {
    test_serialize_deserialize!(
        Test,
        Test {
            one: 1,
            two: 2,
            three: 3,
            four: 4,
        },
        15
    );
}

#[test]
pub fn test_enum() {
    test_serialize_deserialize!(TestEnum, TestEnum::A, 1);
    test_serialize_deserialize!(TestEnum, TestEnum::B(1), 2);
}

#[test]
pub fn test_wrapped() {
    test_serialize_deserialize!(
        Wrapped,
        Wrapped {
            inner: Test {
                one: 1,
                two: 2,
                three: 3,
                four: 4,
            },
            inner2: TestEnum::B(3),
        },
        17
    );
}

#[test]
pub fn test_strings() {
    test_serialize_deserialize!(NormalString, NormalString("123".to_string()), 5);
    test_serialize_deserialize!(DoubleString, DoubleString("456".to_string()), 8);
}

#[test]
pub fn test_vec() {
    test_serialize_deserialize!(WithVec, WithVec(vec![123, 456, 789]), 13);
}

#[test]
pub fn test_cond() {
    test_serialize_deserialize!(
        TestCond,
        TestCond {
            cond: 1,
            unrelated: String::from("abc"),
            value: Some(1),
        },
        7
    );

    test_serialize_deserialize!(
        TestCond,
        TestCond {
            cond: 0,
            unrelated: String::from("abc"),
            value: None,
        },
        6
    );
}

#[test]
pub fn test_large_enum() {
    test_serialize_deserialize!(LargerEnum, LargerEnum::B, 2);
}

#[test]
pub fn test_unknown_variant() {
    let bytes = Bytes::from_static(&[3u8]);
    assert!(matches!(
        TestEnum::try_from(bytes),
        Err(skrillax_serde::SerializationError::UnknownVariation(
            3, "TestEnum"
        ))
    ));
}
