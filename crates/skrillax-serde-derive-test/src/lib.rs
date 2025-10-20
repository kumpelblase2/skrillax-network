#![cfg(test)]

use bytes::BytesMut;
use skrillax_serde::{ByteSize, Deserialize, SerdeContext, Serialize};

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
enum EnumWithNamedVec {
    #[silkroad(value = 1)]
    Variant { inner: Vec<Test> },
}

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
        let mut out_buff = bytes::BytesMut::with_capacity($size);
        start.write_to(&mut out_buff, &SerdeContext::default());
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
    test_serialize_deserialize!(
        EnumWithNamedVec,
        EnumWithNamedVec::Variant {
            inner: vec![Test {
                one: 0,
                two: 0,
                three: 0,
                four: 0,
            }],
        },
        17
    );
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
    let bytes = bytes::Bytes::from_static(&[3u8]);
    assert!(matches!(
        TestEnum::try_from(bytes),
        Err(skrillax_serde::SerializationError::UnknownVariation(
            3, "TestEnum"
        ))
    ));
}

#[derive(Serialize, ByteSize, Deserialize, Eq, PartialEq, Debug)]
#[silkroad(size = 2)]
enum TaggedEnum {
    #[silkroad(when = "tag < 100")]
    A {
        #[silkroad(tag)]
        value: u16,
    },
    #[silkroad(when = "tag >= 100 && tag <= 300")]
    B {
        #[silkroad(tag)]
        value: u16,
    },
    #[silkroad(when = "tag >= 301")]
    C {
        #[silkroad(tag)]
        value: u16,
    },
}

#[test]
pub fn test_tagged_enum() {
    let bytes = bytes::Bytes::from_static(&[50u8, 0u8]);
    let result = TaggedEnum::try_from(bytes);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), TaggedEnum::A { value: 50 });

    let bytes = bytes::Bytes::from_static(&[150u8, 0u8]);
    let result = TaggedEnum::try_from(bytes);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), TaggedEnum::B { value: 150 });

    let bytes = bytes::Bytes::from_static(&[0xD8, 0x4]);
    let result = TaggedEnum::try_from(bytes);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), TaggedEnum::C { value: 1240 });
}

#[test]
pub fn test_tagged_enum_serialization() {
    let a_enum = TaggedEnum::A { value: 50 };
    let mut output = BytesMut::with_capacity(a_enum.byte_size());
    a_enum.write_to(&mut output, &SerdeContext::default());
    let serialized = output.freeze();
    assert_eq!(serialized.as_ref(), &[50u8, 0u8]);

    let b_enum = TaggedEnum::B { value: 150 };
    let mut output = BytesMut::with_capacity(b_enum.byte_size());
    b_enum.write_to(&mut output, &SerdeContext::default());
    let serialized = output.freeze();
    assert_eq!(serialized.as_ref(), &[150u8, 0u8]);

    let c_enum = TaggedEnum::C { value: 1240 };
    let mut output = BytesMut::with_capacity(c_enum.byte_size());
    c_enum.write_to(&mut output, &SerdeContext::default());
    let serialized = output.freeze();
    assert_eq!(serialized.as_ref(), &[0xD8, 0x4]);
}

#[derive(Serialize, ByteSize, Deserialize, Eq, PartialEq, Debug)]
#[silkroad(size = 2)]
enum TaggedTupleEnum {
    #[silkroad(when = "tag < 100")]
    A(#[silkroad(tag)] u16),
    #[silkroad(when = "tag >= 100 && tag <= 300")]
    B(#[silkroad(tag)] u16),
    #[silkroad(when = "tag >= 301")]
    C(#[silkroad(tag)] u16),
}

#[test]
pub fn test_tagged_tuple_enum() {
    let bytes = bytes::Bytes::from_static(&[50u8, 0u8]);
    let result = TaggedTupleEnum::try_from(bytes);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), TaggedTupleEnum::A(50));

    let bytes = bytes::Bytes::from_static(&[150u8, 0u8]);
    let result = TaggedTupleEnum::try_from(bytes);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), TaggedTupleEnum::B(150));

    let bytes = bytes::Bytes::from_static(&[0xD8, 0x4]);
    let result = TaggedTupleEnum::try_from(bytes);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), TaggedTupleEnum::C(1240));
}

#[test]
pub fn test_tagged_tuple_enum_serialization() {
    let a_enum = TaggedTupleEnum::A(50);
    let mut output = BytesMut::with_capacity(a_enum.byte_size());
    a_enum.write_to(&mut output, &SerdeContext::default());
    let serialized = output.freeze();
    assert_eq!(serialized.as_ref(), &[50u8, 0u8]);

    let b_enum = TaggedTupleEnum::B(150);
    let mut output = BytesMut::with_capacity(b_enum.byte_size());
    b_enum.write_to(&mut output, &SerdeContext::default());
    let serialized = output.freeze();
    assert_eq!(serialized.as_ref(), &[150u8, 0u8]);

    let c_enum = TaggedTupleEnum::C(1240);
    let mut output = BytesMut::with_capacity(c_enum.byte_size());
    c_enum.write_to(&mut output, &SerdeContext::default());
    let serialized = output.freeze();
    assert_eq!(serialized.as_ref(), &[0xD8, 0x4]);
}
