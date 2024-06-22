//! Provides a macro to create 'protocols'.
//!
//! This expected to be used for the [skrillax_stream] crate.
//!
//! A protocol defines a set of opcodes and their respective structures. It is
//! essentially a mapping of `opcode -> struct`. To encourage more static
//! dispatch and better developer ergonimics, we want to provide a nice way of
//! constructing these mappings. Otherwise, this would become quite tedious.
//! Additionally, this also generates some convenience functions to
//! automatically move between different protocols that are related.
//!
//! The macro to use is the [define_protocol!] macro - any other macro exports
//! are just helper macros and should be ignored.

#[doc(hidden)]
#[macro_export]
macro_rules! __match_packet_opcode {
    ($opcodeVar:ident =>) => {false};
    ($opcodeVar:ident => $($packet:ident),+) => {
        $($packet::ID == $opcodeVar)||+
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __match_protocol_opcode {
    ($opcodeVar:ident =>) => {false};
    ($opcodeVar:ident => $($proto:ident),+) => {
        $($proto::has_opcode($opcodeVar))||+
    };
}

/// Defines a protocol from a list of packets and/or other protocols.
///
/// A protocol always has a name and may contain packets and/or other protocols.
/// This protocol will then be represented as an enum, where each of the
/// packets/protocols is its own variant. With this enum, all the necessary
/// traits for usage with [skrillax_stream] will then be implemented. In
/// particular, the following traits will be implement by the generated enum:
/// - [InputProtocol](skrillax_stream::InputProtocol)
/// - [OutputProtocol](skrillax_stream::OutputProtocol)
/// - [From], to create the protocol from a variant value
/// - [TryFrom], to extract a variant value from the protocol
///
/// The basic macro invokation looks like this:
/// ```text
/// define_protocol! { MyProtocolName =>
///     MyPacket,
///     MyOtherPacket
///     +
///     MyProtocol
/// }
/// ```
/// This assumes `MyPacket` & `MyOtherPacket` derive [skrillax_packet::Packet]
/// and `MyProtocol` has also been created using `define_protocol!`.
///
/// (!) One limitation of `define_protocol!` is, because it always provides an
/// implementation for [InputProtocol](skrillax_stream::InputProtocol) &
/// [OutputProtocol](skrillax_stream::OutputProtocol), it requires all packets
/// _and_ protocols to be both `Serialize` & `Derserialize`. For some packets,
/// that may not be possible, for example when there's a zero-length optional
/// field. Any protocols those packets are included would also automatically not
/// be both serialize and deserialize and could thus also not be used.
#[macro_export]
macro_rules! define_protocol {
    ($name:ident => $($enumValue:ident),*) => {
        define_protocol! {
            $name => $($enumValue),* +
        }
    };
    ($name:ident => $($enumValue:ident),* + $($innerProto:ident),*) => {
        #[derive(Debug)]
        pub enum $name {
            $(
                $enumValue($enumValue),
            )*
            $(
                $innerProto($innerProto),
            )*
        }

        impl skrillax_stream::InputProtocol for $name {
            fn create_from(opcode: u16, data: &[u8]) -> Result<(usize, Self), skrillax_stream::stream::InStreamError> {
                match opcode {
                    $(
                        $enumValue::ID => {
                            let (consumed, res) = $enumValue::try_deserialize(data)?;
                            Ok((consumed, $name::$enumValue(res)))
                        }
                    )*
                    _ => {
                        #[allow(unused)]
                        use $crate::__internal::MatchOpcode;
                        $(
                        if $innerProto::has_opcode(opcode) {
                            let (consumed, res) = $innerProto::create_from(opcode, data)?;
                            return Ok((consumed, $name::$innerProto(res)));
                        }
                        )*
                        Err(skrillax_stream::stream::InStreamError::UnmatchedOpcode(opcode))
                    }
                }

            }
        }

        impl skrillax_stream::OutputProtocol for $name {
            fn to_packet(&self) -> skrillax_packet::OutgoingPacket {
                match self {
                    $(
                        $name::$enumValue(inner) => skrillax_packet::TryIntoPacket::serialize(inner),
                    )*
                    $(
                        $name::$innerProto(inner) => inner.to_packet(),
                    )*
                }
            }
        }

        impl $crate::__internal::MatchOpcode for $name {
            fn has_opcode(opcode: u16) -> bool {
                $crate::__match_packet_opcode!(opcode => $($enumValue),*) ||
                $crate::__match_protocol_opcode!(opcode => $($innerProto),*)
            }
        }

        $(
            impl From<$enumValue> for $name {
                fn from(value: $enumValue) -> Self {
                    $name::$enumValue(value)
                }
            }
        )*

        $(
            impl From<$innerProto> for $name {
                fn from(value: $innerProto) -> Self {
                    $name::$innerProto(value)
                }
            }
        )*

        $(
            impl TryFrom<$name> for $enumValue {
                type Error = $name;
                fn try_from(value: $name) -> Result<Self, Self::Error> {
                    #[allow(unreachable_patterns)]
                    match value {
                        $name::$enumValue(inner) => Ok(inner),
                        _ => Err(value)
                    }
                }
            }
        )*

        $(
            impl TryFrom<$name> for $innerProto {
                type Error = $name;
                fn try_from(value: $name) -> Result<Self, Self::Error> {
                    #[allow(unreachable_patterns)]
                    match value {
                        $name::$innerProto(inner) => Ok(inner),
                        _ => Err(value)
                    }
                }
            }
        )*
    };
}

#[doc(hidden)]
pub mod __internal {
    use skrillax_packet::Packet;

    pub trait MatchOpcode {
        fn has_opcode(opcode: u16) -> bool;
    }

    impl<T: Packet> MatchOpcode for T {
        fn has_opcode(opcode: u16) -> bool {
            Self::ID == opcode
        }
    }
}

#[cfg(test)]
mod test {
    use skrillax_packet::{Packet, TryFromPacket};
    use skrillax_serde::{ByteSize, Deserialize, Serialize};
    use skrillax_stream::InputProtocol;

    #[derive(Packet, Deserialize, ByteSize, Serialize, Debug)]
    #[packet(opcode = 0x1000)]
    pub struct TestPacket {
        inner: String,
    }

    define_protocol! { TestProtocol =>
        TestPacket
    }

    define_protocol! { WrapperProtocol =>
        +
        TestProtocol
    }

    #[test]
    fn test_protocol() {
        TestProtocol::create_from(0x1000, &[0x00, 0x00]).unwrap();
        WrapperProtocol::create_from(0x1000, &[0x00, 0x00]).unwrap();
    }

    #[test]
    fn test_convert() {
        let (_, packet) = TestPacket::try_deserialize(&[0x00, 0x00]).unwrap();
        let proto: TestProtocol = packet.into();
        let wrapper: WrapperProtocol = proto.into();
        let inner_proto: TestProtocol = wrapper.try_into().expect("Should get back inner");
        let _: TestPacket = inner_proto.try_into().expect("Should get back packet");
    }
}
