//! Provides a macro to create 'protocols'.
//!
//! This expected to be used for the [skrillax_stream] crate.
//!
//! A protocol defines a set of opcodes and their respective structures. It is
//! essentially a mapping of `opcode -> struct`. To encourage more static
//! dispatch and better developer ergonomics, we want to provide a nice way of
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
        $(<$packet as $crate::__internal::Packet>::ID == $opcodeVar)||+
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
/// A protocol always has a name and may contain packets and/or other
/// protocols. This protocol will then be represented as an enum, where
/// each of the packets/protocols is its own variant. With this enum,
/// all the necessary traits for usage with [skrillax_stream] will then
/// be implemented. In particular, the generated enum will
/// implement the following traits:
/// - [InputProtocol](skrillax_stream::InputProtocol)
/// - [OutputProtocol](skrillax_stream::OutputProtocol)
/// - [From], to create the protocol from a variant value
/// - [TryFrom], to extract a variant value from the protocol
///
/// The basic macro invocation looks like this:
/// ```text
/// define_protocol! { MyProtocolName =>
///     MyPacket,
///     MyOtherPacket
///     +
///     MyProtocol
/// }
/// ```
/// This assumes `MyPacket` & `MyOtherPacket` derive
/// [skrillax_packet::Packet] and `MyProtocol` has also been created
/// using `define_protocol!`.
///
/// (!) One limitation of `define_protocol!` is, because it always provides
/// an implementation for
/// [InputProtocol](skrillax_stream::InputProtocol) &
/// [OutputProtocol](skrillax_stream::OutputProtocol), it requires all
/// packets _and_ protocols to be both `Serialize` & `Deserialize`. For
/// some packets, that may not be possible, for example, when there's a
/// zero-length optional field. Any protocols those packets are included
/// would also automatically not be both `Serialize` and `Deserialize` and
/// could thus also not be used.
#[macro_export]
macro_rules! define_protocol {
    ($name:ident => $($enumValue:ident),*) => {
        define_protocol! {
            $name => $($enumValue),* +
        }
    };
    ($name:ident => $($enumValue:ident),* + $($innerProto:ident),*) => {
        $crate::define_protocol_enum! { $name =>
            $($enumValue),* + $($innerProto),*
        }

        $crate::define_input_protocol! { $name =>
            $($enumValue),* + $($innerProto),*
        }

        $crate::define_output_protocol! { $name =>
            $($enumValue),* + $($innerProto),*
        }
    };
}

/// Defines an "outbound" protocol, i.e., a protocol we only care about
/// sending out to another party.
#[macro_export]
macro_rules! define_outbound_protocol {
    ($name:ident => $($enumValue:ident),*) => {
        define_outbound_protocol! {
            $name => $($enumValue),* +
        }
    };
    ($name:ident => $($enumValue:ident),* + $($innerProto:ident),*) => {
        $crate::define_protocol_enum! { $name =>
            $($enumValue),* + $($innerProto),*
        }

        $crate::define_output_protocol! { $name =>
            $($enumValue),* + $($innerProto),*
        }
    }
}

/// Defines an "inbound" protocol, i.e., a protocol we only care about
/// receiving from another party.
#[macro_export]
macro_rules! define_inbound_protocol {
    ($name:ident => $($enumValue:ident),*) => {
        define_inbound_protocol! {
            $name => $($enumValue),* +
        }
    };
    ($name:ident => $($enumValue:ident),* + $($innerProto:ident),*) => {
        $crate::define_protocol_enum! { $name =>
            $($enumValue),* + $($innerProto),*
        }

        $crate::define_input_protocol! { $name =>
            $($enumValue),* + $($innerProto),*
        }
    }
}

#[doc(hidden)]
#[macro_export]
macro_rules! define_protocol_enum {
    ($name:ident => $($enumValue:ident),* + $($innerProto:ident),*) => {
        #[derive(Debug, Clone)]
        pub enum $name {
            $(
                $enumValue($enumValue),
            )*
            $(
                $innerProto($innerProto),
            )*
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
    }
}

#[doc(hidden)]
#[macro_export]
macro_rules! define_input_protocol {
    ($name:ident => $($enumValue:ident),* + $($innerProto:ident),*) => {
        impl $crate::__internal::InputProtocol for $name {
            type Proto = Box<$name>;

            fn create_from(opcode: u16, data: &[u8], ctx: skrillax_serde::SerdeContext) -> Result<(usize, Box<Self>), $crate::__internal::InStreamError> {
                match opcode {
                    $(
                        <$enumValue as $crate::__internal::Packet>::ID => {
                            let (consumed, res) = <$enumValue as $crate::__internal::TryFromPacket>::try_deserialize(data, ctx)?;
                            Ok((consumed, Box::new($name::$enumValue(res))))
                        }
                    )*
                    _ => {
                        #[allow(unused)]
                        use $crate::__internal::MatchOpcode;
                        $(
                        if $innerProto::has_opcode(opcode) {
                            let (consumed, res) = $innerProto::create_from(opcode, data, ctx)?;
                            return Ok((consumed, Box::new($name::$innerProto(*res))));
                        }
                        )*
                        Err($crate::__internal::InStreamError::UnmatchedOpcode(opcode))
                    }
                }
            }
        }

        impl $crate::__internal::MatchOpcode for $name {
            fn has_opcode(opcode: u16) -> bool {
                $crate::__match_packet_opcode!(opcode => $($enumValue),*) ||
                $crate::__match_protocol_opcode!(opcode => $($innerProto),*)
            }
        }
    }
}

#[doc(hidden)]
#[macro_export]
macro_rules! define_output_protocol {
    ($name:ident => $($enumValue:ident),* + $($innerProto:ident),*) => {
        impl $crate::__internal::AsPacket for $name {
            fn as_packet(&self, ctx: skrillax_serde::SerdeContext) -> $crate::__internal::OutgoingPacket {
                match self {
                    $(
                        $name::$enumValue(inner) => inner.as_packet(ctx),
                    )*
                    $(
                        $name::$innerProto(inner) => inner.as_packet(ctx),
                    )*
                }
            }
        }
    }
}

#[doc(hidden)]
pub mod __internal {
    pub use skrillax_packet::*;
    pub use skrillax_stream::stream::*;

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
    use skrillax_packet::{AsPacket, OutgoingPacket, Packet, TryFromPacket};
    use skrillax_serde::{ByteSize, Deserialize, SerdeContext, Serialize};
    use skrillax_stream::InputProtocol;

    #[derive(Packet, Deserialize, ByteSize, Serialize, Debug, Clone)]
    #[packet(opcode = 0x1000)]
    pub struct TestPacket {
        inner: String,
    }

    #[derive(Packet, Serialize, ByteSize, Debug, Clone)]
    #[packet(opcode = 0x1001)]
    pub struct OutboundPacketOnly {
        #[silkroad(size = 0)]
        opt: Option<String>,
    }

    define_protocol! { TestProtocol =>
        TestPacket
    }

    define_protocol! { WrapperProtocol =>
        +
        TestProtocol
    }

    define_outbound_protocol! { OutboundProto =>
        OutboundPacketOnly
    }

    #[test]
    fn test_protocol() {
        TestProtocol::create_from(0x1000, &[0x00, 0x00], SerdeContext::default()).unwrap();
        WrapperProtocol::create_from(0x1000, &[0x00, 0x00], SerdeContext::default()).unwrap();
    }

    #[test]
    fn test_convert() {
        let (_, packet) =
            TestPacket::try_deserialize(&[0x00, 0x00], SerdeContext::default()).unwrap();
        let proto: TestProtocol = packet.into();
        let wrapper: WrapperProtocol = proto.into();
        let inner_proto: TestProtocol = wrapper.try_into().expect("Should get back inner");
        let _: TestPacket = inner_proto.try_into().expect("Should get back packet");
    }

    #[test]
    fn test_outbound_only() {
        let packet = OutboundPacketOnly { opt: None };
        let proto: OutboundProto = packet.into();
        let data: OutgoingPacket = proto.as_packet(SerdeContext::default());

        assert!(matches!(
            data,
            OutgoingPacket::Simple { opcode: 0x1001, .. }
        ))
    }
}
