#[macro_export]
macro_rules! __match_packet_opcode {
    ($opcodeVar:ident =>) => {false};
    ($opcodeVar:ident => $($packet:ident),+) => {
        $($packet::ID == $opcodeVar)||+
    };
}

#[macro_export]
macro_rules! __match_protocol_opcode {
    ($opcodeVar:ident =>) => {false};
    ($opcodeVar:ident => $($proto:ident),+) => {
        $($proto::has_opcode($opcodeVar))||+
    };
}

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
