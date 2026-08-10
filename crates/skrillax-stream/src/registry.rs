use crate::stream::{DynamicPacket, InStreamError, OutStreamError};
use skrillax_packet::{AsPacket, OutgoingPacket, Packet, TryFromPacket};
use skrillax_serde::SerdeContext;
use std::collections::HashMap;
use thiserror::Error;

type EncoderFn = fn(DynamicPacket, &SerdeContext) -> Result<OutgoingPacket, OutStreamError>;
type DecoderFn = fn(u16, &[u8], &SerdeContext) -> Result<(usize, DynamicPacket), InStreamError>;

/// A registry for packets.
///
/// To facilitate dynamic parsing and serializing of packets, a registry is
/// used. This registry contains the information about how packets are read
/// given their opcode. This is done through [PacketRegistry::decode], and for
/// write it's [PacketRegistry::encode]. The registry is read-only and has to
/// be constructed through [PacketRegistryBuilder] / [PacketRegistry::builder].
///
/// ```
/// # use skrillax_stream::registry::PacketRegistry;
/// # use skrillax_stream::stream::DynamicPacket;
/// # use skrillax_packet::Packet;
/// # use skrillax_serde::{Serialize, Deserialize, ByteSize, SerdeContext};
///
/// #[derive(Packet, Serialize, ByteSize, Deserialize)]
/// #[packet(opcode = 0x01)]
/// struct MyPacket;
///
/// # fn main() {
/// let registry = PacketRegistry::builder()
///     .register::<MyPacket>()
///     .build()
///     .unwrap();
///
/// registry
///     .encode(MyPacket.into(), &SerdeContext::default())
///     .unwrap();
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct PacketRegistry {
    encoders: HashMap<u16, EncoderFn>,
    decoders: HashMap<u16, DecoderFn>,
}

impl PacketRegistry {
    /// Creates a build for the registry, where new packets can be registered.
    pub fn builder() -> PacketRegistryBuilder {
        PacketRegistryBuilder {
            encoders: Default::default(),
            decoders: Default::default(),
            error: None,
        }
    }

    /// Tries to decode the given bytes as a packet as provided by the decoders
    /// in the registry. Will fail if no decode is present for the opcode in
    /// the registry. Returns the parsed packet as well as the amount of
    /// consumed bytes.
    pub fn decode(
        &self,
        opcode: u16,
        data: &[u8],
        context: &SerdeContext,
    ) -> Result<(usize, DynamicPacket), InStreamError> {
        let Some(decoder) = self.decoders.get(&opcode) else {
            return Err(InStreamError::UnmatchedOpcode(opcode));
        };

        let (consumed, packet) = decoder(opcode, data, context)?;
        if consumed > data.len() || (consumed == 0 && !data.is_empty()) {
            return Err(InStreamError::InvalidPacketConsumption {
                opcode,
                consumed,
                available: data.len(),
            });
        }
        Ok((consumed, packet))
    }

    /// Converts the registered dynamic packet into an [OutgoingPacket].
    ///
    /// Returns [OutStreamError::UnknownOpcode] when no encoder is registered.
    /// Packet construction and serialization failures are propagated as
    /// [OutStreamError::PacketError].
    pub fn encode(
        &self,
        packet: DynamicPacket,
        context: &SerdeContext,
    ) -> Result<OutgoingPacket, OutStreamError> {
        let opcode = packet.opcode();
        if let Some(encoder) = self.encoders.get(&opcode) {
            encoder(packet, context)
        } else {
            Err(OutStreamError::UnknownOpcode(opcode))
        }
    }
}

/// An error encountered while building a packet registry.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RegistryError {
    #[error("Incoming opcode {opcode:#06x} was registered more than once by {packet}")]
    DuplicateIncomingOpcode { opcode: u16, packet: &'static str },
    #[error("Outgoing opcode {opcode:#06x} was registered more than once by {packet}")]
    DuplicateOutgoingOpcode { opcode: u16, packet: &'static str },
}

/// Builder for [PacketRegistry].
///
/// This builder can be used to build up the necessary encoders/decoders to be
/// present in the packet registry. This can be done through
/// [PacketRegistryBuilder::register], which is a shorthand for
/// [PacketRegistryBuilder::register_incoming] and
/// [PacketRegistryBuilder::register_outgoing]. Duplicate opcodes are retained
/// as a [RegistryError] and returned by [PacketRegistryBuilder::build].
pub struct PacketRegistryBuilder {
    encoders: HashMap<u16, EncoderFn>,
    decoders: HashMap<u16, DecoderFn>,
    error: Option<RegistryError>,
}

fn decode_fn<T: TryFromPacket + Send + 'static>(
    opcode: u16,
    bytes: &[u8],
    context: &SerdeContext,
) -> Result<(usize, DynamicPacket), InStreamError> {
    let (consumed, read) = T::try_deserialize(bytes, context)?;
    Ok((consumed, DynamicPacket::from_value(opcode, read)))
}

fn encode_fn<T: AsPacket + Send + 'static>(
    input: DynamicPacket,
    context: &SerdeContext,
) -> Result<OutgoingPacket, OutStreamError> {
    let casted = input.try_as_packet::<T>()?;
    Ok(casted.as_packet(context)?)
}

impl PacketRegistryBuilder {
    /// Registers a decoder for the given packet.
    ///
    /// A decoder allows deserialization of an incoming packet. Currently, this
    /// just forwards to the packet decoding routine, which is expected to
    /// exist, given that a packet must implement [TryFromPacket].
    pub fn register_incoming<T: Packet + TryFromPacket + Send + 'static>(mut self) -> Self {
        if self.error.is_some() {
            return self;
        }
        if self.decoders.contains_key(&T::ID) {
            self.error = Some(RegistryError::DuplicateIncomingOpcode {
                opcode: T::ID,
                packet: T::NAME,
            });
            return self;
        }
        self.decoders.insert(T::ID, decode_fn::<T>);
        self
    }

    /// Registers an encoder for the given packet.
    ///
    /// An encoder allows serialization of an outgoing packet. Currently, this
    /// just forwards to the packet encoding routine, which is expected to
    /// exist, given that a packet must implement [AsPacket].
    pub fn register_outgoing<T: Packet + AsPacket + Send + 'static>(mut self) -> Self {
        if self.error.is_some() {
            return self;
        }
        if self.encoders.contains_key(&T::ID) {
            self.error = Some(RegistryError::DuplicateOutgoingOpcode {
                opcode: T::ID,
                packet: T::NAME,
            });
            return self;
        }

        self.encoders.insert(T::ID, encode_fn::<T>);
        self
    }

    /// Registers both an encoder and a decoder at the same time.
    ///
    /// See [PacketRegistryBuilder::register_outgoing] &
    /// [PacketRegistryBuilder::register_incoming].
    pub fn register<T: Packet + AsPacket + TryFromPacket + Send + 'static>(mut self) -> Self {
        if self.error.is_some() {
            return self;
        }
        if self.decoders.contains_key(&T::ID) {
            self.error = Some(RegistryError::DuplicateIncomingOpcode {
                opcode: T::ID,
                packet: T::NAME,
            });
            return self;
        }
        if self.encoders.contains_key(&T::ID) {
            self.error = Some(RegistryError::DuplicateOutgoingOpcode {
                opcode: T::ID,
                packet: T::NAME,
            });
            return self;
        }

        self.decoders.insert(T::ID, decode_fn::<T>);
        self.encoders.insert(T::ID, encode_fn::<T>);
        self
    }

    /// Builds the registry, returning any duplicate registration encountered.
    pub fn build(self) -> Result<PacketRegistry, RegistryError> {
        if let Some(error) = self.error {
            return Err(error);
        }
        Ok(PacketRegistry {
            decoders: self.decoders,
            encoders: self.encoders,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use skrillax_packet::PacketError;
    use std::any::type_name;

    struct Expected;

    impl Packet for Expected {
        const ID: u16 = 0x4242;
        const NAME: &'static str = "Expected";
        const MASSIVE: bool = false;
        const ENCRYPTED: bool = false;
    }

    impl AsPacket for Expected {
        fn as_packet(&self, _ctx: &SerdeContext) -> Result<OutgoingPacket, PacketError> {
            Ok(OutgoingPacket::Simple {
                opcode: Self::ID,
                data: Bytes::new(),
            })
        }
    }

    impl TryFromPacket for Expected {
        fn try_deserialize(
            _data: &[u8],
            _ctx: &SerdeContext,
        ) -> Result<(usize, Self), PacketError> {
            Ok((0, Self))
        }
    }

    struct Actual;

    #[test]
    fn erased_packet_type_mismatch_is_an_error() {
        let registry = PacketRegistry::builder()
            .register_outgoing::<Expected>()
            .build()
            .expect("unique packet registration should succeed");
        let packet = DynamicPacket::from_value(Expected::ID, Actual);

        let error = registry
            .encode(packet, &SerdeContext::default())
            .expect_err("the erased type must match the registered packet");

        assert!(matches!(
            error,
            OutStreamError::DynamicPacketType(ref error)
                if error.opcode == Expected::ID
                    && error.expected == type_name::<Expected>()
                    && error.actual == type_name::<Actual>()
        ));
    }

    #[test]
    fn boxed_dynamic_packet_constructor_preserves_the_inner_type() {
        let registry = PacketRegistry::builder()
            .register_outgoing::<Expected>()
            .build()
            .expect("unique packet registration should succeed");
        let inner: Box<dyn std::any::Any + Send> = Box::new(Expected);
        let packet = DynamicPacket::new(Expected::ID, inner);

        let encoded = registry
            .encode(packet, &SerdeContext::default())
            .expect("the boxed constructor should erase only the inner packet");

        assert!(matches!(
            encoded,
            OutgoingPacket::Simple {
                opcode: Expected::ID,
                ..
            }
        ));
    }

    #[test]
    fn duplicate_registration_is_an_error() {
        let error = PacketRegistry::builder()
            .register_outgoing::<Expected>()
            .register_outgoing::<Expected>()
            .build()
            .expect_err("an outgoing opcode cannot be registered twice");

        assert_eq!(
            error,
            RegistryError::DuplicateOutgoingOpcode {
                opcode: Expected::ID,
                packet: Expected::NAME,
            }
        );
    }

    struct InvalidConsumption;

    impl Packet for InvalidConsumption {
        const ID: u16 = 0x4343;
        const NAME: &'static str = "InvalidConsumption";
        const MASSIVE: bool = false;
        const ENCRYPTED: bool = false;
    }

    impl TryFromPacket for InvalidConsumption {
        fn try_deserialize(data: &[u8], _ctx: &SerdeContext) -> Result<(usize, Self), PacketError> {
            Ok((data.len() + 1, Self))
        }
    }

    #[test]
    fn invalid_decoder_consumption_is_an_error() {
        let registry = PacketRegistry::builder()
            .register_incoming::<InvalidConsumption>()
            .build()
            .expect("unique packet registration should succeed");
        let data = [1, 2, 3];

        let error = registry
            .decode(InvalidConsumption::ID, &data, &SerdeContext::default())
            .expect_err("a decoder cannot consume beyond its input");

        assert!(matches!(
            error,
            InStreamError::InvalidPacketConsumption {
                opcode: InvalidConsumption::ID,
                consumed: 4,
                available: 3,
            }
        ));
    }
}
