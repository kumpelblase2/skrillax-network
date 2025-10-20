//!

use crate::stream::{DynamicPacket, InStreamError, OutStreamError};
use skrillax_packet::{AsPacket, OutgoingPacket, Packet, TryFromPacket};
use skrillax_serde::SerdeContext;
use std::collections::HashMap;

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
/// let registry = PacketRegistry::builder().register::<MyPacket>().build();
///
/// registry
///     .encode(0x01, MyPacket.into(), &SerdeContext::default())
///     .unwrap();
/// # }
/// ```
#[derive(Clone)]
pub struct PacketRegistry {
    encoders:
        HashMap<u16, fn(DynamicPacket, &SerdeContext) -> Result<OutgoingPacket, OutStreamError>>,
    decoders:
        HashMap<u16, fn(&[u8], &SerdeContext) -> Result<(usize, DynamicPacket), InStreamError>>,
}

impl PacketRegistry {
    /// Creates a build for the registry, where new packets can be registered.
    pub fn builder() -> PacketRegistryBuilder {
        PacketRegistryBuilder {
            encoders: Default::default(),
            decoders: Default::default(),
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
        if let Some(decoder) = self.decoders.get(&opcode) {
            decoder(data, context)
        } else {
            Err(InStreamError::UnmatchedOpcode(opcode))
        }
    }

    /// Tries to encode the given packet as provided by the encoders in the
    /// registry. Will fail if no encode is present for the opcode in the
    /// registry. Returns the serialized data from the packet.
    pub fn encode(
        &self,
        opcode: u16,
        packet: DynamicPacket,
        context: &SerdeContext,
    ) -> Result<OutgoingPacket, OutStreamError> {
        if let Some(encoder) = self.encoders.get(&opcode) {
            encoder(packet, context)
        } else {
            Err(OutStreamError::UnknownOpcode(opcode))
        }
    }
}

/// Builder for [PacketRegistry].
///
/// This builder can be used to build up the necessary encoders/decoders to be
/// present in the packet registry. This can be done through
/// [PacketRegistryBuilder::register], which is a shorthand for
/// [PacketRegistryBuilder::register_incoming] and
/// [PacketRegistryBuilder::register_outgoing]. It is expected that the
/// registration is done statically. As a result, any errors here are _panics_,
/// specifically registering an opcode multiple times. As there can only be one
/// encoder/decoder per opcode, registering an opcode twice is considered an
/// error.
pub struct PacketRegistryBuilder {
    encoders:
        HashMap<u16, fn(DynamicPacket, &SerdeContext) -> Result<OutgoingPacket, OutStreamError>>,
    decoders:
        HashMap<u16, fn(&[u8], &SerdeContext) -> Result<(usize, DynamicPacket), InStreamError>>,
}

fn decode_fn<T: TryFromPacket + Send + 'static>(
    bytes: &[u8],
    context: &SerdeContext,
) -> Result<(usize, DynamicPacket), InStreamError> {
    let (consumed, read) = T::try_deserialize(bytes, context)?;
    Ok((consumed, DynamicPacket(Box::new(read))))
}

fn encode_fn<T: AsPacket + Send + 'static>(
    input: DynamicPacket,
    context: &SerdeContext,
) -> Result<OutgoingPacket, OutStreamError> {
    let casted = input
        .as_packet::<T>()
        .expect("Type should match generic type parameter");
    Ok(casted.as_packet(context))
}

impl PacketRegistryBuilder {
    /// Registers a decoder for the given packet.
    ///
    /// A decoder allows deserialization of an incoming packet. Currently, this
    /// just forwards to the packet decoding routine, which is expected to
    /// exist, given that a packet must implement [TryFromPacket].
    pub fn register_incoming<T: Packet + TryFromPacket + Send + 'static>(mut self) -> Self {
        if self.decoders.contains_key(&T::ID) {
            panic!("Opcode should not be registered twice");
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
        if self.encoders.contains_key(&T::ID) {
            panic!("Opcode should not be registered twice");
        }

        self.encoders.insert(T::ID, encode_fn::<T>);
        self
    }

    /// Registers both an encoder and a decoder at the same time.
    ///
    /// See [PacketRegistryBuilder::register_outgoing] &
    /// [PacketRegistryBuilder::register_incoming].
    pub fn register<T: Packet + AsPacket + TryFromPacket + Send + 'static>(mut self) -> Self {
        if self.decoders.contains_key(&T::ID) || self.encoders.contains_key(&T::ID) {
            panic!("Opcode should not be registered twice");
        }

        self.decoders.insert(T::ID, decode_fn::<T>);
        self.encoders.insert(T::ID, encode_fn::<T>);
        self
    }

    /// Builds the registry from the currently registered packets.
    pub fn build(self) -> PacketRegistry {
        PacketRegistry {
            decoders: self.decoders,
            encoders: self.encoders,
        }
    }
}
