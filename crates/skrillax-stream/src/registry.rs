use crate::stream::{DynamicPacket, InStreamError, OutStreamError};
use skrillax_packet::{AsPacket, OutgoingPacket, Packet, TryFromPacket};
use skrillax_serde::SerdeContext;
use std::collections::HashMap;

#[derive(Clone)]
pub struct PacketRegistry {
    encoders:
        HashMap<u16, fn(DynamicPacket, &SerdeContext) -> Result<OutgoingPacket, OutStreamError>>,
    decoders:
        HashMap<u16, fn(&[u8], &SerdeContext) -> Result<(usize, DynamicPacket), InStreamError>>,
}

impl PacketRegistry {
    pub fn builder() -> PacketRegistryBuilder {
        PacketRegistryBuilder {
            encoders: Default::default(),
            decoders: Default::default(),
        }
    }

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
    pub fn register_incoming<T: Packet + TryFromPacket + Send + 'static>(mut self) -> Self {
        if self.decoders.contains_key(&T::ID) {
            panic!("Opcode should not be registered twice");
        }
        self.decoders.insert(T::ID, decode_fn::<T>);
        self
    }

    pub fn register_outgoing<T: Packet + AsPacket + Send + 'static>(mut self) -> Self {
        if self.encoders.contains_key(&T::ID) {
            panic!("Opcode should not be registered twice");
        }

        self.encoders.insert(T::ID, encode_fn::<T>);
        self
    }

    pub fn register<T: Packet + AsPacket + TryFromPacket + Send + 'static>(mut self) -> Self {
        if self.decoders.contains_key(&T::ID) || self.encoders.contains_key(&T::ID) {
            panic!("Opcode should not be registered twice");
        }

        self.decoders.insert(T::ID, decode_fn::<T>);
        self.encoders.insert(T::ID, encode_fn::<T>);
        self
    }

    pub fn build(self) -> PacketRegistry {
        PacketRegistry {
            decoders: self.decoders,
            encoders: self.encoders,
        }
    }
}
