use bytes::{Buf, BufMut, Bytes, BytesMut};
use skrillax_codec::{FrameError, SilkroadFrame};
use skrillax_security::EstablishedSecurity;
use skrillax_serde::{ByteSize, Deserialize, SerializationError, Serialize};
use std::cmp::{max, min};
use thiserror::Error;

#[cfg(feature = "derive")]
pub use skrillax_packet_derive::Packet;

#[derive(Error, Debug)]
pub enum PacketError {
    #[error("A frame level error occurred when sending a packet: {0}")]
    FrameError(#[from] FrameError),
    #[error("The packet expected the opcode {expected} but got {received}")]
    MismatchedOpcode { expected: u16, received: u16 },
    #[error("The packet cannot be serialized")]
    NonSerializable,
    #[error("An error occurred while trying to (de)serialize the packet")]
    SerializationError(#[from] SerializationError),
    #[error("An encrypted packet was either attempted to be sent or received, but no security has been established yet")]
    MissingSecurity,
}

/// Defines associated constants with this packet, which can be used to
/// turn this struct into a packet. If this struct also implements
/// [ByteSize] and [Serialize], it will automatically gain [TryIntoPacket].
/// If it implements [Deserialize], it will automatically gain [TryFromPacket].
/// This can automatically be derived with the `derive` feature.
pub trait Packet: Sized {
    const ID: u16;
    const NAME: &'static str;
    const MASSIVE: bool;
    const ENCRYPTED: bool;
}

/// An incoming packet that has already gone through re-framing of massive packets
/// or decryption. It is essentially a collection of bytes for a given opcode,
/// nothing more.
#[derive(Eq, PartialEq)]
pub struct IncomingPacket {
    opcode: u16,
    data: Bytes,
}

impl IncomingPacket {
    pub fn new(opcode: u16, data: Bytes) -> Self {
        Self { opcode, data }
    }

    pub fn consume(self) -> (u16, Bytes) {
        (self.opcode, self.data)
    }

    pub fn opcode(&self) -> u16 {
        self.opcode
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

/// A packet on its way out, before having been turned into a frame. In
/// turn, we still need to know what kind of frame it should end up as.
/// Generally, one outgoing packet will result in a single frame, but
/// multiple packets can be combined to a massive packet. This will
/// span multiple frames, including an additional header.
#[derive(Eq, PartialEq, Debug)]
pub enum OutgoingPacket {
    /// A packet that shall be encrypted before being sent out.
    Encrypted { opcode: u16, data: Bytes },
    /// A basic packet that doesn't need any additional transformation.
    Simple { opcode: u16, data: Bytes },
    /// A massive packet containing multiple inner packets that should be sent together.
    Massive { opcode: u16, packets: Vec<Bytes> },
}

/// Defines _something_ that can be turned into a packet, which then can be sent out.
/// Generally, this will be either a single struct representing a single operation, or
/// a 'protocol' enum containing a list of multiple packets. For convenience, this
/// trait has a blanket implementation for everything which already implements
/// [Packet] and [Deserialize].
///
/// The analog is [TryFromPacket].
pub trait TryIntoPacket {
    fn serialize(&self) -> OutgoingPacket;
}

/// Defines _something_ that can be created from a packet, after it has been received.
/// Once a re-framing, decryption and other parts have completed, we want to turn the
/// contained data into a usable structure.
///
/// The analog is [TryIntoPacket].
pub trait TryFromPacket: Sized {
    /// Tries to create `Self` from the given opcode and the data. The opcode may not
    /// be necessary to create `Self`, if `Self` is a single packet. `data` _may_
    /// contain more data than necessary, for example if we were inside a massive
    /// frame. Thus, we need to return the amount of consumed bytes such that the
    /// remainder may be used to create more elements of `Self` if the caller wants to.
    fn try_deserialize(opcode: u16, data: &[u8]) -> Result<(usize, Self), PacketError>;
}

impl<T> TryFromPacket for T
where
    T: Packet + Deserialize,
{
    fn try_deserialize(opcode: u16, data: &[u8]) -> Result<(usize, Self), PacketError> {
        if opcode != Self::ID {
            return Err(PacketError::MismatchedOpcode {
                expected: Self::ID,
                received: opcode,
            });
        }

        let mut reader = data.reader();
        let read = Self::read_from(&mut reader)?;
        let consumed = data.len() - reader.into_inner().len();
        Ok((consumed, read))
    }
}

impl<T> TryIntoPacket for T
where
    T: Packet + Serialize + ByteSize,
{
    fn serialize(&self) -> OutgoingPacket {
        let mut buffer = BytesMut::with_capacity(self.byte_size());
        self.write_to(&mut buffer);
        if Self::MASSIVE {
            let mut data = buffer.freeze();
            let required_packets = max(data.len() / 0xFFFF, 1);

            let mut result = Vec::with_capacity(required_packets);
            for _ in 0..required_packets {
                result.push(data.split_to(min(0xFFFF, data.len())));
            }

            OutgoingPacket::Massive {
                opcode: Self::ID,
                packets: result,
            }
        } else if Self::ENCRYPTED {
            OutgoingPacket::Encrypted {
                opcode: Self::ID,
                data: buffer.freeze(),
            }
        } else {
            OutgoingPacket::Simple {
                opcode: Self::ID,
                data: buffer.freeze(),
            }
        }
    }
}

/// A procedure to turn an element into actual [SilkroadFrame]s, which can
/// be written by the codec onto the wire.
pub trait AsFrames {
    /// Creates a collection of [SilkroadFrame] that represent the given
    /// structure. This is mostly a 1-to-1 mapping between output packet
    /// kinds and their respective frames. Since frames may be encrypted,
    /// this can optionally receive the security to be used. If no
    /// security is passed, but an encrypted packet is requested, this
    /// may error.
    fn as_frames(
        &self,
        security: Option<&EstablishedSecurity>,
    ) -> Result<Vec<SilkroadFrame>, PacketError>;
}

impl AsFrames for OutgoingPacket {
    fn as_frames(
        &self,
        security: Option<&EstablishedSecurity>,
    ) -> Result<Vec<SilkroadFrame>, PacketError> {
        match self {
            OutgoingPacket::Encrypted { opcode, data } => {
                let Some(security) = security else {
                    return Err(PacketError::MissingSecurity);
                };
                let mut new_buffer = BytesMut::with_capacity(data.len() + 4);
                new_buffer.put_u16(*opcode);
                new_buffer.put_u8(0);
                new_buffer.put_u8(0);
                new_buffer.copy_from_slice(data);

                let encrypted_data = security
                    .encrypt(&new_buffer.freeze())
                    .expect("Should be able to encrypt");
                Ok(vec![SilkroadFrame::Encrypted {
                    content_size: data.len(),
                    encrypted_data,
                }])
            }
            OutgoingPacket::Simple { opcode, data } => Ok(vec![SilkroadFrame::Packet {
                count: 0,
                crc: 0,
                opcode: *opcode,
                data: data.clone(),
            }]),
            OutgoingPacket::Massive { opcode, packets } => {
                let mut frames = Vec::with_capacity(1 + packets.len());

                frames.push(SilkroadFrame::MassiveHeader {
                    count: 0,
                    crc: 0,
                    contained_opcode: *opcode,
                    contained_count: packets.len() as u16,
                });

                for packet in packets.iter() {
                    frames.push(SilkroadFrame::MassiveContainer {
                        count: 0,
                        crc: 0,
                        inner: packet.clone(),
                    });
                }

                Ok(frames)
            }
        }
    }
}

#[derive(Error, Debug)]
pub enum ReframingError {
    #[error("We don't have enough packets to complete the re-framing")]
    Incomplete(Option<usize>),
    #[error("Cannot handle a massive container without a header")]
    StrayMassiveContainer,
    #[error("Found a mixture of massive and non-massive frames")]
    MixedFrames,
    #[error("Encountered an encrypted packet but was not provided a security setup")]
    MissingSecurity,
    #[error("The decryption of an encrypted packet did not yield a simple frame")]
    InvalidEncryptedData,
}

pub trait FromFrames {
    fn from_frames(
        frames: &[SilkroadFrame],
        security: Option<&EstablishedSecurity>,
    ) -> Result<IncomingPacket, ReframingError>;
}

struct MassiveInfo {
    opcode: u16,
    remaining: u16,
}

impl FromFrames for IncomingPacket {
    fn from_frames(
        frames: &[SilkroadFrame],
        security: Option<&EstablishedSecurity>,
    ) -> Result<IncomingPacket, ReframingError> {
        let mut massive_information: Option<MassiveInfo> = None;
        let mut massive_buffer: Option<BytesMut> = None;
        for (i, frame) in frames.iter().enumerate() {
            match frame {
                SilkroadFrame::Packet { .. } | SilkroadFrame::Encrypted { .. }
                    if massive_information.is_some() =>
                {
                    return Err(ReframingError::MixedFrames);
                }
                SilkroadFrame::Packet { opcode, data, .. } => {
                    return Ok(IncomingPacket::new(*opcode, data.clone()))
                }
                SilkroadFrame::Encrypted {
                    encrypted_data,
                    content_size,
                } => {
                    let Some(encryption) = &security else {
                        return Err(ReframingError::MissingSecurity);
                    };

                    let decrypted = encryption
                        .decrypt(&encrypted_data)
                        .expect("Should be able to decrypt bytes");

                    let frame = SilkroadFrame::from_data(&decrypted[0..(*content_size)]);
                    return match frame {
                        SilkroadFrame::Packet { opcode, data, .. } => {
                            Ok(IncomingPacket::new(opcode, data))
                        }
                        _ => Err(ReframingError::InvalidEncryptedData),
                    };
                }
                SilkroadFrame::MassiveHeader {
                    contained_count,
                    contained_opcode,
                    ..
                } => {
                    let required_frames = *contained_count as usize;
                    let remaining_frames = frames.len() - (i + 1);
                    if required_frames > remaining_frames {
                        return Err(ReframingError::Incomplete(Some(required_frames)));
                    }

                    massive_information = Some(MassiveInfo {
                        opcode: *contained_opcode,
                        remaining: *contained_count,
                    });
                }
                SilkroadFrame::MassiveContainer { inner, .. } => {
                    if let Some(mut massive) = massive_information.take() {
                        let mut current_buffer = massive_buffer.take().unwrap_or_default();
                        current_buffer.extend_from_slice(&inner);

                        massive.remaining = massive.remaining.saturating_sub(1);
                        if massive.remaining == 0 {
                            return Ok(IncomingPacket::new(
                                massive.opcode,
                                current_buffer.freeze(),
                            ));
                        } else {
                            massive_buffer = Some(current_buffer);
                            massive_information = Some(massive);
                        }
                    } else {
                        return Err(ReframingError::StrayMassiveContainer);
                    }
                }
            }
        }

        Err(ReframingError::Incomplete(
            massive_information.map(|massive| massive.remaining as usize),
        ))
    }
}
