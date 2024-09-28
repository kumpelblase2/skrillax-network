//! This crate mainly provides one trait: [Packet]. While you can implement it
//! yourself, you might as well use the derive macro to derive it instead (which
//! requires the `derive` feature).
//! ```
//! # #[cfg(feature = "derive")]
//! # {
//! # use skrillax_packet_derive::Packet;
//! #[derive(Packet)]
//! #[packet(opcode = 0x5001)]
//! struct MyPacket {
//!     content: String,
//! }
//! # }
//! ```
//!
//! The rest of this crate focuses around converting a [Packet] into a
//! [SilkroadFrame], or vice-versa. This currently takes a small detour through
//! using either an [IncomingPacket] or [OutgoingPacket], depending on the
//! direction. This is done because we often first need to apply some kind of
//! transformation to the frames, before we can easily turn them into structs
//! representing the packet. This would include combining multiple massive
//! frames into one large buffer as well as decrypting the content of frames to
//! figure out their opcodes. Thus, the chain goes something like this, in a
//! simplified way. To turn a packet into frames:
//! `myPacket.serialize().as_frames(context)` To turn frames into a packet:
//! `IncomingPacket::from_frames(frames, context).try_into_packet::<MyPacket>()`
//!
//! However, this does require a bit more than just the [Packet] implementation.
//! Either you need to implement the [TryFromPacket] and [AsPacket] traits
//! yourself, or you need to implement/derive [skrillax_serde::Serialize](https://docs.rs/skrillax-serde/latest/skrillax_serde/trait.Serialize.html),
//! [skrillax_serde::Deserialize](https://docs.rs/skrillax-serde/latest/skrillax_serde/trait.Deserialize.html),
//! and [skrillax_serde::ByteSize](https://docs.rs/skrillax-serde/latest/skrillax_serde/trait.ByteSize.html)
//! from the [skrillax_serde](https://docs.rs/skrillax-serde/latest/skrillax_serde/) crate.
//! With these, [AsPacket] and [TryFromPacket] are automatically
//! implemented for you. They are necessary to serialize/deserialize the packet
//! content into bytes, which can be sent using the frames.
//!
//! ## Derive
//!
//! The derive macro currently has three options, for all the options the trait
//! provides:
//! ```
//! # #[cfg(feature = "derive")]
//! # {
//! # use skrillax_packet_derive::Packet;
//! #[derive(Packet)]
//! #[packet(opcode = 0x5001, encrypted = true, massive = false)]
//! struct MyPacket {
//!     content: String,
//! }
//! # }
//! ```
//! `encrypted` and `massive` are `false` by default and are mutually exclusive.
//! `opcode` is a required attribute, this is also considered the `ID` of a
//! packet. The name is automatically considered to be the structure's name.

use bytes::{BufMut, Bytes, BytesMut};
use skrillax_codec::SilkroadFrame;
use skrillax_security::handshake::CheckBytesInitialization;
use skrillax_security::{Checksum, ChecksumBuilder, MessageCounter, SilkroadEncryption};
use std::sync::Mutex;
use thiserror::Error;

#[cfg(feature = "derive")]
pub use skrillax_packet_derive::Packet;
#[cfg(feature = "serde")]
use skrillax_serde::{ByteSize, Deserialize, SerializationError, Serialize};

#[derive(Error, Debug)]
pub enum PacketError {
    #[cfg(feature = "serde")]
    #[error("An error occurred while trying to (de)serialize the packet")]
    SerializationError(#[from] SerializationError),
    #[error(
        "An encrypted packet was either attempted to be sent or received, but no security has \
         been established yet"
    )]
    MissingSecurity,
}

/// Defines associated constants with this packet, which can be used to turn
/// this struct into a packet.
///
/// If this struct also implements [skrillax_serde::ByteSize](https://docs.rs/skrillax-serde/latest/skrillax_serde/trait.ByteSize.html)
/// and [skrillax_serde::Serialize](https://docs.rs/skrillax-serde/latest/skrillax_serde/trait.Serialize.html),
/// it will automatically gain [AsPacket]. If it implements
/// [skrillax_serde::Deserialize](https://docs.rs/skrillax-serde/latest/skrillax_serde/trait.Deserialize.html), it will automatically gain [TryFromPacket].
/// This can automatically be derived with the `derive` feature.
pub trait Packet {
    /// Defines the ID or OpCode of the packet.
    const ID: u16;
    /// Provides a more readable name for the given packet. This is usually just
    /// the struct name.
    const NAME: &'static str;
    /// Defines if this packet is a massive packet, and should thus use massive
    /// frames for transport.
    const MASSIVE: bool;
    /// Defines if this packet is an encrypted packet.
    const ENCRYPTED: bool;
}

/// An incoming packet that has already gone through re-framing of massive
/// packets or decryption. It is essentially a collection of bytes for a given
/// opcode, nothing more.
#[derive(Eq, PartialEq, Debug)]
pub struct IncomingPacket {
    opcode: u16,
    data: Bytes,
}

impl IncomingPacket {
    /// Creates a new packet given the opcode and contained data.
    pub fn new(opcode: u16, data: Bytes) -> Self {
        Self { opcode, data }
    }

    /// Consumes this packet, return the contained data.
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

/// A packet on its way out, before having been turned into a frame.
///
/// In turn, we still need to know what kind of frame it should end up as.
/// Generally, one outgoing packet will result in a single frame, but
/// multiple packets can be combined to a massive packet. This will
/// span multiple frames, including an additional header.
#[derive(Eq, PartialEq, Debug)]
pub enum OutgoingPacket {
    /// A packet that shall be encrypted before being sent out.
    Encrypted { opcode: u16, data: Bytes },
    /// A basic packet that doesn't need any additional transformation.
    Simple { opcode: u16, data: Bytes },
    /// A massive packet containing multiple inner packets that should be sent
    /// together.
    Massive { opcode: u16, packets: Vec<Bytes> },
}

/// Defines _something_ that can be turned into a packet, which then can be sent
/// out.
///
/// Generally, this will be either a single struct representing a single
/// operation, or a 'protocol' enum containing a list of multiple packets. For
/// convenience, this trait has a blanket implementation for everything which
/// already implements [Packet] and [Deserialize](https://docs.rs/skrillax-serde/latest/skrillax_serde/trait.Deserialize.html).
///
/// The analog is [TryFromPacket].
pub trait AsPacket {
    /// Serializes this structure into a packet that can be sent over the wire.
    fn as_packet(&self) -> OutgoingPacket;
}

impl<T: AsPacket> From<T> for OutgoingPacket {
    fn from(value: T) -> Self {
        value.as_packet()
    }
}

/// Defines _something_ that can be created from a packet, after it has been
/// received.
///
/// Once a re-framing, decryption and other parts have completed, we want to
/// turn the contained data into a usable structure.
///
/// The analog is [AsPacket].
pub trait TryFromPacket {
    /// Tries to create `Self` from the given data. Unlike [AsPacket], we
    /// do not deal with the opcode here. It is expected that we have
    /// already matched the opcode to `Self` and know it matches.
    ///
    /// `data` _may_ contain more data than necessary to form a single packet,
    /// for example if we were inside a massive frame. Thus, we need to
    /// return the amount of consumed bytes such that the remainder may be
    /// used to create more elements of `Self` if the caller wants to.
    fn try_deserialize(data: &[u8]) -> Result<(usize, Self), PacketError>
    where
        Self: Sized;
}

#[cfg(feature = "serde")]
impl<T> TryFromPacket for T
where
    T: Packet + Deserialize + Send + Sized,
{
    fn try_deserialize(data: &[u8]) -> Result<(usize, Self), PacketError> {
        use bytes::Buf;
        let mut reader = data.reader();
        let read = Self::read_from(&mut reader)?;
        let consumed = data.len() - reader.into_inner().len();
        Ok((consumed, read))
    }
}

#[cfg(feature = "serde")]
impl<T> AsPacket for [T]
where
    T: Packet + Serialize + ByteSize,
{
    fn as_packet(&self) -> OutgoingPacket {
        use std::cmp::{max, min};
        assert!(T::MASSIVE, "Can only transform massive packets");
        let total_size = self.iter().map(|p| p.byte_size()).sum();
        let mut buffer = BytesMut::with_capacity(total_size);
        for p in self {
            p.write_to(&mut buffer);
        }

        let mut data = buffer.freeze();
        let required_packets = max(data.len() / 0x7FFF, 1);

        let mut result = Vec::with_capacity(required_packets);
        for _ in 0..required_packets {
            result.push(data.split_to(min(0x7FFF, data.len())));
        }

        OutgoingPacket::Massive {
            opcode: T::ID,
            packets: result,
        }
    }
}

#[cfg(feature = "serde")]
impl<T> AsPacket for T
where
    T: Packet + Serialize + ByteSize,
{
    fn as_packet(&self) -> OutgoingPacket {
        use std::cmp::{max, min};

        let mut buffer = BytesMut::with_capacity(self.byte_size());
        self.write_to(&mut buffer);
        if Self::MASSIVE {
            let mut data = buffer.freeze();
            let required_packets = max(data.len() / 0x7FFF, 1);

            let mut result = Vec::with_capacity(required_packets);
            for _ in 0..required_packets {
                result.push(data.split_to(min(0x7FFF, data.len())));
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

#[derive(Error, Debug)]
pub enum FramingError {
    #[error("Tried to create an encrypted frame but no encrypted was set up")]
    MissingEncryption,
}

/// A procedure to turn an element into actual [SilkroadFrame]s,
/// which can be written by the codec onto the wire.
pub trait AsFrames {
    /// Creates a collection of [SilkroadFrame] that represent
    /// the given structure.
    ///
    /// This is mostly a 1-to-1 mapping between output packet
    /// kinds and their respective frames. Since frames may be encrypted,
    /// this can optionally receive the security to be used. If no
    /// security is passed, but an encrypted packet is requested, this
    /// may error.
    fn as_frames(&self, context: SecurityContext) -> Result<Vec<SilkroadFrame>, FramingError>;
}

impl AsFrames for OutgoingPacket {
    fn as_frames(&self, context: SecurityContext) -> Result<Vec<SilkroadFrame>, FramingError> {
        let count = context
            .checkers()
            .map(|check| check.generate_count_byte())
            .unwrap_or(0);

        match self {
            OutgoingPacket::Encrypted { opcode, data } => {
                let Some(encryption) = context.encryption() else {
                    return Err(FramingError::MissingEncryption);
                };
                let content_length = data.len() + 4;
                let length_with_padding = SilkroadEncryption::find_encrypted_length(content_length);
                let mut new_buffer = BytesMut::with_capacity(length_with_padding);
                new_buffer.put_u16_le(*opcode);
                new_buffer.put_u8(count);
                new_buffer.put_u8(0);
                new_buffer.put_slice(data);

                if let Some(mut checksum_builder) = context
                    .checkers()
                    .map(|checkers| checkers.checksum_builder())
                {
                    checksum_builder.update(&(data.len() as u16 | 0x8000).to_le_bytes());
                    checksum_builder.update(&new_buffer);
                    new_buffer[3] = checksum_builder.digest();
                }

                for _ in 0..(length_with_padding - content_length) {
                    new_buffer.put_u8(0);
                }

                encryption
                    .encrypt_mut(&mut new_buffer)
                    .expect("Should be able to encrypt");
                Ok(vec![SilkroadFrame::Encrypted {
                    content_size: data.len(),
                    encrypted_data: new_buffer.freeze(),
                }])
            },
            OutgoingPacket::Simple { opcode, data } => {
                let crc = if let Some(mut checksum_builder) = context
                    .checkers()
                    .map(|checkers| checkers.checksum_builder())
                {
                    checksum_builder.update(&(data.len() as u16).to_le_bytes());
                    checksum_builder.update(&opcode.to_le_bytes());
                    checksum_builder.update_byte(count);
                    checksum_builder.update_byte(0);
                    checksum_builder.update(data);
                    checksum_builder.digest()
                } else {
                    0
                };

                Ok(vec![SilkroadFrame::Packet {
                    count,
                    crc,
                    opcode: *opcode,
                    data: data.clone(),
                }])
            },
            OutgoingPacket::Massive { opcode, packets } => {
                let mut frames = Vec::with_capacity(1 + packets.len());

                let crc = if let Some(mut checksum_builder) = context
                    .checkers()
                    .map(|checkers| checkers.checksum_builder())
                {
                    checksum_builder.update(&5u16.to_le_bytes());
                    checksum_builder.update(&0x600Du16.to_le_bytes());
                    checksum_builder.update_byte(count);
                    checksum_builder.update_byte(0);
                    checksum_builder.update_byte(1);
                    checksum_builder.update(&opcode.to_le_bytes());
                    checksum_builder.update(&(packets.len() as u16).to_le_bytes());
                    checksum_builder.digest()
                } else {
                    0
                };

                frames.push(SilkroadFrame::MassiveHeader {
                    count,
                    crc,
                    contained_opcode: *opcode,
                    contained_count: packets.len() as u16,
                });

                for packet in packets.iter() {
                    let count = context
                        .checkers()
                        .map(|check| check.generate_count_byte())
                        .unwrap_or(0);

                    let crc = if let Some(mut checksum_builder) = context
                        .checkers()
                        .map(|checkers| checkers.checksum_builder())
                    {
                        checksum_builder.update(&((packet.len() + 1) as u16).to_le_bytes());
                        checksum_builder.update(&0x600Du16.to_le_bytes());
                        checksum_builder.update_byte(count);
                        checksum_builder.update_byte(0);
                        checksum_builder.update_byte(0);
                        checksum_builder.update(packet);
                        checksum_builder.digest()
                    } else {
                        0
                    };

                    frames.push(SilkroadFrame::MassiveContainer {
                        count,
                        crc,
                        inner: packet.clone(),
                    });
                }

                Ok(frames)
            },
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
    #[error("The CRC byte was {received} by we expected to to be {expected}")]
    CrcCheckFailed { expected: u8, received: u8 },
    #[error("The count byte was {received} by we expected to to be {expected}")]
    CounterCheckFailed { expected: u8, received: u8 },
}

/// Provides a way to turn [SilkroadFrame]s into an [IncomingPacket].
pub trait FromFrames {
    type Output;
    /// Try to turn _all_ frames into an incoming packet.
    ///
    /// This accepts a slice of frames, which is either a single packet frame
    /// (plain or encrypted), or multiple frames representing a massive
    /// packet. As such, this function does not return how many frames may
    /// have been consumed, as it is expected to have consumed all the given
    /// frames.
    ///
    /// It requires a security context such that it may validate and decrypt
    /// frames, when the need arises. If no security is provided but an
    /// encrypted frame is encountered, it will error.
    fn from_frames(
        frames: &[SilkroadFrame],
        security: SecurityContext,
    ) -> Result<Self::Output, ReframingError>;
}

struct MassiveInfo {
    opcode: u16,
    remaining: u16,
}

impl FromFrames for IncomingPacket {
    type Output = IncomingPacket;

    fn from_frames(
        frames: &[SilkroadFrame],
        security: SecurityContext,
    ) -> Result<Self, ReframingError> {
        let mut massive_information: Option<MassiveInfo> = None;
        let mut massive_buffer: Option<BytesMut> = None;
        for (i, frame) in frames.iter().enumerate() {
            match frame {
                SilkroadFrame::Packet { .. } | SilkroadFrame::Encrypted { .. }
                    if massive_information.is_some() =>
                {
                    return Err(ReframingError::MixedFrames);
                },
                SilkroadFrame::Packet {
                    opcode,
                    data,
                    count,
                    crc,
                } => {
                    if let Some(checkers) = security.checkers() {
                        let expected_count = checkers.generate_count_byte();
                        if *count != expected_count {
                            return Err(ReframingError::CounterCheckFailed {
                                expected: expected_count,
                                received: *count,
                            });
                        }

                        let mut checksum_builder = checkers.checksum_builder();
                        checksum_builder.update(&(data.len() as u16).to_le_bytes());
                        checksum_builder.update(&opcode.to_le_bytes());
                        checksum_builder.update_byte(*count);
                        checksum_builder.update_byte(0);
                        checksum_builder.update(data);
                        let expected_crc = checksum_builder.digest();
                        if *crc != expected_crc {
                            return Err(ReframingError::CrcCheckFailed {
                                expected: expected_crc,
                                received: *crc,
                            });
                        }
                    }

                    return Ok(IncomingPacket::new(*opcode, data.clone()));
                },
                SilkroadFrame::Encrypted {
                    encrypted_data,
                    content_size,
                } => {
                    let Some(encryption) = security.encryption() else {
                        return Err(ReframingError::MissingSecurity);
                    };

                    let decrypted = encryption
                        .decrypt(encrypted_data)
                        .expect("Should be able to decrypt bytes");

                    let frame = SilkroadFrame::from_data(&decrypted[0..(*content_size + 4)]);
                    return match frame {
                        SilkroadFrame::Packet {
                            opcode,
                            data,
                            count,
                            crc,
                        } => {
                            if let Some(checkers) = security.checkers() {
                                let expected_count = checkers.generate_count_byte();
                                if count != expected_count {
                                    return Err(ReframingError::CounterCheckFailed {
                                        expected: expected_count,
                                        received: count,
                                    });
                                }

                                let mut checksum_builder = checkers.checksum_builder();
                                checksum_builder
                                    .update(&(data.len() as u16 | 0x8000).to_le_bytes());
                                checksum_builder.update(&opcode.to_le_bytes());
                                checksum_builder.update_byte(count);
                                checksum_builder.update_byte(0);
                                checksum_builder.update(&data);
                                let expected_crc = checksum_builder.digest();
                                if crc != expected_crc {
                                    return Err(ReframingError::CrcCheckFailed {
                                        expected: expected_crc,
                                        received: crc,
                                    });
                                }
                            }
                            Ok(IncomingPacket::new(opcode, data))
                        },
                        _ => Err(ReframingError::InvalidEncryptedData),
                    };
                },
                SilkroadFrame::MassiveHeader {
                    contained_count,
                    contained_opcode,
                    count,
                    crc,
                } => {
                    let required_frames = *contained_count as usize;
                    let remaining_frames = frames.len() - (i + 1);
                    if required_frames > remaining_frames {
                        return Err(ReframingError::Incomplete(Some(required_frames)));
                    }

                    if let Some(checkers) = security.checkers() {
                        let expected_count = checkers.generate_count_byte();
                        if *count != expected_count {
                            return Err(ReframingError::CounterCheckFailed {
                                expected: expected_count,
                                received: *count,
                            });
                        }

                        let mut checksum_builder = checkers.checksum_builder();
                        checksum_builder.update(&5u16.to_le_bytes());
                        checksum_builder.update(&0x600Du16.to_le_bytes());
                        checksum_builder.update_byte(*count);
                        checksum_builder.update_byte(0);
                        checksum_builder.update_byte(1);
                        checksum_builder.update(&contained_opcode.to_le_bytes());
                        checksum_builder.update(&contained_count.to_le_bytes());
                        let expected_crc = checksum_builder.digest();
                        if *crc != expected_crc {
                            return Err(ReframingError::CrcCheckFailed {
                                expected: expected_crc,
                                received: *crc,
                            });
                        }
                    }

                    massive_information = Some(MassiveInfo {
                        opcode: *contained_opcode,
                        remaining: *contained_count,
                    });
                },
                SilkroadFrame::MassiveContainer { inner, count, crc } => {
                    if let Some(mut massive) = massive_information.take() {
                        let mut current_buffer = massive_buffer.take().unwrap_or_default();
                        current_buffer.extend_from_slice(inner);

                        massive.remaining = massive.remaining.saturating_sub(1);

                        if let Some(checkers) = security.checkers() {
                            let expected_count = checkers.generate_count_byte();
                            if *count != expected_count {
                                return Err(ReframingError::CounterCheckFailed {
                                    expected: expected_count,
                                    received: *count,
                                });
                            }

                            let mut checksum_builder = checkers.checksum_builder();
                            checksum_builder.update(&(1u16 + inner.len() as u16).to_le_bytes());
                            checksum_builder.update(&0x600Du16.to_le_bytes());
                            checksum_builder.update_byte(*count);
                            checksum_builder.update_byte(0);
                            checksum_builder.update_byte(1);
                            checksum_builder.update(inner);
                            let expected_crc = checksum_builder.digest();
                            if *crc != expected_crc {
                                return Err(ReframingError::CrcCheckFailed {
                                    expected: expected_crc,
                                    received: *crc,
                                });
                            }
                        }

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
                },
            }
        }

        Err(ReframingError::Incomplete(
            massive_information.map(|massive| massive.remaining as usize),
        ))
    }
}

/// Container for [MessageCounter] and [Checksum].
pub struct SecurityBytes {
    counter: Mutex<MessageCounter>,
    checksum: Checksum,
}

impl SecurityBytes {
    pub fn from_seeds(crc_seed: u32, count_seed: u32) -> Self {
        Self {
            counter: Mutex::new(MessageCounter::new(count_seed)),
            checksum: Checksum::new(crc_seed),
        }
    }

    /// Generate the next count byte.
    ///
    /// A count byte is used to avoid replay attacks, used to determine a
    /// continuous flow of the data. If a packet is dropped, or another
    /// injected, this will no longer match. It is essentially a seeded RNG
    /// number.
    pub fn generate_count_byte(&self) -> u8 {
        self.counter
            .lock()
            .expect("Should be able to lock the counter for increasing it")
            .next_byte()
    }

    pub fn generate_checksum(&self, data: &[u8]) -> u8 {
        self.checksum.generate_byte(data)
    }

    pub fn checksum_builder(&self) -> ChecksumBuilder {
        self.checksum.builder()
    }
}

// Technically, this is not the right place. But due to the orphan rule, it's
// the most suitable place.
impl From<CheckBytesInitialization> for SecurityBytes {
    fn from(value: CheckBytesInitialization) -> Self {
        SecurityBytes::from_seeds(value.crc_seed, value.count_seed)
    }
}

/// Provides a complete security context to handle packets.
///
/// To properly handle all security features of a Silkroad Online packet, you
/// may need all three elements: [SilkroadEncryption], [MessageCounter], and
/// [Checksum]. However, it is possible for either the [SilkroadEncryption] to
/// be absent and/or both [MessageCounter] and [Checksum] to be absent. Thus,
/// [MessageCounter] and [Checksum] are tied together. This struct does not
/// really provide much in and of itself, but it is handy as it might be used in
/// different layers in the stack to refer to.
#[derive(Default)]
pub struct SecurityContext<'a> {
    encryption: Option<&'a SilkroadEncryption>,
    checkers: Option<&'a SecurityBytes>,
}

impl<'a> SecurityContext<'a> {
    pub fn new(
        encryption: Option<&'a SilkroadEncryption>,
        security_bytes: Option<&'a SecurityBytes>,
    ) -> Self {
        Self {
            encryption,
            checkers: security_bytes,
        }
    }

    /// Provide the established encryption, if present.
    pub fn encryption(&self) -> Option<&SilkroadEncryption> {
        self.encryption
    }

    /// Provide the security bytes/checkers, if present.
    pub fn checkers(&self) -> Option<&SecurityBytes> {
        self.checkers
    }
}
