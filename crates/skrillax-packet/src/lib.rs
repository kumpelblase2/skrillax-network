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
//! [SilkroadFrame], or vice versa. This currently takes a small detour through
//! using either an [IncomingPacket] or [OutgoingPacket], depending on the
//! direction. This is done because we often first need to apply some kind of
//! transformation to the frames before we can easily turn them into structs
//! representing the packet. This would include combining multiple massive
//! frames into one large buffer as well as decrypting the content of frames to
//! figure out their opcodes. Thus, the chain goes something like this, in a
//! simplified way. To turn a packet into frames, first call the fallible
//! `my_packet.as_packet(&serde_context)?`, then
//! `outgoing.as_frames(security_context)?`. To turn frames into a packet, use
//! `IncomingPacket::from_frames(frames, security_context)` followed by the
//! packet's `TryFromPacket` implementation. Receiver-controlled frame-count and
//! payload-byte limits can be enforced with
//! [`IncomingPacket::from_frames_with_limits`] or [`IncomingPacketReframer`].
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
use skrillax_codec::{
    FrameContentSize, FrameEncodeError, FrameParseError, MASSIVE_CONTAINER_MODE,
    MASSIVE_HEADER_MODE, MASSIVE_PACKET_OPCODE, MAX_MASSIVE_CONTAINER_INNER_SIZE, SilkroadFrame,
};
use skrillax_security::handshake::CheckBytesInitialization;
use skrillax_security::{
    Checksum, ChecksumBuilder, MessageCounter, SilkroadEncryption, SilkroadSecurityError,
};
use std::sync::Mutex;
use thiserror::Error;

#[cfg(feature = "derive")]
pub use skrillax_packet_derive::Packet;
#[cfg(feature = "serde")]
pub use skrillax_serde::SerdeContext;
#[cfg(feature = "serde")]
use skrillax_serde::{ByteSize, Deserialize, SerializationError, Serialize};

#[derive(Error, Debug)]
pub enum PacketError {
    #[cfg(feature = "serde")]
    #[error("An error occurred while trying to (de)serialize the packet. {0:?}")]
    SerializationError(#[from] SerializationError),
    #[error(
        "An encrypted packet was either attempted to be sent or received, but no security has \
         been established yet"
    )]
    MissingSecurity,
    #[error("Packet type {packet} is not configured for massive framing")]
    NonMassivePacketSequence { packet: &'static str },
    #[error("The combined serialized size of packet type {packet} overflowed usize")]
    PacketSizeOverflow { packet: &'static str },
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
    /// Defines if this packet is a massive packet and should thus use massive
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

    /// Constructs one logical packet from the start of a frame slice while
    /// enforcing receiver limits.
    ///
    /// Limits are checked incrementally before massive container payloads are
    /// accumulated. The returned slice contains every frame after the first
    /// complete packet and can be passed to this function again.
    pub fn from_frames_with_limits<'frames>(
        frames: &'frames [SilkroadFrame],
        security: SecurityContext<'_>,
        limits: ReframingLimits,
    ) -> Result<(Self, &'frames [SilkroadFrame]), ReframingError> {
        let mut reframer = IncomingPacketReframer::new(limits);
        for (index, frame) in frames.iter().enumerate() {
            if let Some(packet) = reframer.push(
                frame,
                SecurityContext::new(security.encryption(), security.checkers()),
            )? {
                return Ok((packet, &frames[index + 1..]));
            }
        }

        Err(reframer.incomplete_error())
    }
}

/// A packet on its way out, before having been turned into a frame.
///
/// In turn, we still need to know what kind of frame it should end up as.
/// Generally, one outgoing packet will result in a single frame, but
/// multiple packets can be combined into a massive packet. This will
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

impl OutgoingPacket {
    pub fn opcode(&self) -> u16 {
        match self {
            OutgoingPacket::Encrypted { opcode, .. } => *opcode,
            OutgoingPacket::Simple { opcode, .. } => *opcode,
            OutgoingPacket::Massive { opcode, .. } => *opcode,
        }
    }
}

/// Fallibly converts a value into an [OutgoingPacket].
///
/// Generally, this is a struct representing one operation or a protocol enum
/// containing several packet types. A blanket implementation is provided for
/// values implementing [Packet] and
/// [Serialize](https://docs.rs/skrillax-serde/latest/skrillax_serde/trait.Serialize.html),
/// as well as slices of massive packets.
///
/// Packet serialization uses a fresh buffer. If serialization fails, that
/// buffer is discarded and the original
/// [`skrillax_serde::SerializationError`] is returned as a [PacketError]. No
/// partially constructed packet is returned.
///
/// The incoming analog is [TryFromPacket].
#[cfg(feature = "serde")]
pub trait AsPacket {
    /// Serializes this value using `ctx` and constructs a packet ready for
    /// framing.
    ///
    /// This can fail when serialization rejects an unrepresentable or
    /// internally inconsistent value. Callers must handle the returned
    /// [PacketError] before attempting to create or send frames.
    fn as_packet(&self, ctx: &SerdeContext) -> Result<OutgoingPacket, PacketError>;
}

/// Defines _something_ that can be created from a packet, after it has been
/// received.
///
/// Once the re-framing, decryption, and other parts have completed, we want to
/// turn the contained data into a usable structure.
///
/// The analog is [AsPacket].
#[cfg(feature = "serde")]
pub trait TryFromPacket {
    /// Tries to create `Self` from the given data. Unlike [AsPacket], we
    /// do not deal with the opcode here. It is expected that we have
    /// already matched the opcode to `Self` and know it matches.
    ///
    /// `data` _may_ contain more data than necessary to form a single packet,
    /// for example, if we were inside a massive frame. Thus, we need to
    /// return the number of consumed bytes such that the remainder may be
    /// used to create more elements of `Self` if the caller wants to.
    fn try_deserialize(data: &[u8], ctx: &SerdeContext) -> Result<(usize, Self), PacketError>
    where
        Self: Sized;
}

#[cfg(feature = "serde")]
impl<T> TryFromPacket for T
where
    T: Packet + Deserialize,
{
    fn try_deserialize(data: &[u8], ctx: &SerdeContext) -> Result<(usize, Self), PacketError> {
        use bytes::Buf;
        let mut reader = data.reader();
        let read = Self::read_from(&mut reader, ctx)?;
        let consumed = data.len() - reader.into_inner().len();
        Ok((consumed, read))
    }
}

#[cfg(feature = "serde")]
fn split_massive_payload(mut data: Bytes) -> Vec<Bytes> {
    let required_packets = data.len().div_ceil(MAX_MASSIVE_CONTAINER_INNER_SIZE).max(1);
    let mut packets = Vec::with_capacity(required_packets);

    while data.len() > MAX_MASSIVE_CONTAINER_INNER_SIZE {
        packets.push(data.split_to(MAX_MASSIVE_CONTAINER_INNER_SIZE));
    }
    packets.push(data);

    packets
}

#[cfg(feature = "serde")]
impl<T> AsPacket for [T]
where
    T: Packet + Serialize + ByteSize,
{
    fn as_packet(&self, ctx: &SerdeContext) -> Result<OutgoingPacket, PacketError> {
        if !T::MASSIVE {
            return Err(PacketError::NonMassivePacketSequence { packet: T::NAME });
        }
        let total_size = self.iter().try_fold(0usize, |total, packet| {
            total.checked_add(packet.byte_size())
        });
        let Some(total_size) = total_size else {
            return Err(PacketError::PacketSizeOverflow { packet: T::NAME });
        };
        let mut buffer = BytesMut::with_capacity(total_size.min(MAX_MASSIVE_CONTAINER_INNER_SIZE));
        for p in self {
            p.write_to(&mut buffer, ctx)?;
        }

        Ok(OutgoingPacket::Massive {
            opcode: T::ID,
            packets: split_massive_payload(buffer.freeze()),
        })
    }
}

#[cfg(feature = "serde")]
impl<T> AsPacket for T
where
    T: Packet + Serialize + ByteSize,
{
    fn as_packet(&self, ctx: &SerdeContext) -> Result<OutgoingPacket, PacketError> {
        let initial_capacity = self.byte_size().min(MAX_MASSIVE_CONTAINER_INNER_SIZE);
        let mut buffer = BytesMut::with_capacity(initial_capacity);
        self.write_to(&mut buffer, ctx)?;
        if Self::MASSIVE {
            Ok(OutgoingPacket::Massive {
                opcode: Self::ID,
                packets: split_massive_payload(buffer.freeze()),
            })
        } else if Self::ENCRYPTED {
            Ok(OutgoingPacket::Encrypted {
                opcode: Self::ID,
                data: buffer.freeze(),
            })
        } else {
            Ok(OutgoingPacket::Simple {
                opcode: Self::ID,
                data: buffer.freeze(),
            })
        }
    }
}

#[derive(Error, Debug)]
pub enum FramingError {
    #[error("Tried to create an encrypted frame but no encrypted was set up")]
    MissingEncryption,
    #[error(transparent)]
    FrameEncoding(#[from] FrameEncodeError),
    #[error("Massive container payload has {actual} bytes, but the maximum is {maximum} bytes")]
    MassiveContainerTooLarge { actual: usize, maximum: usize },
    #[error("Massive packet has {actual} containers, but the maximum is {maximum}")]
    TooManyMassiveContainers { actual: usize, maximum: usize },
    #[error("Could not encrypt frame data")]
    Encryption(#[source] SilkroadSecurityError),
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
    /// may be an error.
    fn as_frames(&self, context: SecurityContext) -> Result<Vec<SilkroadFrame>, FramingError>;
}

impl AsFrames for OutgoingPacket {
    fn as_frames(&self, context: SecurityContext) -> Result<Vec<SilkroadFrame>, FramingError> {
        match self {
            OutgoingPacket::Encrypted { opcode, data } => {
                let frame_content_size = FrameContentSize::try_from(data.len())?;
                let Some(encryption) = context.encryption() else {
                    return Err(FramingError::MissingEncryption);
                };
                let count = context
                    .checkers()
                    .map(|check| check.generate_count_byte())
                    .unwrap_or(0);
                let content_length = frame_content_size.as_usize() + 4;
                let length_with_padding = frame_content_size.encrypted_data_len();
                let mut new_buffer = BytesMut::with_capacity(length_with_padding);
                new_buffer.put_u16_le(*opcode);
                new_buffer.put_u8(count);
                new_buffer.put_u8(0);
                new_buffer.put_slice(data);

                if let Some(mut checksum_builder) = context
                    .checkers()
                    .map(|checkers| checkers.checksum_builder())
                {
                    checksum_builder
                        .update(&frame_content_size.encrypted_wire_value().to_le_bytes());
                    checksum_builder.update(&new_buffer);
                    new_buffer[3] = checksum_builder.digest();
                }

                for _ in 0..(length_with_padding - content_length) {
                    new_buffer.put_u8(0);
                }

                encryption
                    .encrypt_mut(&mut new_buffer)
                    .map_err(FramingError::Encryption)?;
                Ok(vec![SilkroadFrame::Encrypted {
                    content_size: frame_content_size.as_usize(),
                    encrypted_data: new_buffer.freeze(),
                }])
            },
            OutgoingPacket::Simple { opcode, data } => {
                let content_size = FrameContentSize::try_from(data.len())?;
                let count = context
                    .checkers()
                    .map(|check| check.generate_count_byte())
                    .unwrap_or(0);
                let crc = if let Some(mut checksum_builder) = context
                    .checkers()
                    .map(|checkers| checkers.checksum_builder())
                {
                    checksum_builder.update(&content_size.get().to_le_bytes());
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
                let contained_count = u16::try_from(packets.len()).map_err(|_| {
                    FramingError::TooManyMassiveContainers {
                        actual: packets.len(),
                        maximum: usize::from(u16::MAX),
                    }
                })?;
                for packet in packets {
                    if packet.len() > MAX_MASSIVE_CONTAINER_INNER_SIZE {
                        return Err(FramingError::MassiveContainerTooLarge {
                            actual: packet.len(),
                            maximum: MAX_MASSIVE_CONTAINER_INNER_SIZE,
                        });
                    }
                }

                let count = context
                    .checkers()
                    .map(|check| check.generate_count_byte())
                    .unwrap_or(0);
                let mut frames = Vec::with_capacity(1 + packets.len());

                let crc = context
                    .checkers()
                    .map(|checkers| {
                        checkers.generate_massive_header_checksum(count, *opcode, contained_count)
                    })
                    .unwrap_or(0);

                frames.push(SilkroadFrame::MassiveHeader {
                    count,
                    crc,
                    contained_opcode: *opcode,
                    contained_count,
                });

                for packet in packets {
                    let count = context
                        .checkers()
                        .map(|check| check.generate_count_byte())
                        .unwrap_or(0);

                    let crc = context
                        .checkers()
                        .map(|checkers| checkers.generate_massive_container_checksum(count, packet))
                        .unwrap_or(0);

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

/// Receiver policy for constructing one logical packet from frames.
///
/// Frame counts include every frame contributing to the logical packet,
/// including a massive header. Payload bytes are the bytes eventually exposed
/// through [`IncomingPacket::data`]; framing metadata and encryption padding do
/// not count. The default uses [`ReframingLimits::recommended`]; unlimited
/// reframing remains available through [`ReframingLimits::unlimited`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ReframingLimits {
    max_frames_per_packet: Option<usize>,
    max_payload_bytes_per_packet: Option<usize>,
}

impl ReframingLimits {
    /// Creates a policy with no frame-count or payload-byte limit.
    pub const fn unlimited() -> Self {
        Self {
            max_frames_per_packet: None,
            max_payload_bytes_per_packet: None,
        }
    }

    /// Creates a policy with the recommended limits to start with.
    ///
    /// This is currently set to 64 max frames and ~8MiB of payload. It is
    /// unlikely to get larger payloads in normal operation, but this avoids
    /// abusive peers to some degree.
    pub const fn recommended() -> Self {
        Self {
            max_frames_per_packet: Some(64),
            max_payload_bytes_per_packet: Some(1024 * 1024 * 8),
        }
    }

    /// Sets the maximum number of frames contributing to one logical packet.
    ///
    /// A maximum of zero rejects every packet. A normal packet requires one
    /// frame, while a massive packet requires its header plus all declared
    /// container frames.
    pub const fn with_max_frames_per_packet(mut self, maximum: usize) -> Self {
        self.max_frames_per_packet = Some(maximum);
        self
    }

    /// Sets the maximum payload size of one logical packet.
    ///
    /// A maximum of zero permits packets with an empty payload.
    pub const fn with_max_payload_bytes_per_packet(mut self, maximum: usize) -> Self {
        self.max_payload_bytes_per_packet = Some(maximum);
        self
    }

    /// Returns the configured frame-count maximum, if any.
    pub const fn max_frames_per_packet(&self) -> Option<usize> {
        self.max_frames_per_packet
    }

    /// Returns the configured payload-byte maximum, if any.
    pub const fn max_payload_bytes_per_packet(&self) -> Option<usize> {
        self.max_payload_bytes_per_packet
    }

    fn check_frame_count(&self, required: usize) -> Result<(), ReframingError> {
        if let Some(maximum) = self.max_frames_per_packet
            && required > maximum
        {
            return Err(ReframingError::FrameCountLimitExceeded { required, maximum });
        }

        Ok(())
    }

    fn check_payload_bytes(&self, attempted: usize) -> Result<(), ReframingError> {
        if let Some(maximum) = self.max_payload_bytes_per_packet
            && attempted > maximum
        {
            return Err(ReframingError::PayloadByteLimitExceeded { attempted, maximum });
        }

        Ok(())
    }
}

impl Default for ReframingLimits {
    fn default() -> Self {
        ReframingLimits::recommended()
    }
}

#[derive(Error, Debug)]
#[non_exhaustive]
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
    #[error("Could not decrypt encrypted frame data")]
    Decryption(#[source] SilkroadSecurityError),
    #[error("Could not parse the decrypted encrypted frame: {0}")]
    InvalidEncryptedFrame(#[from] FrameParseError),
    #[error("The CRC byte was {received} by we expected to to be {expected}")]
    CrcCheckFailed { expected: u8, received: u8 },
    #[error("The count byte was {received} by we expected to to be {expected}")]
    CounterCheckFailed { expected: u8, received: u8 },
    #[error(
        "Logical packet requires {required} frames, exceeding the configured maximum {maximum}"
    )]
    FrameCountLimitExceeded { required: usize, maximum: usize },
    #[error("The frame count of a logical packet overflowed usize")]
    FrameCountOverflow,
    #[error(
        "Logical packet payload would contain {attempted} bytes, exceeding the configured maximum \
         {maximum}"
    )]
    PayloadByteLimitExceeded { attempted: usize, maximum: usize },
    #[error("The combined payload size of a logical packet overflowed usize")]
    PayloadSizeOverflow,
}

/// Incrementally constructs logical packets from incoming frames.
///
/// Limits are checked before payload bytes are accumulated. In particular, a
/// massive header whose declared frame count exceeds the policy is rejected
/// before any of its containers are received. A limit error should be treated
/// as terminal for the containing stream because unread containers belonging to
/// a rejected massive packet remain on the wire.
pub struct IncomingPacketReframer {
    limits: ReframingLimits,
    massive_information: Option<MassiveInfo>,
    massive_buffer: BytesMut,
    frame_count: usize,
}

impl IncomingPacketReframer {
    /// Creates an idle reframer using `limits` for each logical packet.
    pub fn new(limits: ReframingLimits) -> Self {
        Self {
            limits,
            massive_information: None,
            massive_buffer: BytesMut::new(),
            frame_count: 0,
        }
    }

    /// Returns the active receiver policy.
    pub const fn limits(&self) -> ReframingLimits {
        self.limits
    }

    /// Processes one frame, returning a packet when the logical packet is
    /// complete.
    ///
    /// `Ok(None)` means that a massive packet still requires container frames.
    /// The reframer resets after completing a packet and can then receive the
    /// first frame of the next logical packet.
    pub fn push(
        &mut self,
        frame: &SilkroadFrame,
        security: SecurityContext<'_>,
    ) -> Result<Option<IncomingPacket>, ReframingError> {
        match frame {
            SilkroadFrame::Packet {
                opcode,
                data,
                count,
                crc,
            } => {
                if self.massive_information.is_some() {
                    return Err(ReframingError::MixedFrames);
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

                self.limits.check_frame_count(1)?;
                self.limits.check_payload_bytes(data.len())?;
                Ok(Some(self.finish_packet(*opcode, data.clone())))
            },
            SilkroadFrame::Encrypted {
                encrypted_data,
                content_size,
            } => {
                if self.massive_information.is_some() {
                    return Err(ReframingError::MixedFrames);
                }

                let Some(encryption) = security.encryption() else {
                    return Err(ReframingError::MissingSecurity);
                };

                let decrypted = encryption
                    .decrypt(encrypted_data)
                    .map_err(ReframingError::Decryption)?;

                let Some(decrypted_data) = content_size
                    .checked_add(4)
                    .and_then(|payload_end| decrypted.get(0..payload_end))
                else {
                    return Err(ReframingError::InvalidEncryptedData);
                };
                let decrypted_frame = SilkroadFrame::from_data(decrypted_data)?;
                let SilkroadFrame::Packet {
                    opcode,
                    data,
                    count,
                    crc,
                } = decrypted_frame
                else {
                    return Err(ReframingError::InvalidEncryptedData);
                };

                if let Some(checkers) = security.checkers() {
                    let expected_count = checkers.generate_count_byte();
                    if count != expected_count {
                        return Err(ReframingError::CounterCheckFailed {
                            expected: expected_count,
                            received: count,
                        });
                    }

                    let mut checksum_builder = checkers.checksum_builder();
                    checksum_builder.update(&(data.len() as u16 | 0x8000).to_le_bytes());
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

                self.limits.check_frame_count(1)?;
                self.limits.check_payload_bytes(data.len())?;
                Ok(Some(self.finish_packet(opcode, data)))
            },
            SilkroadFrame::MassiveHeader {
                contained_count,
                contained_opcode,
                count,
                crc,
            } => {
                if self.massive_information.is_some() {
                    return Err(ReframingError::MixedFrames);
                }

                if let Some(checkers) = security.checkers() {
                    let expected_count = checkers.generate_count_byte();
                    if *count != expected_count {
                        return Err(ReframingError::CounterCheckFailed {
                            expected: expected_count,
                            received: *count,
                        });
                    }

                    let expected_crc = checkers.generate_massive_header_checksum(
                        *count,
                        *contained_opcode,
                        *contained_count,
                    );
                    if *crc != expected_crc {
                        return Err(ReframingError::CrcCheckFailed {
                            expected: expected_crc,
                            received: *crc,
                        });
                    }
                }

                let required_frames = usize::from(*contained_count)
                    .checked_add(1)
                    .ok_or(ReframingError::FrameCountOverflow)?;
                self.limits.check_frame_count(required_frames)?;
                self.limits.check_payload_bytes(0)?;

                if *contained_count == 0 {
                    return Ok(Some(self.finish_packet(*contained_opcode, Bytes::new())));
                }

                self.massive_information = Some(MassiveInfo {
                    opcode: *contained_opcode,
                    remaining: *contained_count,
                });
                self.frame_count = 1;
                Ok(None)
            },
            SilkroadFrame::MassiveContainer { inner, count, crc } => {
                if self.massive_information.is_none() {
                    return Err(ReframingError::StrayMassiveContainer);
                }

                if let Some(checkers) = security.checkers() {
                    let expected_count = checkers.generate_count_byte();
                    if *count != expected_count {
                        return Err(ReframingError::CounterCheckFailed {
                            expected: expected_count,
                            received: *count,
                        });
                    }

                    let expected_crc = checkers.generate_massive_container_checksum(*count, inner);
                    if *crc != expected_crc {
                        return Err(ReframingError::CrcCheckFailed {
                            expected: expected_crc,
                            received: *crc,
                        });
                    }
                }

                let frame_count = self
                    .frame_count
                    .checked_add(1)
                    .ok_or(ReframingError::FrameCountOverflow)?;
                self.limits.check_frame_count(frame_count)?;
                let payload_size = self
                    .massive_buffer
                    .len()
                    .checked_add(inner.len())
                    .ok_or(ReframingError::PayloadSizeOverflow)?;
                self.limits.check_payload_bytes(payload_size)?;

                self.massive_buffer.extend_from_slice(inner);
                self.frame_count = frame_count;

                let Some(massive) = self.massive_information.as_mut() else {
                    return Err(ReframingError::StrayMassiveContainer);
                };
                massive.remaining -= 1;
                if massive.remaining != 0 {
                    return Ok(None);
                }

                let opcode = massive.opcode;
                let data = std::mem::take(&mut self.massive_buffer).freeze();
                Ok(Some(self.finish_packet(opcode, data)))
            },
        }
    }

    fn finish_packet(&mut self, opcode: u16, data: Bytes) -> IncomingPacket {
        self.massive_information = None;
        self.massive_buffer.clear();
        self.frame_count = 0;
        IncomingPacket::new(opcode, data)
    }

    fn incomplete_error(&self) -> ReframingError {
        ReframingError::Incomplete(
            self.massive_information
                .as_ref()
                .map(|massive| usize::from(massive.remaining)),
        )
    }
}

/// Provides a way to turn [SilkroadFrame]s into an [IncomingPacket].
pub trait FromFrames {
    type Output;
    /// Tries to turn the first logical packet in `frames` into an incoming
    /// packet and returns the unconsumed frame suffix.
    ///
    /// The packet may be represented by one plain or encrypted frame, or by a
    /// massive header and its declared container frames. Returning the suffix
    /// makes every supplied frame explicit and allows callers to parse several
    /// logical packets from one slice without silently ignoring input.
    ///
    /// It requires a security context such that it may validate and decrypt
    /// frames when the need arises. If no security is provided but an
    /// encrypted frame is encountered, it will error.
    ///
    /// This compatibility entry point does not impose receiver limits. Use
    /// [`IncomingPacket::from_frames_with_limits`] when handling untrusted
    /// frame sequences directly.
    fn from_frames<'frames>(
        frames: &'frames [SilkroadFrame],
        security: SecurityContext,
    ) -> Result<(Self::Output, &'frames [SilkroadFrame]), ReframingError>;
}

struct MassiveInfo {
    opcode: u16,
    remaining: u16,
}

impl FromFrames for IncomingPacket {
    type Output = IncomingPacket;

    fn from_frames<'frames>(
        frames: &'frames [SilkroadFrame],
        security: SecurityContext,
    ) -> Result<(Self, &'frames [SilkroadFrame]), ReframingError> {
        if let Some(SilkroadFrame::MassiveHeader {
            contained_count, ..
        }) = frames.first()
        {
            let required_containers = usize::from(*contained_count);
            let available_containers = frames.len().saturating_sub(1);
            if required_containers > available_containers {
                return Err(ReframingError::Incomplete(Some(required_containers)));
            }
        }

        Self::from_frames_with_limits(frames, security, ReframingLimits::recommended())
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
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .next_byte()
    }

    pub fn generate_checksum(&self, data: &[u8]) -> u8 {
        self.checksum.generate_byte(data)
    }

    pub fn checksum_builder(&self) -> ChecksumBuilder<'_> {
        self.checksum.builder()
    }

    fn generate_massive_header_checksum(
        &self,
        count: u8,
        contained_opcode: u16,
        contained_count: u16,
    ) -> u8 {
        let mut checksum_builder = self.checksum_builder();
        checksum_builder.update(&5u16.to_le_bytes());
        checksum_builder.update(&MASSIVE_PACKET_OPCODE.to_le_bytes());
        checksum_builder.update_byte(count);
        checksum_builder.update_byte(0);
        checksum_builder.update_byte(MASSIVE_HEADER_MODE);
        checksum_builder.update(&contained_opcode.to_le_bytes());
        checksum_builder.update(&contained_count.to_le_bytes());
        checksum_builder.digest()
    }

    fn generate_massive_container_checksum(&self, count: u8, inner: &[u8]) -> u8 {
        let mut checksum_builder = self.checksum_builder();
        checksum_builder.update(&((inner.len() + 1) as u16).to_le_bytes());
        checksum_builder.update(&MASSIVE_PACKET_OPCODE.to_le_bytes());
        checksum_builder.update_byte(count);
        checksum_builder.update_byte(0);
        checksum_builder.update_byte(MASSIVE_CONTAINER_MODE);
        checksum_builder.update(inner);
        checksum_builder.digest()
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
/// [MessageCounter] and [Checksum] are tied together. This struct really
/// provides little in and of itself, but it is handy as it might be used in
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_peer_massive_header_is_rejected() {
        let frames = [
            SilkroadFrame::MassiveHeader {
                count: 0,
                crc: 0,
                contained_opcode: 0x4242,
                contained_count: 1,
            },
            SilkroadFrame::MassiveHeader {
                count: 0,
                crc: 0,
                contained_opcode: 0x4343,
                contained_count: 0,
            },
        ];

        let result = IncomingPacket::from_frames(&frames, SecurityContext::default());

        assert!(
            matches!(result, Err(ReframingError::MixedFrames)),
            "a nested peer header must not replace an in-progress massive packet: {result:?}"
        );
    }

    #[test]
    fn invalid_encrypted_block_length_returns_decryption_error() {
        let encryption = SilkroadEncryption::from_key(0xFF00FF00FF00FF00);
        let frame = SilkroadFrame::Encrypted {
            content_size: 1,
            encrypted_data: Bytes::from_static(&[1, 2, 3]),
        };
        let frames = [frame];

        let result =
            IncomingPacket::from_frames(&frames, SecurityContext::new(Some(&encryption), None));

        assert!(matches!(
            result,
            Err(ReframingError::Decryption(
                SilkroadSecurityError::InvalidBlockLength(3)
            ))
        ));
    }

    #[test]
    fn malformed_encrypted_massive_frame_returns_parse_error() {
        let encryption = SilkroadEncryption::from_key(0xFF00FF00FF00FF00);
        let encrypted_data = encryption
            .encrypt(&[0x0D, 0x60, 0, 0, 1])
            .expect("encrypting test data should succeed");
        let frame = SilkroadFrame::Encrypted {
            content_size: 1,
            encrypted_data,
        };
        let frames = [frame];

        let result =
            IncomingPacket::from_frames(&frames, SecurityContext::new(Some(&encryption), None));

        assert!(matches!(
            result,
            Err(ReframingError::InvalidEncryptedFrame(
                FrameParseError::MassiveHeaderTooShort { actual: 5 }
            ))
        ));
    }
}
