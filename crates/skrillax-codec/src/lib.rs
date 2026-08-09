//! `skrillax-codec` is a crate to turn a raw stream of bytes into more
//! meaningful frames in the format used by Silkroad Online. Framing is only the
//! first step, as a frame is still quite a general object and does itself not
//! provide many operations. Instead, operations are contained inside frames and
//! will need to be decoded/encoded separately.
//!
//! This crate provides two things: the [SilkroadFrame] and [SilkroadCodec]. The
//! latter, [SilkroadCodec], is expected to be used in combination with tokio's
//! [tokio_util::codec::FramedWrite] & [tokio_util::codec::FramedRead]. It uses
//! the former, [SilkroadFrame], as the type it produces. However, it is totally
//! possible to use this crate without using the codec by using the
//! [SilkroadFrame]'s serialization and deserialization functions.

use byteorder::{ByteOrder, LittleEndian};
#[cfg(feature = "codec")]
use bytes::Buf;
use bytes::{BufMut, Bytes, BytesMut};
use thiserror::Error;

/// An error encountered while encoding a [`SilkroadFrame`].
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum FrameEncodeError {
    /// A frame's content length cannot fit in the 15-bit wire field.
    #[error("frame content has {actual} bytes, but the maximum is {maximum}")]
    ContentTooLarge { actual: usize, maximum: usize },
    /// Encrypted bytes do not match the block-aligned size declared by the
    /// frame.
    #[error(
        "encrypted content size {content_size} requires {expected} encrypted bytes, but {actual} \
         were provided"
    )]
    EncryptedDataLengthMismatch {
        content_size: usize,
        expected: usize,
        actual: usize,
    },
}

/// An error encountered while parsing bytes into a [`SilkroadFrame`].
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum FrameParseError {
    /// The length prefix or declared frame body has not been received in full.
    #[error("frame requires at least {additional} additional byte(s)")]
    Incomplete { additional: usize },
    /// Frame data does not contain the opcode, security count, and CRC fields.
    #[error("frame data requires at least 4 bytes, but only {actual} were provided")]
    FrameTooShort { actual: usize },
    /// A massive frame does not contain its required mode byte.
    #[error("massive frame is missing its mode byte")]
    MissingMassiveMode,
    /// A massive frame contains a mode outside the protocol-defined values.
    #[error("invalid massive frame mode {mode}")]
    InvalidMassiveMode { mode: u8 },
    /// A massive header does not contain all of its required fields.
    #[error("massive header requires at least 10 bytes, but only {actual} were provided")]
    MassiveHeaderTooShort { actual: usize },
}

/// Opcode reserved for massive packet headers and containers.
pub const MASSIVE_PACKET_OPCODE: u16 = 0x600D;
/// Mode byte identifying a massive packet header.
pub const MASSIVE_HEADER_MODE: u8 = 1;
/// Mode byte identifying a massive packet data container.
pub const MASSIVE_CONTAINER_MODE: u8 = 0;
const ENCRYPTED_FRAME_FLAG: u16 = 0x8000;
const FRAME_CONTENT_LENGTH_MASK: u16 = 0x7FFF;
const ENCRYPTED_ALIGNMENT: usize = 8;

/// The largest content length representable without setting the encrypted-frame
/// flag.
pub const MAX_FRAME_CONTENT_SIZE: usize = FRAME_CONTENT_LENGTH_MASK as usize;
/// The largest payload a massive container can carry after its one-byte mode
/// field.
pub const MAX_MASSIVE_CONTAINER_INNER_SIZE: usize = MAX_FRAME_CONTENT_SIZE - 1;

/// A frame content length proven to fit in the protocol's 15-bit wire field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameContentSize(u16);

impl TryFrom<usize> for FrameContentSize {
    type Error = FrameEncodeError;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        if value > MAX_FRAME_CONTENT_SIZE {
            return Err(FrameEncodeError::ContentTooLarge {
                actual: value,
                maximum: MAX_FRAME_CONTENT_SIZE,
            });
        }

        let wire_value = u16::try_from(value).map_err(|_| FrameEncodeError::ContentTooLarge {
            actual: value,
            maximum: MAX_FRAME_CONTENT_SIZE,
        })?;
        Ok(Self(wire_value))
    }
}

impl FrameContentSize {
    /// Returns the checked wire value.
    pub const fn get(self) -> u16 {
        self.0
    }

    /// Returns the checked value as a platform-sized integer.
    pub const fn as_usize(self) -> usize {
        self.0 as usize
    }

    /// Returns the wire value with the encrypted-frame marker set.
    pub const fn encrypted_wire_value(self) -> u16 {
        self.0 | ENCRYPTED_FRAME_FLAG
    }

    /// Returns the block-aligned ciphertext length for this content size.
    pub fn encrypted_data_len(self) -> usize {
        find_encrypted_length(self.as_usize() + 4)
    }
}

/// Find the nearest block-aligned length.
///
/// Given the current length of data to encrypt, calculates the length of the
/// encrypted output, which includes padding. Can at most increase by
/// `ENCRYPTED_ALIGNMENT - 1`, which is `7`.
fn find_encrypted_length(given_length: usize) -> usize {
    let aligned_length = given_length % ENCRYPTED_ALIGNMENT;
    if aligned_length == 0 {
        // Already block-aligned, no need to pad
        return given_length;
    }

    given_length + (8 - aligned_length) // Add padding
}

/// A 'frame' denotes the most fundamental block of data that can be sent
/// between the client and the server in Silkroad Online. Any and all operations
/// or data exchanges are built on top of something like a frame.
///
/// There are two categories of frames; normal frames and massive frames. A
/// normal frame is the most common frame denoting a single operation using a
/// specified opcode. This frame may be encrypted, causing everything but the
/// length to require decrypting before being usable. Massive frames are used to
/// carry a larger logical payload. A massive header is sent first, containing
/// the number of following container frames as well as the logical packet's
/// opcode, and is then followed by the specified number of containers, which
/// contain the data. The container count does not describe how many application
/// objects can be deserialized from that data. Massive frames cannot be
/// encrypted.
///
/// Every frame, including an encrypted frame, contains two additional bytes:
/// a crc checksum and a cryptographically random count. The former is used
/// to check for bitflips/modifications and the count to prevent replay
/// attacks.
///
/// To read a frame from a byte-stream, you can use the [SilkroadFrame::parse]
/// function to try and parse a frame from those bytes:
/// ```
/// # use bytes::Bytes;
/// # use skrillax_codec::SilkroadFrame;
/// let (_, frame) = SilkroadFrame::parse(&[0x00, 0x00, 0x01, 0x00, 0x00, 0x00]).unwrap();
/// assert_eq!(
///     frame,
///     SilkroadFrame::Packet {
///         count: 0,
///         crc: 0,
///         opcode: 1,
///         data: Bytes::new(),
///     }
/// );
/// ```
///
/// This works vice versa, to write a frame into a byte stream, using
/// [SilkroadFrame::serialize]:
/// ```
/// # use bytes::Bytes;
/// # use skrillax_codec::SilkroadFrame;
/// let bytes = SilkroadFrame::Packet {
///     count: 0,
///     crc: 0,
///     opcode: 1,
///     data: Bytes::new(),
/// }
/// .serialize()
/// .expect("the frame is representable");
/// assert_eq!(bytes.as_ref(), &[0x00, 0x00, 0x01, 0x00, 0x00, 0x00]);
/// ```
#[derive(Eq, PartialEq, Debug)]
pub enum SilkroadFrame {
    /// The most basic frame containing exactly one operation identified
    /// by its opcode.
    Packet {
        count: u8,
        crc: u8,
        opcode: u16,
        data: Bytes,
    },
    /// A [SilkroadFrame::Packet] which is, however, still encrypted. This
    /// contains the encrypted data and will first need to be decrypted (for
    /// example, using the `skrillax-security` crate).
    Encrypted {
        content_size: usize,
        encrypted_data: Bytes,
    },
    /// The header portion of a massive packet which contains information
    /// that is necessary for the identification and usage of the following
    /// [SilkroadFrame::MassiveContainer] frame(s). `contained_count` is the
    /// number of following container frames, not a count of application
    /// objects.
    MassiveHeader {
        count: u8,
        crc: u8,
        contained_opcode: u16,
        contained_count: u16,
    },
    /// The data container portion of a massive packet. Must come after
    /// a [SilkroadFrame::MassiveHeader] and contributes data to the logical
    /// payload identified by that header.
    MassiveContainer { count: u8, crc: u8, inner: Bytes },
}

impl SilkroadFrame {
    /// Tries to parse the first possible frame from the given data slice.
    /// In addition to the created frame, it will also return the size of
    /// consumed bytes by the frame. If not enough data is available, it
    /// returns [`FrameParseError::Incomplete`]. The returned value in
    /// `FrameParseError::Incomplete` is not guaranteed to be the exact
    /// necessary bytes; it is possible to get it multiple times, even
    /// when ensuring at least the amount of returned requested bytes were
    /// added. This is because if we _need_ the header info first and
    /// only then can we know the expected size.
    /// Complete but malformed frames return a structural parsing error.
    pub fn parse(data: &[u8]) -> Result<(usize, SilkroadFrame), FrameParseError> {
        if data.len() < 2 {
            return Err(FrameParseError::Incomplete {
                additional: 2 - data.len(),
            });
        }

        let length = LittleEndian::read_u16(&data[0..2]);
        let encrypted = length & ENCRYPTED_FRAME_FLAG != 0;
        let content_size = (length & FRAME_CONTENT_LENGTH_MASK) as usize;
        let total_size = if encrypted {
            find_encrypted_length(content_size + 4)
        } else {
            content_size + 4
        };

        let data = &data[2..];
        if data.len() < total_size {
            return Err(FrameParseError::Incomplete {
                additional: total_size - data.len(),
            });
        }

        let total_consumed = total_size + 2;
        let data = Bytes::copy_from_slice(&data[0..total_size]);
        if encrypted {
            return Ok((
                total_consumed,
                SilkroadFrame::Encrypted {
                    content_size,
                    encrypted_data: data,
                },
            ));
        }

        Ok((total_consumed, Self::from_data(&data)?))
    }

    /// Creates a [SilkroadFrame] given the received data. Generally, this will
    /// result in a [SilkroadFrame::Packet], unless we encounter a packet
    /// with the opcode `0x600D`, which is reserved for a massive packet,
    /// consisting of a [SilkroadFrame::MassiveHeader] and multiple
    /// [SilkroadFrame::MassiveContainer]s.
    ///
    /// The data must contain the two-byte opcode, one-byte security count,
    /// one-byte CRC, and any frame-specific fields. Malformed data is returned
    /// as a typed error.
    pub fn from_data(data: &[u8]) -> Result<SilkroadFrame, FrameParseError> {
        if data.len() < 4 {
            return Err(FrameParseError::FrameTooShort { actual: data.len() });
        }

        let opcode = LittleEndian::read_u16(&data[0..2]);
        let count = data[2];
        let crc = data[3];

        if opcode == MASSIVE_PACKET_OPCODE {
            let mode = *data.get(4).ok_or(FrameParseError::MissingMassiveMode)?;
            match mode {
                MASSIVE_HEADER_MODE => {
                    if data.len() < 10 {
                        return Err(FrameParseError::MassiveHeaderTooShort { actual: data.len() });
                    }
                    let inner_amount = LittleEndian::read_u16(&data[5..7]);
                    let inner_opcode = LittleEndian::read_u16(&data[7..9]);
                    Ok(SilkroadFrame::MassiveHeader {
                        count,
                        crc,
                        contained_opcode: inner_opcode,
                        contained_count: inner_amount,
                    })
                },
                MASSIVE_CONTAINER_MODE => Ok(SilkroadFrame::MassiveContainer {
                    count,
                    crc,
                    inner: Bytes::copy_from_slice(&data[5..]),
                }),
                mode => Err(FrameParseError::InvalidMassiveMode { mode }),
            }
        } else {
            Ok(SilkroadFrame::Packet {
                count,
                crc,
                opcode,
                data: Bytes::copy_from_slice(&data[4..]),
            })
        }
    }

    /// Computes the value represented by the 15-bit length header field.
    /// Depending on the type of frame, this is either:
    /// - The application payload size (basic frame)
    /// - The unpadded application payload size, excluding the encrypted opcode,
    ///   count, and CRC fields (encrypted frame)
    /// - A fixed size (massive header frame)
    /// - The mode byte and payload size (massive container frame)
    pub fn content_size(&self) -> Result<FrameContentSize, FrameEncodeError> {
        let size = match &self {
            SilkroadFrame::Packet { data, .. } => data.len(),
            SilkroadFrame::Encrypted { content_size, .. } => *content_size,
            SilkroadFrame::MassiveHeader { .. } => {
                // Massive headers have a fixed length because they're always:
                // 1 Byte 'is header', 2 Bytes 'number of packets', 2 Bytes 'opcode', 1 Byte
                // unknown
                6
            },
            SilkroadFrame::MassiveContainer { inner, .. } => {
                inner
                    .len()
                    .checked_add(1)
                    .ok_or(FrameEncodeError::ContentTooLarge {
                        actual: usize::MAX,
                        maximum: MAX_FRAME_CONTENT_SIZE,
                    })?
            },
        };

        FrameContentSize::try_from(size)
    }

    fn validated_content_size(&self) -> Result<FrameContentSize, FrameEncodeError> {
        let content_size = self.content_size()?;
        if let SilkroadFrame::Encrypted {
            content_size: declared_content_size,
            encrypted_data,
        } = self
        {
            let expected = content_size.encrypted_data_len();
            if encrypted_data.len() != expected {
                return Err(FrameEncodeError::EncryptedDataLengthMismatch {
                    content_size: *declared_content_size,
                    expected,
                    actual: encrypted_data.len(),
                });
            }
        }

        Ok(content_size)
    }

    /// Validates that this frame has a representable length and coherent shape.
    pub fn validate(&self) -> Result<(), FrameEncodeError> {
        self.validated_content_size().map(|_| ())
    }

    /// Computes the total encoded size of this frame.
    ///
    /// This includes the length header and, for encrypted frames, the fixed
    /// encrypted fields and block padding.
    pub fn packet_size(&self) -> Result<usize, FrameEncodeError> {
        let content_size = self.validated_content_size()?;
        Ok(match self {
            SilkroadFrame::Encrypted { .. } => content_size.encrypted_data_len() + 2,
            _ => 6 + content_size.as_usize(),
        })
    }

    /// Tries to fetch the opcode of the frame, unless the packet
    /// is encrypted, which returns [None].
    pub fn opcode(&self) -> Option<u16> {
        match &self {
            SilkroadFrame::Packet { opcode, .. } => Some(*opcode),
            SilkroadFrame::Encrypted { .. } => None,
            _ => Some(0x600D),
        }
    }

    /// Tries to serialize this frame into a byte stream.
    ///
    /// Frames whose content length cannot be represented by the protocol's
    /// 15-bit length field are rejected before any output is produced.
    pub fn serialize(&self) -> Result<Bytes, FrameEncodeError> {
        let content_size = self.validated_content_size()?;
        let packet_size = match self {
            SilkroadFrame::Encrypted { .. } => content_size.encrypted_data_len() + 2,
            _ => 6 + content_size.as_usize(),
        };
        let mut output = BytesMut::with_capacity(packet_size);

        match &self {
            SilkroadFrame::Packet {
                count,
                crc,
                opcode,
                data,
            } => {
                output.put_u16_le(content_size.get());
                output.put_u16_le(*opcode);
                output.put_u8(*count);
                output.put_u8(*crc);
                output.put_slice(data);
            },
            SilkroadFrame::Encrypted { encrypted_data, .. } => {
                output.put_u16_le(content_size.encrypted_wire_value());
                output.put_slice(encrypted_data);
            },
            SilkroadFrame::MassiveHeader {
                count,
                crc,
                contained_opcode,
                contained_count,
            } => {
                output.put_u16_le(content_size.get());
                output.put_u16_le(MASSIVE_PACKET_OPCODE);
                output.put_u8(*count);
                output.put_u8(*crc);
                output.put_u8(MASSIVE_HEADER_MODE);
                output.put_u16_le(*contained_count);
                output.put_u16_le(*contained_opcode);
                output.put_u8(0);
            },
            SilkroadFrame::MassiveContainer { count, crc, inner } => {
                output.put_u16_le(content_size.get());
                output.put_u16_le(MASSIVE_PACKET_OPCODE);
                output.put_u8(*count);
                output.put_u8(*crc);
                output.put_u8(MASSIVE_CONTAINER_MODE);
                output.put_slice(inner);
            },
        }

        Ok(output.freeze())
    }
}

#[cfg(feature = "codec")]
pub use codec::*;

#[cfg(feature = "codec")]
mod codec {
    use super::*;
    use std::io;
    use tokio_util::codec::{Decoder, Encoder};

    /// A codec to read and write [SilkroadFrame] from/onto a byte stream.
    /// This implements [Encoder] and [Decoder] to be used in combination
    /// with tokio framed read/write. Essentially, this wraps the
    /// [SilkroadFrame::serialize] and [SilkroadFrame::parse] functions
    /// to serialize and deserialize the frames.
    pub struct SilkroadCodec;

    impl Encoder<SilkroadFrame> for SilkroadCodec {
        type Error = io::Error;

        fn encode(&mut self, item: SilkroadFrame, dst: &mut BytesMut) -> Result<(), Self::Error> {
            let bytes = item
                .serialize()
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
            dst.extend_from_slice(&bytes);
            Ok(())
        }
    }

    impl Decoder for SilkroadCodec {
        type Item = SilkroadFrame;
        type Error = io::Error;

        fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
            match SilkroadFrame::parse(src) {
                Ok((bytes_read, frame)) => {
                    src.advance(bytes_read);
                    Ok(Some(frame))
                },
                Err(FrameParseError::Incomplete { .. }) => Ok(None),
                Err(error) => Err(io::Error::new(io::ErrorKind::InvalidData, error)),
            }
        }
    }
}

#[cfg(test)]
mod test {
    #[cfg(feature = "codec")]
    use crate::SilkroadCodec;
    use crate::{FrameEncodeError, FrameParseError, MAX_FRAME_CONTENT_SIZE, SilkroadFrame};
    use bytes::Bytes;
    #[cfg(feature = "codec")]
    use bytes::BytesMut;
    #[cfg(feature = "codec")]
    use tokio_util::codec::{Decoder, Encoder};

    #[test]
    fn test_parse_empty() {
        let data = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let (consumed, packet) =
            SilkroadFrame::parse(&data).expect("Should parse empty, valid data");
        assert_eq!(6, consumed);
        assert_eq!(
            SilkroadFrame::Packet {
                count: 0,
                crc: 0,
                opcode: 0,
                data: Bytes::new(),
            },
            packet
        );
    }

    #[test]
    fn test_parse_incomplete() {
        assert_eq!(
            Err(FrameParseError::Incomplete { additional: 2 }),
            SilkroadFrame::parse(&[])
        );
        assert_eq!(
            Err(FrameParseError::Incomplete { additional: 1 }),
            SilkroadFrame::parse(&[0x00])
        );

        let data = [0x00, 0x00, 0x00, 0x00, 0x00];
        let res = SilkroadFrame::parse(&data);
        assert_eq!(Err(FrameParseError::Incomplete { additional: 1 }), res);

        let data = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00];
        let res = SilkroadFrame::parse(&data);
        assert_eq!(Err(FrameParseError::Incomplete { additional: 1 }), res);
    }

    #[test]
    fn test_parse_rejects_massive_frame_without_mode() {
        let data = [0x00, 0x00, 0x0D, 0x60, 0x00, 0x00];

        let result = SilkroadFrame::parse(&data);

        assert_eq!(Err(FrameParseError::MissingMassiveMode), result);
    }

    #[test]
    fn peer_massive_mode_outside_protocol_is_rejected() {
        // A massive frame may only use mode 0 (container) or mode 1 (header).
        // This peer frame uses mode 2 with one payload byte.
        let wire = [0x02, 0x00, 0x0D, 0x60, 0x00, 0x00, 0x02, 0xAA];

        let result = SilkroadFrame::parse(&wire);

        assert_eq!(Err(FrameParseError::InvalidMassiveMode { mode: 2 }), result);
    }

    #[test]
    fn test_parse_rejects_truncated_massive_header() {
        for content_size in 1usize..6 {
            let mut data = vec![content_size as u8, 0x00, 0x0D, 0x60, 0x00, 0x00, 0x01];
            data.resize(6 + content_size, 0);

            let result = SilkroadFrame::parse(&data);

            assert_eq!(
                Err(FrameParseError::MassiveHeaderTooShort {
                    actual: 4 + content_size,
                }),
                result
            );
        }
    }

    #[test]
    fn test_from_data_rejects_short_frame() {
        for actual in 0..4 {
            let data = [0; 3];

            assert_eq!(
                Err(FrameParseError::FrameTooShort { actual }),
                SilkroadFrame::from_data(&data[..actual])
            );
        }
    }

    #[test]
    fn test_parse_content() {
        let data = [0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x01];
        let (consumed, packet) = SilkroadFrame::parse(&data).expect("Should parse valid data");
        assert_eq!(8, consumed);
        assert_eq!(
            SilkroadFrame::Packet {
                count: 0,
                crc: 0,
                opcode: 0x0001,
                data: Bytes::from_static(&[0x01, 0x01]),
            },
            packet
        );
    }

    #[test]
    fn test_parse_encrypted() {
        let data = [0x02, 0x80, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01];
        let (consumed, packet) = SilkroadFrame::parse(&data).expect("Should parse valid data");
        assert_eq!(10, consumed);
        assert_eq!(
            SilkroadFrame::Encrypted {
                content_size: 2,
                encrypted_data: Bytes::from_static(&[
                    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
                ]),
            },
            packet
        );
    }

    #[test]
    fn test_parse_massive() {
        let header = [
            0x06, 0x00, 0x0D, 0x60, 0x00, 0x00, 0x01, 0x01, 0x00, 0x42, 0x00, 0x00,
        ];
        let (consumed, packet) = SilkroadFrame::parse(&header).expect("Should parse valid data");
        assert_eq!(12, consumed);
        assert_eq!(
            SilkroadFrame::MassiveHeader {
                count: 0,
                crc: 0,
                contained_opcode: 0x42,
                contained_count: 1,
            },
            packet
        );

        let header = [0x02, 0x00, 0x0D, 0x60, 0x00, 0x00, 0x00, 0x01];
        let (consumed, packet) = SilkroadFrame::parse(&header).expect("Should parse valid data");
        assert_eq!(8, consumed);
        assert_eq!(
            SilkroadFrame::MassiveContainer {
                count: 0,
                crc: 0,
                inner: Bytes::from_static(&[0x01]),
            },
            packet
        );
    }

    #[test]
    fn massive_header_count_round_trip_preserves_full_range() {
        for contained_count in [0, u16::MAX] {
            let frame = SilkroadFrame::MassiveHeader {
                count: 0,
                crc: 0,
                contained_opcode: 0x42,
                contained_count,
            };
            let wire = frame
                .serialize()
                .expect("a massive header should be representable");

            let (consumed, parsed) =
                SilkroadFrame::parse(&wire).expect("a massive header count should round-trip");

            assert_eq!(wire.len(), consumed);
            assert_eq!(frame, parsed);
        }
    }

    #[cfg(feature = "codec")]
    #[test]
    fn test_decoder() {
        let mut codec = SilkroadCodec;
        let mut buffer = BytesMut::new();
        buffer.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        let decoded = codec.decode(&mut buffer);
        assert!(matches!(decoded, Ok(None)));

        buffer.extend_from_slice(&[0x00, 0x00]);
        let decoded = codec.decode_eof(&mut buffer).unwrap();
        assert_eq!(
            Some(SilkroadFrame::Packet {
                count: 0,
                crc: 0,
                opcode: 0,
                data: Bytes::new(),
            }),
            decoded
        );
    }

    #[cfg(feature = "codec")]
    #[test]
    fn test_decoder_rejects_malformed_frame() {
        let mut codec = SilkroadCodec;
        let mut buffer = BytesMut::from(&[0x00, 0x00, 0x0D, 0x60, 0x00, 0x00][..]);

        let error = codec
            .decode(&mut buffer)
            .expect_err("malformed frame should be rejected");

        assert_eq!(std::io::ErrorKind::InvalidData, error.kind());
    }

    #[test]
    fn test_serialize_empty() {
        let data = SilkroadFrame::Packet {
            count: 0,
            crc: 0,
            opcode: 0,
            data: Bytes::new(),
        }
        .serialize()
        .expect("an empty frame should be representable");
        assert_eq!(data.as_ref(), &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn maximum_plain_frame_length_round_trips_without_setting_encryption_flag() {
        let frame = SilkroadFrame::Packet {
            count: 7,
            crc: 9,
            opcode: 0x1234,
            data: Bytes::from(vec![0xAB; MAX_FRAME_CONTENT_SIZE]),
        };

        let wire = frame
            .serialize()
            .expect("the maximum 15-bit content length is representable");
        let (consumed, decoded) =
            SilkroadFrame::parse(&wire).expect("the maximum plain frame should parse");

        assert_eq!([0xFF, 0x7F], wire[..2]);
        assert_eq!(wire.len(), consumed);
        assert_eq!(frame, decoded);
    }

    #[test]
    fn oversized_plain_frame_is_rejected() {
        let frame = SilkroadFrame::Packet {
            count: 0,
            crc: 0,
            opcode: 0x1234,
            data: Bytes::from(vec![0; MAX_FRAME_CONTENT_SIZE + 1]),
        };

        let error = frame
            .serialize()
            .expect_err("a plain frame cannot use the encryption marker as length");

        assert_eq!(
            FrameEncodeError::ContentTooLarge {
                actual: MAX_FRAME_CONTENT_SIZE + 1,
                maximum: MAX_FRAME_CONTENT_SIZE,
            },
            error
        );
    }

    #[cfg(feature = "codec")]
    #[test]
    fn codec_rejection_does_not_modify_the_destination_buffer() {
        let frame = SilkroadFrame::Packet {
            count: 0,
            crc: 0,
            opcode: 0x1234,
            data: Bytes::from(vec![0; MAX_FRAME_CONTENT_SIZE + 1]),
        };
        let mut codec = SilkroadCodec;
        let mut destination = BytesMut::from(&b"canary"[..]);

        let error = codec
            .encode(frame, &mut destination)
            .expect_err("the codec must reject an unrepresentable frame");

        assert_eq!(std::io::ErrorKind::InvalidInput, error.kind());
        assert_eq!(&b"canary"[..], destination.as_ref());
    }

    #[test]
    fn test_serialize_encrypted() {
        let data = SilkroadFrame::Encrypted {
            content_size: 0,
            encrypted_data: Bytes::from_static(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
        }
        .serialize()
        .expect("an empty encrypted frame should be representable");
        assert_eq!(
            data.as_ref(),
            &[0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn encrypted_frame_with_mismatched_ciphertext_length_is_rejected() {
        for actual in [7, 16] {
            let frame = SilkroadFrame::Encrypted {
                content_size: 1,
                encrypted_data: Bytes::from(vec![0; actual]),
            };

            let expected_error = FrameEncodeError::EncryptedDataLengthMismatch {
                content_size: 1,
                expected: 8,
                actual,
            };

            assert_eq!(
                expected_error,
                frame
                    .packet_size()
                    .expect_err("an invalid frame has no encoded packet size")
            );
            assert_eq!(
                expected_error,
                frame
                    .serialize()
                    .expect_err("ciphertext must match the padded encrypted content length")
            );
        }
    }

    #[test]
    fn oversized_encrypted_frame_is_rejected() {
        let frame = SilkroadFrame::Encrypted {
            content_size: MAX_FRAME_CONTENT_SIZE + 1,
            encrypted_data: Bytes::new(),
        };

        let error = frame
            .serialize()
            .expect_err("encrypted content must fit the 15-bit length field");

        assert_eq!(
            FrameEncodeError::ContentTooLarge {
                actual: MAX_FRAME_CONTENT_SIZE + 1,
                maximum: MAX_FRAME_CONTENT_SIZE,
            },
            error
        );
    }

    #[test]
    fn test_serialize_massive() {
        let data = SilkroadFrame::MassiveHeader {
            count: 0,
            crc: 0,
            contained_opcode: 0x42,
            contained_count: 1,
        }
        .serialize()
        .expect("a massive header should be representable");
        assert_eq!(
            data.as_ref(),
            &[
                0x06, 0x00, 0x0D, 0x60, 0x00, 0x00, 0x01, 0x01, 0x00, 0x42, 0x00, 0x00
            ]
        );

        let data = SilkroadFrame::MassiveContainer {
            count: 0,
            crc: 0,
            inner: Bytes::new(),
        }
        .serialize()
        .expect("an empty massive container should be representable");
        assert_eq!(data.as_ref(), &[0x01, 0x00, 0x0D, 0x60, 0x00, 0x00, 0x00]);
    }
}
