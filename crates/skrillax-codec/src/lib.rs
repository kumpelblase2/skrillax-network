//! `skrillax-codec` is a crate to turn a raw stream of bytes into more meaningful frames in
//! the format used by Silkroad Online. Framing is only the first step, as a frame is still
//! quite a general object and does itself not provide many operations. Instead, operations
//! are contained inside frames and will need to be decoded/encoded separately.
//!
//! This crate provides two things: the [SilkroadFrame] and [SilkroadCodec]. The latter,
//! [SilkroadCodec], is expected to be used in combination with tokio's
//! [tokio_util::codec::FramedWrite] & [tokio_util::codec::FramedRead]. It uses the former,
//! [SilkroadFrame], as the type it produces. However, it is totally possible to use this
//! crate without using the codec by using the [SilkroadFrame]'s serialization and deserialization
//! functions.

use byteorder::{ByteOrder, LittleEndian};
use bytes::{Buf, BufMut, Bytes, BytesMut};

const MASSIVE_PACKET_OPCODE: u16 = 0x600D;
const ENCRYPTED_ALIGNMENT: usize = 8;

/// Find the nearest block-aligned length.
///
/// Given the current length of data to encrypt, calculates the length of the encrypted output, which includes
/// padding. Can at most increase by `ENCRYPTED_ALIGNMENT - 1`, which is `7`.
fn find_encrypted_length(given_length: usize) -> usize {
    let aligned_length = given_length % ENCRYPTED_ALIGNMENT;
    if aligned_length == 0 {
        // Already block-aligned, no need to pad
        return given_length;
    }

    given_length + (8 - aligned_length) // Add padding
}

/// A 'frame' denotes the most fundamental block of data that can be sent between
/// the client and the server in Silkroad Online. Any and all operations or data exchanges
/// are built on top of a kind of frame.
///
/// There are two categories of frames; normal frames and massive frames. A normal
/// frame is the most common frame denoting a single operation using a specified
/// opcode. This frame may be encrypted, causing everything but the length to require
/// decrypting before being usable. Massive frames are used to bundle similar
/// operations together. A massive header is sent first, containing the amount
/// of operations as well as their opcode, and is then followed by the specified
/// amount of containers, which now only contain the data. Thus, massive frames
/// cannot be encrypted.
///
/// Every frame, including an encrypted frame, contains two additional bytes:
/// a crc checksum and a cryptographically random count. The former is used
/// to check for bitflips/modifications and the count to prevent replay
/// attacks.
///
/// To read a frame from a bytestream, you can use the [SilkroadFrame::parse]
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
/// This works vice-versa, to write a frame into a byte stream, using
/// [SilkroadFrame::serialize]:
/// ```
/// # use bytes::Bytes;
/// # use skrillax_codec::SilkroadFrame;
/// let bytes = SilkroadFrame::Packet {
///     count: 0,
///     crc: 0,
///     opcode: 1,
///     data: Bytes::new()
/// }.serialize();
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
    /// that is necessary for the identification and usage of the followed
    /// [SilkroadFrame::MassiveContainer] frame(s).
    MassiveHeader {
        count: u8,
        crc: u8,
        contained_opcode: u16,
        contained_count: u16,
    },
    /// The data container portion of a massive packet. Must come after
    /// a [SilkroadFrame::MassiveHeader]. Given the opcode and included
    /// count specified in the header frame, contains the data for `n`
    /// operations of the same opcode.
    MassiveContainer { count: u8, crc: u8, inner: Bytes },
}

impl SilkroadFrame {
    /// Tries to parse the first possible frame from the given data slice.
    /// In addition to the created frame, it will also return the size of
    /// consumed bytes by the frame. If not enough data is available, it
    /// will return [Err] with the bytes required to finish the frame.
    pub fn parse(data: &[u8]) -> Result<(usize, SilkroadFrame), usize> {
        if data.len() < 2 {
            return Err(2 - data.len());
        }

        let length = LittleEndian::read_u16(&data[0..2]);
        let encrypted = length & 0x8000 != 0;
        let content_size = (length & 0x7FFF) as usize;
        let total_size = if encrypted {
            find_encrypted_length(content_size + 4)
        } else {
            content_size + 4
        };

        if data.len() < (total_size + 2) {
            return Err((total_size + 2) - data.len());
        }

        let data = &data[2..];

        let final_length = total_size + 2;
        let data = Bytes::copy_from_slice(&data[0..total_size]);
        if encrypted {
            return Ok((
                final_length,
                SilkroadFrame::Encrypted {
                    content_size,
                    encrypted_data: data,
                },
            ));
        }

        Ok((final_length, Self::from_data(&data)))
    }

    /// Creates a [SilkroadFrame] given the received data. Generally, this will result
    /// in a [SilkroadFrame::Packet], unless we encounter a packet with the opcode
    /// `0x600D`, which is reserved for a massive packet, consisting of a
    /// [SilkroadFrame::MassiveHeader] and multiple [SilkroadFrame::MassiveContainer]s.
    ///
    /// This assumes the data is well-formed, i.e. first two bytes opcode, one byte
    /// security count, one byte crc, and the rest data. If the data represents a
    /// massive frame, it's also expected that the massive information has the
    /// correct format. In other cases, this will currently _panic_.
    pub fn from_data(data: &[u8]) -> SilkroadFrame {
        assert!(data.len() >= 4);
        let opcode = LittleEndian::read_u16(&data[0..2]);
        let count = data[2];
        let crc = data[3];

        if opcode == MASSIVE_PACKET_OPCODE {
            assert!(data.len() >= 5);
            let mode = data[4];
            if mode == 1 {
                assert!(data.len() >= 10);
                // 1 == Header
                let inner_amount = LittleEndian::read_u16(&data[5..7]);
                let inner_opcode = LittleEndian::read_u16(&data[7..9]);
                SilkroadFrame::MassiveHeader {
                    count,
                    crc,
                    contained_opcode: inner_opcode,
                    contained_count: inner_amount,
                }
            } else {
                SilkroadFrame::MassiveContainer {
                    count,
                    crc,
                    inner: Bytes::copy_from_slice(&data[5..]),
                }
            }
        } else {
            SilkroadFrame::Packet {
                count,
                crc,
                opcode,
                data: Bytes::copy_from_slice(&data[4..]),
            }
        }
    }

    /// Computes the size that should be used for the length header field.
    /// Depending on the type of frame this is either:
    /// - The size of the contained data (basic frame)
    /// - Encrypted size without header, but possibly padding (encrypted frame)
    /// - A fixed size (massive header frame)
    /// - Container and data size (massive container frame)
    pub fn content_size(&self) -> usize {
        match &self {
            SilkroadFrame::Packet { data, .. } => data.len(),
            SilkroadFrame::Encrypted { content_size, .. } => *content_size,
            SilkroadFrame::MassiveHeader { .. } => {
                // Massive headers have a fixed length because they're always:
                // 1 Byte 'is header', 2 Bytes 'amount of packets', 2 Bytes 'opcode', 1 Byte unknown
                6
            }
            SilkroadFrame::MassiveContainer { inner, .. } => {
                // 1 at the start to denote that this is container packet
                // 1 in each content to denote there's more
                1 + inner.len()
            }
        }
    }

    /// Computes the total size of the network packet for this frame.
    /// This is different from [Self::content_size] as it includes
    /// the size of the header as well as the correct size for
    /// encrypted packets.
    pub fn packet_size(&self) -> usize {
        match self {
            SilkroadFrame::Encrypted { content_size, .. } => {
                find_encrypted_length(*content_size + 4) + 2
            }
            _ => 6 + self.content_size(),
        }
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

    /// Tries to serialize this frame into a byte stream. It will allocate
    /// a buffer that matches the packet size into which it will serialize
    /// itself.
    pub fn serialize(&self) -> Bytes {
        let mut output = BytesMut::with_capacity(self.packet_size());

        match &self {
            SilkroadFrame::Packet {
                count,
                crc,
                opcode,
                data,
            } => {
                output.put_u16_le(self.content_size() as u16);
                output.put_u16_le(*opcode);
                output.put_u8(*count);
                output.put_u8(*crc);
                output.put_slice(data);
            }
            SilkroadFrame::Encrypted {
                content_size,
                encrypted_data,
            } => {
                output.put_u16_le((*content_size | 0x8000) as u16);
                output.put_slice(encrypted_data);
            }
            SilkroadFrame::MassiveHeader {
                count,
                crc,
                contained_opcode,
                contained_count,
            } => {
                output.put_u16_le(self.content_size() as u16);
                output.put_u16_le(MASSIVE_PACKET_OPCODE);
                output.put_u8(*count);
                output.put_u8(*crc);
                output.put_u8(1);
                output.put_u16_le(*contained_count);
                output.put_u16_le(*contained_opcode);
                output.put_u8(0);
            }
            SilkroadFrame::MassiveContainer { count, crc, inner } => {
                output.put_u16_le(self.content_size() as u16);
                output.put_u16_le(MASSIVE_PACKET_OPCODE);
                output.put_u8(*count);
                output.put_u8(*crc);
                output.put_u8(0);
                output.put_slice(inner);
            }
        }

        output.freeze()
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
    /// to serialize & deserialize the frames.
    pub struct SilkroadCodec;

    impl Encoder<SilkroadFrame> for SilkroadCodec {
        type Error = io::Error;

        fn encode(&mut self, item: SilkroadFrame, dst: &mut BytesMut) -> Result<(), Self::Error> {
            let bytes = item.serialize();
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
                }
                Err(_) => Ok(None),
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{SilkroadCodec, SilkroadFrame};
    use bytes::{Bytes, BytesMut};
    use tokio_util::codec::Decoder;

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
        let data = [0x00, 0x00, 0x00, 0x00, 0x00];
        let res = SilkroadFrame::parse(&data);
        assert!(matches!(res, Err(1)));

        let data = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00];
        let res = SilkroadFrame::parse(&data);
        assert!(matches!(res, Err(1)));
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

    #[test]
    fn test_serialize_empty() {
        let data = SilkroadFrame::Packet {
            count: 0,
            crc: 0,
            opcode: 0,
            data: Bytes::new(),
        }
        .serialize();
        assert_eq!(data.as_ref(), &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_serialize_encrypted() {
        let data = SilkroadFrame::Encrypted {
            content_size: 0,
            encrypted_data: Bytes::from_static(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
        }
        .serialize();
        assert_eq!(
            data.as_ref(),
            &[0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
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
        .serialize();
        assert_eq!(
            data.as_ref(),
            &[0x06, 0x00, 0x0D, 0x60, 0x00, 0x00, 0x01, 0x01, 0x00, 0x42, 0x00, 0x00]
        );

        let data = SilkroadFrame::MassiveContainer {
            count: 0,
            crc: 0,
            inner: Bytes::new(),
        }
        .serialize();
        assert_eq!(data.as_ref(), &[0x01, 0x00, 0x0D, 0x60, 0x00, 0x00, 0x00]);
    }
}
