use bytes::Bytes;
use futures::{SinkExt, Stream, StreamExt};
use skrillax_codec::{SilkroadCodec, SilkroadFrame};
use skrillax_packet::{
    AsFrames, FramingError, FromFrames, IncomingPacket, OutgoingPacket, Packet, PacketError,
    ReframingError, SecurityBytes, SecurityContext, TryFromPacket,
};
use skrillax_security::SilkroadEncryption;
use std::io;
use std::sync::Arc;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio_util::codec::{FramedRead, FramedWrite};

/// Errors for possible problems writing packets.
///
/// When writing packets to be sent over the wire, a few issues can appear,
/// which are represented by this error.
#[derive(Debug, Error)]
pub enum OutStreamError {
    /// Some I/O related issue occurred. This generally means the underlying
    /// transport layer was disconnected or otherwise impaired.
    #[error("Some IO level error occurred")]
    IoError(#[from] io::Error),
    /// Something went wrong when trying to create frame(s) for the packet.
    /// This currently can only happen if an encrypted frame is supposed to
    /// be built, but no encryption has been configured.
    #[error("Error occurred when trying to create frames")]
    Framing(#[from] FramingError),
}

/// Errors encountered when reading packets.
///
/// Unlike [OutStreamError], there are many more possibilities for an error
/// to occur here, due to accepting mostly untrusted input.
#[derive(Debug, Error)]
pub enum InStreamError {
    /// Something went wrong on the I/O layer.
    ///
    /// When the underlying transport layer was disconnected or had other
    /// issues while trying to read data, this error occurs.
    #[error("Some IO level error occurred")]
    IoError(#[from] io::Error),
    #[error("Error occurred at the packet level")]
    PacketError(#[from] PacketError),
    #[error("Error when trying to turn frames into packets")]
    ReframingError(#[from] ReframingError),
    /// The end of the stream was reached, but we expected more data.
    #[error("Reached the end of the stream")]
    EndOfStream,
    /// When trying to receive a specific packet or protocol, a different or
    /// unknown packet was received.
    #[error("Received unexpected opcode: {0:#06x}")]
    UnmatchedOpcode(u16),
}

/// An [InputProtocol] is a trait which can be used to deserialize a single
/// operation given its opcode. A protocol is assumed to support multiple
/// opcodes as it is assumed to be applicable to any operation present on
/// a stream. Generally, [InputProtocol::Proto] will be an enum to reflect
/// that fact.
pub trait InputProtocol {
    /// The type of all possible values we can create
    type Proto: Send;

    fn create_from(opcode: u16, data: &[u8]) -> Result<(usize, Self::Proto), InStreamError>;
}

impl<T: TryFromPacket + Packet + Send> InputProtocol for T {
    type Proto = T;

    fn create_from(opcode: u16, data: &[u8]) -> Result<(usize, T), InStreamError> {
        if opcode != T::ID {
            return Err(InStreamError::UnmatchedOpcode(opcode));
        }

        Ok(T::try_deserialize(data)?)
    }
}

/// Extensions to [TcpStream] to convert it into a silkroad stream, sending
/// and receiving silkroad packets.
pub trait SilkroadTcpExt {
    /// Creates a stream using the existing socket, wrapping it into a stream to
    /// read and write [IncomingPacket] & [OutgoingPacket].
    ///
    /// ```
    /// # use std::error::Error;
    /// use skrillax_stream::stream::SilkroadTcpExt;
    ///
    /// # async fn test() -> Result<(), Box<dyn Error>> {
    /// # use tokio::net::TcpStream;
    /// let stream = TcpStream::connect("127.0.0.1:1337").await?;
    /// let (reader, writer) = stream.into_silkroad_stream();
    /// # Ok(())
    /// # }
    /// ```
    fn into_silkroad_stream(
        self,
    ) -> (
        SilkroadStreamRead<OwnedReadHalf>,
        SilkroadStreamWrite<OwnedWriteHalf>,
    );
}

impl SilkroadTcpExt for TcpStream {
    fn into_silkroad_stream(
        self,
    ) -> (
        SilkroadStreamRead<OwnedReadHalf>,
        SilkroadStreamWrite<OwnedWriteHalf>,
    ) {
        let (read, write) = self.into_split();
        let reader = FramedRead::new(read, SilkroadCodec);
        let writer = FramedWrite::new(write, SilkroadCodec);

        let stream_reader = SilkroadStreamRead::new(reader);
        let stream_writer = SilkroadStreamWrite::new(writer);

        (stream_reader, stream_writer)
    }
}

/// The writing side of a Silkroad Online connection.
///
/// This is an analog to [OwnedWriteHalf], containing additional state to
/// facilitate a Silkroad connection, such as encryption.
pub struct SilkroadStreamWrite<T: AsyncWrite + Unpin> {
    writer: FramedWrite<T, SilkroadCodec>,
    encryption: Option<Arc<SilkroadEncryption>>,
    security_bytes: Option<Arc<SecurityBytes>>,
}

impl<T: AsyncWrite + Unpin> SilkroadStreamWrite<T> {
    fn new(writer: FramedWrite<T, SilkroadCodec>) -> Self {
        Self {
            writer,
            encryption: None,
            security_bytes: None,
        }
    }

    #[allow(unused)]
    fn with_encryption(
        writer: FramedWrite<T, SilkroadCodec>,
        encryption: Arc<SilkroadEncryption>,
        security_bytes: Arc<SecurityBytes>,
    ) -> Self {
        Self {
            writer,
            encryption: Some(encryption),
            security_bytes: Some(security_bytes),
        }
    }

    pub fn enable_encryption(&mut self, encryption: Arc<SilkroadEncryption>) {
        self.encryption = Some(encryption);
    }

    pub fn enable_security_checks(&mut self, security_bytes: Arc<SecurityBytes>) {
        self.security_bytes = Some(security_bytes);
    }

    pub fn encryption(&self) -> Option<&SilkroadEncryption> {
        self.encryption.as_deref()
    }

    pub fn security_bytes(&self) -> Option<&SecurityBytes> {
        self.security_bytes.as_deref()
    }

    pub fn security_context(&self) -> SecurityContext {
        SecurityContext::new(self.encryption(), self.security_bytes())
    }

    pub async fn write(&mut self, packet: OutgoingPacket) -> Result<(), OutStreamError> {
        let frames = packet.as_frames(self.security_context())?;
        for frame in frames {
            self.writer.send(frame).await?;
        }
        Ok(())
    }

    pub async fn write_packet<S: Into<OutgoingPacket>>(
        &mut self,
        packet: S,
    ) -> Result<(), OutStreamError> {
        let outgoing_packet = packet.into();
        self.write(outgoing_packet).await
    }
}

/// The reading side of a Silkroad Online connection.
///
/// This is an analog to [OwnedReadHalf], containing additional state to
/// facilitate a Silkroad connection, such as encryption.
pub struct SilkroadStreamRead<T: AsyncRead + Unpin> {
    reader: FramedRead<T, SilkroadCodec>,
    encryption: Option<Arc<SilkroadEncryption>>,
    security_bytes: Option<Arc<SecurityBytes>>,
    unconsumed: Option<(u16, Bytes)>,
}

impl<T: AsyncRead + Unpin> SilkroadStreamRead<T>
where
    FramedRead<T, SilkroadCodec>: Stream<Item = Result<SilkroadFrame, io::Error>>,
{
    fn new(reader: FramedRead<T, SilkroadCodec>) -> Self {
        Self {
            reader,
            encryption: None,
            security_bytes: None,
            unconsumed: None,
        }
    }

    #[allow(unused)]
    fn with_encryption(
        reader: FramedRead<T, SilkroadCodec>,
        encryption: Arc<SilkroadEncryption>,
        security_bytes: Arc<SecurityBytes>,
    ) -> Self {
        Self {
            reader,
            encryption: Some(encryption),
            security_bytes: Some(security_bytes),
            unconsumed: None,
        }
    }

    /// Enables encryption for this stream.
    ///
    /// Upon starting a connection, a stream will not be encrypted. Only after
    /// the handshake is finished will the encryption be present. This should
    /// generally be set implicitly by the handshake protocol, but it is
    /// possible to manually configure it.
    ///
    /// An [Arc] is expected here because it is assumed that the same encryption
    /// will be set on the write half as well.
    pub fn enable_encryption(&mut self, encryption: Arc<SilkroadEncryption>) {
        self.encryption = Some(encryption);
    }

    /// Enables additional security checks for this stream.
    ///
    /// In addition to encryption, there are additional security checks
    /// available on packets. In particular this is the counter and CRC
    /// checksum.
    ///
    /// An [Arc] is expected here because it is assumed that the same encryption
    /// will be set on the write half as well.
    pub fn enable_security_checks(&mut self, security_bytes: Arc<SecurityBytes>) {
        self.security_bytes = Some(security_bytes);
    }

    /// Provides the currently set encryption configuration, if present.
    pub fn encryption(&self) -> Option<&SilkroadEncryption> {
        self.encryption.as_deref()
    }

    /// Provides the currently set security data, if present.
    pub fn security_bytes(&self) -> Option<&SecurityBytes> {
        self.security_bytes.as_deref()
    }

    /// Provides the security context present for the reader.
    ///
    /// This will always return a new context with the
    /// [SilkroadStreamRead::encryption] and
    /// [SilkroadStreamRead::security_bytes] data inside. Essentially, this
    /// is a convenience wrapper around those functions to provide
    /// a single struct that can be passed around.
    pub fn security_context(&self) -> SecurityContext {
        SecurityContext::new(self.encryption(), self.security_bytes())
    }

    /// Read the next packet and handle re-framing.
    ///
    /// [skrillax_codec] deals on single packets (i.e., frames), and some
    /// packets may span multiple frames. It does not attempt to collect
    /// those frames where appropriate and instead pushes the problem up the
    /// abstraction chain. Thus, at the current abstraction level we're
    /// performing this merging of frames into logical packets. Thus, it is
    /// possible the resulting [IncomingPacket] is actually a massive packet
    /// containing multiple operations inside it. At this point we can't
    /// split that into the individual operations because we don't know the
    /// length of those operations.
    ///
    /// This should only be necessary if you're not interested in actual packet
    /// data or work really generically. Otherwise,
    /// [SilkroadStreamRead::next_packet] should be used instead.
    pub async fn next(&mut self) -> Result<IncomingPacket, InStreamError> {
        let mut buffer = Vec::new();
        let mut remaining = 1usize;
        while let Some(res) = self.reader.next().await {
            let frame = res?;
            buffer.push(frame);
            remaining -= 1;
            if remaining == 0 {
                match IncomingPacket::from_frames(&buffer, self.security_context()) {
                    Ok(packet) => return Ok(packet),
                    Err(ReframingError::Incomplete(required)) => {
                        remaining += required.unwrap_or(1);
                    },
                    Err(e) => return Err(InStreamError::ReframingError(e)),
                }
            }
        }

        Err(InStreamError::EndOfStream)
    }

    /// Tries to serialize the next incoming packet into the given protocol.
    ///
    /// This will poll the underlying transport layer to read a new packet
    /// and will then try to serialize into a matching packet of the given
    /// protocol. We expect that all packets are part of the given protocol,
    /// otherwise it will be _discarded_ and [InStreamError::UnmatchedOpcode]
    /// will be returned.
    ///
    /// Since [InputProtocol] is automatically derived for structs that have
    /// [skrillax_packet::Packet] & [skrillax_serde::Deserialize], you can
    /// both expect a single packet and a full protocol here.
    pub async fn next_packet<S: InputProtocol>(&mut self) -> Result<S::Proto, InStreamError> {
        let (opcode, mut buffer) = match self.unconsumed.take() {
            Some(inner) => inner,
            _ => self.next().await?.consume(),
        };

        let (consumed, p) = S::create_from(opcode, &buffer)?;
        let _ = buffer.split_to(consumed);
        if !buffer.is_empty() {
            self.unconsumed = Some((opcode, buffer));
        }

        Ok(p)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use skrillax_serde::{ByteSize, Deserialize, Serialize};

    #[derive(Packet, Deserialize, Serialize, ByteSize)]
    #[packet(opcode = 0x0042)]
    struct Empty;

    #[tokio::test]
    pub async fn test_read_packet_from_stream() {
        let buffer: &[u8] = &[0x00, 0x00, 0x42, 0x00, 0x00, 0x00];
        let mut reader = SilkroadStreamRead::new(FramedRead::new(buffer, SilkroadCodec));
        let _ = reader
            .next_packet::<Empty>()
            .await
            .expect("Should read empty packet.");
    }

    #[tokio::test]
    pub async fn test_write_packet_to_stream() {
        let mut buffer: Vec<u8> = Vec::new();
        let mut writer = SilkroadStreamWrite::new(FramedWrite::new(&mut buffer, SilkroadCodec));
        writer
            .write_packet(Empty)
            .await
            .expect("Should write empty packet.");
        drop(writer);
        let content: &[u8] = &buffer;
        assert_eq!(&[0x00u8, 0x00, 0x42, 0x00, 0x00, 0x00], content);
    }
}
