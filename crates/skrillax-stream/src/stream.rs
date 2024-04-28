use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use skrillax_codec::SilkroadCodec;
use skrillax_packet::{
    AsFrames, FromFrames, IncomingPacket, OutgoingPacket, PacketError, ReframingError,
    SecurityBytes, SecurityContext, TryFromPacket, TryIntoPacket,
};
use skrillax_security::SilkroadEncryption;
use std::io;
use std::sync::Arc;
use thiserror::Error;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio_util::codec::{FramedRead, FramedWrite};

#[derive(Debug, Error)]
pub enum StreamError {
    #[error("Some IO level error occurred")]
    IoError(#[from] io::Error),
    #[error("Error occurred at the packet level")]
    PacketError(#[from] PacketError),
    #[error("Error when trying to turn frames into packets")]
    ReframingError(#[from] ReframingError),
    #[error("Reached the end of the stream")]
    EndOfStream,
}

/// Extensions to [TcpStream] to convert it into a silkroad stream, sending
/// and receiving silkroad packets.
pub trait SilkroadTcpExt {
    /// Creates an actively encrypted stream, in other words a stream which will
    /// prefer to set up encryption. This is the case for most client originating
    /// streams.
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
    fn into_silkroad_stream(self) -> (SilkroadStreamRead, SilkroadStreamWrite);
}

impl SilkroadTcpExt for TcpStream {
    fn into_silkroad_stream(self) -> (SilkroadStreamRead, SilkroadStreamWrite) {
        let (read, write) = self.into_split();
        let reader = FramedRead::new(read, SilkroadCodec);
        let writer = FramedWrite::new(write, SilkroadCodec);

        let stream_reader = SilkroadStreamRead::new(reader);
        let stream_writer = SilkroadStreamWrite::new(writer);

        (stream_reader, stream_writer)
    }
}

pub struct SilkroadStreamWrite {
    writer: FramedWrite<OwnedWriteHalf, SilkroadCodec>,
    encryption: Option<Arc<SilkroadEncryption>>,
    security_bytes: Option<Arc<SecurityBytes>>,
}

impl SilkroadStreamWrite {
    fn new(writer: FramedWrite<OwnedWriteHalf, SilkroadCodec>) -> Self {
        Self {
            writer,
            encryption: None,
            security_bytes: None,
        }
    }

    #[allow(unused)]
    fn with_encryption(
        writer: FramedWrite<OwnedWriteHalf, SilkroadCodec>,
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

    pub async fn write(&mut self, packet: OutgoingPacket) -> Result<(), StreamError> {
        let frames = packet.as_frames(self.security_context())?;
        for frame in frames {
            self.writer.send(frame).await?;
        }
        Ok(())
    }

    pub async fn send<T: TryIntoPacket>(&mut self, packet: T) -> Result<(), StreamError> {
        self.write(packet.serialize()).await
    }
}

pub struct SilkroadStreamRead {
    reader: FramedRead<OwnedReadHalf, SilkroadCodec>,
    encryption: Option<Arc<SilkroadEncryption>>,
    security_bytes: Option<Arc<SecurityBytes>>,
    unconsumed: Option<(u16, Bytes)>,
}

impl SilkroadStreamRead {
    fn new(reader: FramedRead<OwnedReadHalf, SilkroadCodec>) -> Self {
        Self {
            reader,
            encryption: None,
            security_bytes: None,
            unconsumed: None,
        }
    }

    #[allow(unused)]
    fn with_encryption(
        reader: FramedRead<OwnedReadHalf, SilkroadCodec>,
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

    pub async fn next(&mut self) -> Result<IncomingPacket, StreamError> {
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
                    }
                    Err(e) => return Err(StreamError::ReframingError(e)),
                }
            }
        }

        Err(StreamError::EndOfStream)
    }

    pub async fn next_packet<T: TryFromPacket>(&mut self) -> Result<T, StreamError> {
        let (opcode, mut buffer) = match self.unconsumed.take() {
            Some(inner) => inner,
            _ => self.next().await?.consume(),
        };

        let (consumed, p) = T::try_deserialize(opcode, &buffer)?;
        let _ = buffer.split_to(consumed);
        if !buffer.is_empty() {
            self.unconsumed = Some((opcode, buffer));
        }

        Ok(p)
    }
}
