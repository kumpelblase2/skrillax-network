use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use skrillax_codec::SilkroadCodec;
use skrillax_packet::{
    AsFrames, FromFrames, IncomingPacket, OutgoingPacket, PacketError, ReframingError,
    TryFromPacket, TryIntoPacket,
};
use skrillax_security::EstablishedSecurity;
use std::sync::Arc;
use thiserror::Error;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio_util::codec::{FramedRead, FramedWrite};

#[derive(Debug, Error)]
pub enum StreamError {
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
    pub(crate) writer: FramedWrite<OwnedWriteHalf, SilkroadCodec>,
    pub(crate) encryption: Option<Arc<EstablishedSecurity>>,
}

impl SilkroadStreamWrite {
    fn new(writer: FramedWrite<OwnedWriteHalf, SilkroadCodec>) -> Self {
        Self {
            writer,
            encryption: None,
        }
    }

    fn with_encryption(
        writer: FramedWrite<OwnedWriteHalf, SilkroadCodec>,
        encryption: Arc<EstablishedSecurity>,
    ) -> Self {
        Self {
            writer,
            encryption: Some(encryption),
        }
    }

    pub fn enable_encryption(&mut self, encryption: Arc<EstablishedSecurity>) {
        self.encryption = Some(encryption);
    }

    pub async fn write(&mut self, packet: OutgoingPacket) -> Result<(), StreamError> {
        let frames = packet.as_frames(self.encryption.as_ref().map(Arc::as_ref))?;
        for frame in frames {
            self.writer
                .send(frame)
                .await
                .map_err(|f| StreamError::PacketError(PacketError::FrameError(f)))?;
        }
        Ok(())
    }

    pub async fn send<T: TryIntoPacket>(&mut self, packet: T) -> Result<(), StreamError> {
        self.write(packet.serialize()).await
    }
}

pub struct SilkroadStreamRead {
    reader: FramedRead<OwnedReadHalf, SilkroadCodec>,
    encryption: Option<Arc<EstablishedSecurity>>,
    unconsumed: Option<(u16, Bytes)>,
}

impl SilkroadStreamRead {
    fn new(reader: FramedRead<OwnedReadHalf, SilkroadCodec>) -> Self {
        Self {
            reader,
            encryption: None,
            unconsumed: None,
        }
    }

    fn with_encryption(
        reader: FramedRead<OwnedReadHalf, SilkroadCodec>,
        encryption: Arc<EstablishedSecurity>,
    ) -> Self {
        Self {
            reader,
            encryption: Some(encryption),
            unconsumed: None,
        }
    }

    pub fn enable_encryption(&mut self, encryption: Arc<EstablishedSecurity>) {
        self.encryption = Some(encryption);
    }

    pub async fn next(&mut self) -> Result<IncomingPacket, StreamError> {
        let mut buffer = Vec::new();
        let mut remaining = 1usize;
        while let Some(res) = self.reader.next().await {
            let frame = res.map_err(PacketError::FrameError)?;
            buffer.push(frame);
            remaining -= 1;
            if remaining == 0 {
                match IncomingPacket::from_frames(
                    &buffer,
                    self.encryption.as_ref().map(Arc::as_ref),
                ) {
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
