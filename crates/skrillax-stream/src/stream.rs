use crate::context::{LastReceivedPacket, LastSentPacket};
use crate::registry::PacketRegistry;
use bytes::Bytes;
use futures::{SinkExt, Stream, StreamExt};
use skrillax_codec::{SilkroadCodec, SilkroadFrame};
use skrillax_packet::{
    AsFrames, FramingError, FromFrames, IncomingPacket, OutgoingPacket, Packet, PacketError,
    ReframingError, SecurityBytes, SecurityContext,
};
use skrillax_security::SilkroadEncryption;
use skrillax_serde::SerdeContext;
use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
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
    #[error("Opcode {0} was not registered.")]
    UnknownOpcode(u16),
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
    #[error("Some IO level error occurred. {0:?}")]
    IoError(#[from] io::Error),
    #[error("Error occurred at the packet level. {0:?}")]
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

/// Extensions to [TcpStream] to convert it into a silkroad stream, sending
/// and receiving silkroad packets.
pub trait SilkroadTcpExt {
    /// Creates a stream using the existing socket, wrapping it into a stream to
    /// read and write [IncomingPacket] & [OutgoingPacket].
    ///
    /// ```
    /// # use std::error::Error;
    /// # use skrillax_stream::registry::PacketRegistry;
    /// use skrillax_stream::stream::SilkroadTcpExt;
    ///
    /// # async fn test() -> Result<(), Box<dyn Error>> {
    /// # use tokio::net::TcpStream;
    /// let stream = TcpStream::connect("127.0.0.1:1337").await?;
    /// let registry = PacketRegistry::builder().build();
    /// let (reader, writer) = stream.into_silkroad_stream(registry);
    /// # Ok(())
    /// # }
    /// ```
    fn into_silkroad_stream(
        self,
        registry: PacketRegistry,
    ) -> (
        SilkroadStreamRead<OwnedReadHalf>,
        SilkroadStreamWrite<OwnedWriteHalf>,
    );
}

impl SilkroadTcpExt for TcpStream {
    fn into_silkroad_stream(
        self,
        registry: PacketRegistry,
    ) -> (
        SilkroadStreamRead<OwnedReadHalf>,
        SilkroadStreamWrite<OwnedWriteHalf>,
    ) {
        let (read, write) = self.into_split();
        let reader = FramedRead::new(read, SilkroadCodec);
        let writer = FramedWrite::new(write, SilkroadCodec);

        let state = SharedState::new();
        let stream_reader = SilkroadStreamRead::new(reader, registry.clone(), state.clone());
        let stream_writer = SilkroadStreamWrite::new(writer, registry, state);

        (stream_reader, stream_writer)
    }
}

pub struct DynamicPacket(pub(crate) Box<dyn Any + Send>);

impl Debug for DynamicPacket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "dynamic packet")
    }
}

impl DynamicPacket {
    pub fn as_packet<T: 'static>(&self) -> Option<&T> {
        self.0.downcast_ref()
    }

    pub fn into_packet<T: 'static>(self) -> Result<T, DynamicPacket> {
        match self.0.downcast::<T>() {
            Ok(b) => Ok(*b),
            Err(b) => Err(DynamicPacket(b)),
        }
    }

    pub fn packet_type(&self) -> TypeId {
        self.0.as_ref().type_id()
    }
}

#[derive(Default, Clone)]
struct SharedState {
    encryption: Option<Arc<SilkroadEncryption>>,
    security_bytes: Option<Arc<SecurityBytes>>,
    state: SerdeContext,
}

impl SharedState {
    fn new() -> Self {
        Self {
            encryption: None,
            security_bytes: None,
            state: SerdeContext::default(),
        }
    }

    fn as_context(&self) -> SerdeContext {
        self.state.clone()
    }

    pub fn set_last_received(&self, opcode: u16) {
        self.state.set(LastReceivedPacket(opcode))
    }

    pub fn set_last_sent(&self, opcode: u16) {
        self.state.set(LastSentPacket(opcode))
    }
}

#[derive(Default)]
struct WriteCallbacks {
    before_write_frame: Vec<Box<dyn Fn(&OutgoingPacket, &SerdeContext) + Send>>,
    before_write_packet: HashMap<TypeId, Box<dyn Fn(&DynamicPacket, &SerdeContext) + Send>>,
}

impl WriteCallbacks {
    fn register_frame_callback<F: Fn(&OutgoingPacket, &SerdeContext) + Send + 'static>(
        &mut self,
        func: F,
    ) {
        self.before_write_frame.push(Box::new(func));
    }

    fn call_for_frame(&self, packet: &OutgoingPacket, context: &SerdeContext) {
        for handler in &self.before_write_frame {
            handler(packet, context);
        }
    }

    fn register_packet_callback<T: 'static, F: Fn(&T, &SerdeContext) + Send + 'static>(
        &mut self,
        func: F,
    ) {
        let type_id = TypeId::of::<T>();
        let wrapper = Box::new(move |any_packet: &DynamicPacket, ctx: &SerdeContext| {
            let packet = any_packet
                .as_packet::<T>()
                .expect("T should match it's type id");
            func(packet, ctx);
        });
        self.before_write_packet.insert(type_id, wrapper);
    }

    fn call_for_packet(&self, packet: &DynamicPacket, context: &SerdeContext) {
        let Some(handler) = self.before_write_packet.get(&packet.packet_type()) else {
            return;
        };

        handler(packet, context);
    }
}

/// The writing side of a Silkroad Online connection.
///
/// This is an analog to [OwnedWriteHalf], containing additional state to
/// facilitate a Silkroad connection, such as encryption.
pub struct SilkroadStreamWrite<T: AsyncWrite + Unpin> {
    writer: FramedWrite<T, SilkroadCodec>,
    registry: PacketRegistry,
    state: SharedState,
    write_callbacks: WriteCallbacks,
}

impl<T: AsyncWrite + Unpin> SilkroadStreamWrite<T> {
    fn new(
        writer: FramedWrite<T, SilkroadCodec>,
        registry: PacketRegistry,
        state: SharedState,
    ) -> Self {
        Self {
            writer,
            state,
            registry,
            write_callbacks: WriteCallbacks::default(),
        }
    }

    #[allow(unused)]
    fn with_encryption(
        writer: FramedWrite<T, SilkroadCodec>,
        registry: PacketRegistry,
        encryption: Arc<SilkroadEncryption>,
        security_bytes: Arc<SecurityBytes>,
    ) -> Self {
        Self {
            writer,
            registry,
            state: SharedState {
                encryption: Some(encryption),
                security_bytes: Some(security_bytes),
                state: SerdeContext::default(),
            },
            write_callbacks: WriteCallbacks::default(),
        }
    }

    pub fn enable_encryption(&mut self, encryption: Arc<SilkroadEncryption>) {
        self.state.encryption = Some(encryption);
    }

    pub fn enable_security_checks(&mut self, security_bytes: Arc<SecurityBytes>) {
        self.state.security_bytes = Some(security_bytes);
    }

    pub fn on_before_write<F: Fn(&OutgoingPacket, &SerdeContext) + Send + 'static>(
        &mut self,
        f: F,
    ) {
        self.write_callbacks.register_frame_callback(f);
    }

    pub fn on_before_send<P: Packet + 'static, F: Fn(&P, &SerdeContext) + Send + 'static>(
        &mut self,
        f: F,
    ) {
        self.write_callbacks.register_packet_callback(f);
    }

    pub fn encryption(&self) -> Option<&SilkroadEncryption> {
        self.state.encryption.as_deref()
    }

    pub fn security_bytes(&self) -> Option<&SecurityBytes> {
        self.state.security_bytes.as_deref()
    }

    pub fn security_context(&self) -> SecurityContext<'_> {
        SecurityContext::new(self.encryption(), self.security_bytes())
    }

    pub async fn write(&mut self, packet: OutgoingPacket) -> Result<(), OutStreamError> {
        self.state.set_last_sent(packet.opcode());
        let frames = packet.as_frames(self.security_context())?;
        for frame in frames {
            self.writer.send(frame).await?;
        }
        Ok(())
    }

    pub async fn write_packet<S: Packet + Send + 'static>(
        &mut self,
        packet: S,
    ) -> Result<(), OutStreamError> {
        let context = self.state.as_context();
        let packet = DynamicPacket(Box::new(packet));
        self.write_callbacks.call_for_packet(&packet, &context);
        let opcode = S::ID;
        let outgoing_packet = self.registry.encode(opcode, packet, &context)?;
        self.write_callbacks
            .call_for_frame(&outgoing_packet, &context);
        self.write(outgoing_packet).await
    }

    pub fn context(&self) -> SerdeContext {
        self.state.as_context()
    }
}

#[derive(Default)]
struct ReadCallbacks {
    after_read_frame: Vec<Box<dyn Fn(&IncomingPacket, &SerdeContext) + Send + 'static>>,
    after_read_packet: HashMap<TypeId, Box<dyn Fn(&DynamicPacket, &SerdeContext) + Send + 'static>>,
}

impl ReadCallbacks {
    fn register_frame_callback<F: Fn(&IncomingPacket, &SerdeContext) + Send + 'static>(
        &mut self,
        func: F,
    ) {
        self.after_read_frame.push(Box::new(func));
    }

    fn call_for_frame(&self, packet: &IncomingPacket, context: &SerdeContext) {
        for handler in &self.after_read_frame {
            handler(packet, context);
        }
    }

    fn register_packet_callback<T: 'static, F: Fn(&T, &SerdeContext) + Send + 'static>(
        &mut self,
        func: F,
    ) {
        let type_id = TypeId::of::<T>();
        let wrapper = Box::new(move |any_packet: &DynamicPacket, ctx: &SerdeContext| {
            let packet = any_packet
                .as_packet::<T>()
                .expect("T should match it's type id");
            func(packet, ctx);
        });
        self.after_read_packet.insert(type_id, wrapper);
    }

    fn call_for_packet(&self, packet: &DynamicPacket, context: &SerdeContext) {
        let Some(handler) = self.after_read_packet.get(&packet.packet_type()) else {
            return;
        };

        handler(packet, context);
    }
}

/// The reading side of a Silkroad Online connection.
///
/// This is an analog to [OwnedReadHalf], containing additional state to
/// facilitate a Silkroad connection, such as encryption.
pub struct SilkroadStreamRead<T: AsyncRead + Unpin> {
    reader: FramedRead<T, SilkroadCodec>,
    registry: PacketRegistry,
    state: SharedState,
    unconsumed: Option<(u16, Bytes)>,
    read_callbacks: ReadCallbacks,
}

impl<T: AsyncRead + Unpin> SilkroadStreamRead<T>
where
    FramedRead<T, SilkroadCodec>: Stream<Item = Result<SilkroadFrame, io::Error>>,
{
    fn new(
        reader: FramedRead<T, SilkroadCodec>,
        registry: PacketRegistry,
        state: SharedState,
    ) -> Self {
        Self {
            reader,
            state,
            registry,
            unconsumed: None,
            read_callbacks: ReadCallbacks::default(),
        }
    }

    #[allow(unused)]
    fn with_encryption(
        reader: FramedRead<T, SilkroadCodec>,
        registry: PacketRegistry,
        encryption: Arc<SilkroadEncryption>,
        security_bytes: Arc<SecurityBytes>,
        state: SerdeContext,
    ) -> Self {
        Self {
            reader,
            registry,
            state: SharedState {
                encryption: Some(encryption),
                security_bytes: Some(security_bytes),
                state,
            },
            unconsumed: None,
            read_callbacks: ReadCallbacks::default(),
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
        self.state.encryption = Some(encryption);
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
        self.state.security_bytes = Some(security_bytes);
    }

    /// Provides the currently set encryption configuration, if present.
    pub fn encryption(&self) -> Option<&SilkroadEncryption> {
        self.state.encryption.as_deref()
    }

    /// Provides the currently set security data, if present.
    pub fn security_bytes(&self) -> Option<&SecurityBytes> {
        self.state.security_bytes.as_deref()
    }

    /// Provides the security context present for the reader.
    ///
    /// This will always return a new context with the
    /// [SilkroadStreamRead::encryption] and
    /// [SilkroadStreamRead::security_bytes] data inside. Essentially, this
    /// is a convenience wrapper around those functions to provide
    /// a single struct that can be passed around.
    pub fn security_context(&self) -> SecurityContext<'_> {
        SecurityContext::new(self.encryption(), self.security_bytes())
    }

    pub fn on_after_read<F: Fn(&IncomingPacket, &SerdeContext) + Send + 'static>(&mut self, f: F) {
        self.read_callbacks.register_frame_callback(f);
    }

    pub fn on_after_receive<P: Packet + 'static, F: Fn(&P, &SerdeContext) + Send + 'static>(
        &mut self,
        f: F,
    ) {
        self.read_callbacks.register_packet_callback(f);
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
                    Ok(packet) => {
                        self.read_callbacks.call_for_frame(&packet, &self.context());
                        return Ok(packet);
                    },
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
    pub async fn next_packet(&mut self) -> Result<DynamicPacket, InStreamError> {
        let (opcode, mut buffer) = match self.unconsumed.take() {
            Some(inner) => inner,
            _ => self.next().await?.consume(),
        };

        let context = self.context();
        let (consumed, p) = self.registry.decode(opcode, &buffer, &context)?;
        let _ = buffer.split_to(consumed);
        if !buffer.is_empty() {
            self.unconsumed = Some((opcode, buffer));
        }

        self.read_callbacks.call_for_packet(&p, &context);
        self.state.set_last_received(opcode);
        Ok(p)
    }

    pub fn context(&self) -> SerdeContext {
        self.state.as_context()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use skrillax_serde::{ByteSize, Deserialize, Serialize};

    #[derive(Copy, Clone, Default)]
    struct CustomFlag(u8);

    #[derive(Packet, Deserialize, Serialize, ByteSize)]
    #[packet(opcode = 0x0042)]
    struct Empty;

    #[derive(Packet, Deserialize, Serialize, ByteSize)]
    #[packet(opcode = 0x0043)]
    #[silkroad(size = 0)]
    enum Conditional {
        // Ordering matters when using when given that it's just `if` clauses.
        #[silkroad(when = "ctx.get::<CustomFlag>().unwrap_or_default().0 == 1")]
        Third(u8),
        #[silkroad(when = "crate::context::last_sent_packet_is(ctx, 0x0042)")]
        First(u8),
        #[silkroad(when = "crate::context::last_sent_packet_is(ctx, 0x0043)")]
        Second(u8),
    }

    #[tokio::test]
    pub async fn test_read_packet_from_stream() {
        let buffer: &[u8] = &[0x00, 0x00, 0x42, 0x00, 0x00, 0x00];
        let registry = PacketRegistry::builder().register::<Empty>().build();
        let mut reader = SilkroadStreamRead::new(
            FramedRead::new(buffer, SilkroadCodec),
            registry,
            SharedState::new(),
        );
        let p = reader
            .next_packet()
            .await
            .expect("Should read empty packet.");
        assert!(p.into_packet::<Empty>().is_ok());
    }

    #[tokio::test]
    pub async fn test_write_packet_to_stream() {
        let mut buffer: Vec<u8> = Vec::new();
        let mut writer = SilkroadStreamWrite::new(
            FramedWrite::new(&mut buffer, SilkroadCodec),
            PacketRegistry::builder().register::<Empty>().build(),
            SharedState::new(),
        );
        writer
            .write_packet(Empty)
            .await
            .expect("Should write empty packet.");
        drop(writer);
        let content: &[u8] = &buffer;
        assert_eq!(&[0x00u8, 0x00, 0x42, 0x00, 0x00, 0x00], content);
    }

    #[tokio::test]
    pub async fn test_context_received_sent() {
        let mut buffer: Vec<u8> = Vec::new();
        let state = SharedState::default();
        let registry = PacketRegistry::builder()
            .register::<Empty>()
            .register::<Conditional>()
            .build();
        let mut writer = SilkroadStreamWrite::new(
            FramedWrite::new(&mut buffer, SilkroadCodec),
            registry.clone(),
            state.clone(),
        );

        // First, write the Empty packet to set last_sent
        writer
            .write_packet(Empty)
            .await
            .expect("Should write Empty packet");

        assert_eq!(
            writer
                .context()
                .get::<LastSentPacket>()
                .unwrap_or_default()
                .0,
            0x0042
        );

        let test_buffer: &[u8] = &[
            // First one should end up with Conditional::First(0x42)
            0x01, 0x00, 0x43, 0x00, 0x00, 0x00, 0x42,
            // Second one should end up with Conditional::Second(0x42)
            0x01, 0x00, 0x43, 0x00, 0x00, 0x00, 0x42,
            // Third one should end up with Conditional::Third(0x42)
            0x01, 0x00, 0x43, 0x00, 0x00, 0x00, 0x42,
        ];
        let mut reader = SilkroadStreamRead::new(
            FramedRead::new(test_buffer, SilkroadCodec),
            registry,
            state.clone(),
        );
        let cond = reader.next_packet().await.expect("Should read Conditional");
        assert!(matches!(
            cond.into_packet::<Conditional>(),
            Ok(Conditional::First(0x42))
        ));

        writer
            .write_packet(Conditional::First(1))
            .await
            .expect("Should be able to send packet");
        assert_eq!(
            writer
                .context()
                .get::<LastSentPacket>()
                .unwrap_or_default()
                .0,
            0x0043
        );
        let cond = reader.next_packet().await.expect("Should read Conditional");
        assert!(matches!(
            cond.into_packet::<Conditional>(),
            Ok(Conditional::Second(0x42))
        ));

        state.state.set(CustomFlag(1));
        let cond = reader.next_packet().await.expect("Should read Conditional");
        assert!(matches!(
            cond.into_packet::<Conditional>(),
            Ok(Conditional::Third(0x42))
        ));
    }
}
