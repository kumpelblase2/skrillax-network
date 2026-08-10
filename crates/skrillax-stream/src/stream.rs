use crate::context::{LastReceivedPacket, LastSentPacket};
use crate::registry::PacketRegistry;
use bytes::Bytes;
use futures::{SinkExt, Stream, StreamExt};
use skrillax_codec::{SilkroadCodec, SilkroadFrame};
use skrillax_packet::{
    AsFrames, FramingError, IncomingPacket, IncomingPacketReframer, OutgoingPacket, Packet,
    PacketError, ReframingError, ReframingLimits, SecurityBytes, SecurityContext,
};
use skrillax_security::SilkroadEncryption;
use skrillax_serde::SerdeContext;
use std::any::{Any, TypeId, type_name};
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::io;
use std::sync::Arc;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
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
    /// Something went wrong when trying to create frame(s) for the packet,
    /// such as missing encryption or an unrepresentable frame length.
    #[error("Error occurred when trying to create frames")]
    Framing(#[from] FramingError),
    /// Packet construction failed, including serialization errors. This occurs
    /// before the packet is framed or written to the transport.
    #[error("An error occurred at the packet level")]
    PacketError(#[from] PacketError),
    #[error("Opcode {0} was not registered.")]
    UnknownOpcode(u16),
    /// A dynamically typed packet did not contain the type registered for its
    /// opcode.
    #[error(transparent)]
    DynamicPacketType(#[from] DynamicPacketTypeError),
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
    /// A previous reframing failure consumed part of a logical packet, so the
    /// stream can no longer recover packet boundaries safely.
    #[error("The incoming stream cannot continue after a reframing failure")]
    ReframingTerminated,
    /// The end of the stream was reached, but we expected more data.
    #[error("Reached the end of the stream")]
    EndOfStream,
    /// When trying to receive a specific packet or protocol, a different or
    /// unknown packet was received.
    #[error("Received unexpected opcode: {0:#06x}")]
    UnmatchedOpcode(u16),
    /// A dynamically typed packet did not contain the type selected for its
    /// callback.
    #[error(transparent)]
    DynamicPacketType(#[from] DynamicPacketTypeError),
    /// A packet decoder reported a byte count that cannot advance safely
    /// through the supplied input.
    #[error(
        "Decoder for opcode {opcode:#06x} consumed {consumed} bytes from an {available}-byte input"
    )]
    InvalidPacketConsumption {
        opcode: u16,
        consumed: usize,
        available: usize,
    },
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
    /// let registry = PacketRegistry::builder().build()?;
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

/// A failed attempt to recover a concrete packet from its type-erased form.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("Packet with opcode {opcode:#06x} contained {actual}, but {expected} was expected")]
pub struct DynamicPacketTypeError {
    pub opcode: u16,
    pub expected: &'static str,
    pub actual: &'static str,
}

pub struct DynamicPacket {
    inner: Box<dyn Any + Send>,
    opcode: u16,
    type_name: &'static str,
}

impl Debug for DynamicPacket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamicPacket")
            .field("opcode", &self.opcode)
            .field("type_name", &self.type_name)
            .finish_non_exhaustive()
    }
}

impl DynamicPacket {
    /// Creates a dynamic packet from an already erased value.
    ///
    /// Use [`DynamicPacket::from_value`] when the concrete value is still
    /// available so type mismatch errors can include its name.
    pub fn new(opcode: u16, inner: Box<dyn Any + Send>) -> Self {
        Self {
            inner,
            opcode,
            type_name: "an erased value",
        }
    }

    /// Erases a concrete value while retaining its type name for diagnostics.
    pub fn from_value<T: Any + Send>(opcode: u16, inner: T) -> Self {
        Self {
            inner: Box::new(inner),
            opcode,
            type_name: type_name::<T>(),
        }
    }

    pub fn as_packet<T: 'static>(&self) -> Option<&T> {
        self.inner.downcast_ref()
    }

    /// Borrows the erased packet as `T`, preserving type mismatch details.
    pub fn try_as_packet<T: 'static>(&self) -> Result<&T, DynamicPacketTypeError> {
        self.as_packet::<T>().ok_or_else(|| DynamicPacketTypeError {
            opcode: self.opcode,
            expected: type_name::<T>(),
            actual: self.type_name,
        })
    }

    pub fn into_packet<T: 'static>(self) -> Result<T, DynamicPacket> {
        match self.inner.downcast::<T>() {
            Ok(packet) => Ok(*packet),
            Err(inner) => Err(DynamicPacket {
                inner,
                opcode: self.opcode,
                type_name: self.type_name,
            }),
        }
    }

    pub fn packet_type(&self) -> TypeId {
        self.inner.as_ref().type_id()
    }

    pub fn packet_type_name(&self) -> &'static str {
        self.type_name
    }

    pub fn opcode(&self) -> u16 {
        self.opcode
    }
}

impl<T: Packet + Send + 'static> From<T> for DynamicPacket {
    fn from(packet: T) -> Self {
        Self::from_value(T::ID, packet)
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

type BeforeWriteFrameCallback = Box<dyn Fn(&OutgoingPacket, &SerdeContext) + Send>;
type BeforeWritePacketCallback =
    Box<dyn Fn(&DynamicPacket, &SerdeContext) -> Result<(), DynamicPacketTypeError> + Send>;

#[derive(Default)]
struct WriteCallbacks {
    before_write_frame: Vec<BeforeWriteFrameCallback>,
    before_write_packet: HashMap<TypeId, BeforeWritePacketCallback>,
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
            let packet = any_packet.try_as_packet::<T>()?;
            func(packet, ctx);
            Ok(())
        });
        self.before_write_packet.insert(type_id, wrapper);
    }

    fn call_for_packet(
        &self,
        packet: &DynamicPacket,
        context: &SerdeContext,
    ) -> Result<(), DynamicPacketTypeError> {
        let Some(handler) = self.before_write_packet.get(&packet.packet_type()) else {
            return Ok(());
        };

        handler(packet, context)
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
        let opcode = packet.opcode();
        let frames = packet.as_frames(self.security_context())?;
        for frame in frames {
            self.writer.send(frame).await?;
        }
        self.state.set_last_sent(opcode);
        Ok(())
    }

    /// Serializes, frames, and sends a registered packet.
    ///
    /// Packet serialization failures are returned as
    /// [OutStreamError::PacketError]. In that case packet framing is not
    /// attempted and no bytes are written to the transport.
    pub async fn write_packet<S: Into<DynamicPacket>>(
        &mut self,
        packet: S,
    ) -> Result<(), OutStreamError> {
        let context = self.state.as_context();
        let packet = packet.into();
        self.write_callbacks.call_for_packet(&packet, &context)?;
        let outgoing_packet = self.registry.encode(packet, &context)?;
        self.write_callbacks
            .call_for_frame(&outgoing_packet, &context);
        self.write(outgoing_packet).await
    }

    pub fn context(&self) -> SerdeContext {
        self.state.as_context()
    }
}

type AfterReadFrameCallback = Box<dyn Fn(&IncomingPacket, &SerdeContext) + Send + 'static>;
type AfterReadPacketCallback = Box<
    dyn Fn(&DynamicPacket, &SerdeContext) -> Result<(), DynamicPacketTypeError> + Send + 'static,
>;

#[derive(Default)]
struct ReadCallbacks {
    after_read_frame: Vec<AfterReadFrameCallback>,
    after_read_packet: HashMap<TypeId, AfterReadPacketCallback>,
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
            let packet = any_packet.try_as_packet::<T>()?;
            func(packet, ctx);
            Ok(())
        });
        self.after_read_packet.insert(type_id, wrapper);
    }

    fn call_for_packet(
        &self,
        packet: &DynamicPacket,
        context: &SerdeContext,
    ) -> Result<(), DynamicPacketTypeError> {
        let Some(handler) = self.after_read_packet.get(&packet.packet_type()) else {
            return Ok(());
        };

        handler(packet, context)
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
    reframing_limits: ReframingLimits,
    reframer: Option<IncomingPacketReframer>,
    reframing_failed: bool,
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
            reframing_limits: ReframingLimits::default(),
            reframer: None,
            reframing_failed: false,
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
            reframing_limits: ReframingLimits::recommended(),
            reframer: None,
            reframing_failed: false,
        }
    }

    /// Sets the receiver policy used for subsequent logical packets.
    ///
    /// Limits apply while frames are combined, before a massive payload is
    /// fully accumulated. They do not apply retroactively to a payload already
    /// retained in `next_packet`'s unconsumed buffer.
    pub fn set_reframing_limits(&mut self, limits: ReframingLimits) {
        self.reframing_limits = limits;
    }

    /// Returns the active logical-packet reframing policy.
    pub const fn reframing_limits(&self) -> ReframingLimits {
        self.reframing_limits
    }

    /// Restores unlimited logical-packet reframing.
    pub fn clear_reframing_limits(&mut self) {
        self.reframing_limits = ReframingLimits::unlimited();
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
    /// Frame-count and payload-byte limits configured through
    /// [`SilkroadStreamRead::set_reframing_limits`] are enforced incrementally
    /// while performing this merge. A limit error is terminal for the logical
    /// stream because unread massive containers remain on the transport.
    ///
    /// This should only be necessary if you're not interested in actual packet
    /// data or work really generically. Otherwise,
    /// [SilkroadStreamRead::next_packet] should be used instead.
    pub async fn next(&mut self) -> Result<IncomingPacket, InStreamError> {
        if self.reframing_failed {
            return Err(InStreamError::ReframingTerminated);
        }

        if self.reframer.is_none() {
            self.reframer = Some(IncomingPacketReframer::new(self.reframing_limits));
        }

        while let Some(res) = self.reader.next().await {
            let frame = res?;
            let security = SecurityContext::new(
                self.state.encryption.as_deref(),
                self.state.security_bytes.as_deref(),
            );
            let Some(reframer) = self.reframer.as_mut() else {
                return Err(InStreamError::ReframingTerminated);
            };
            match reframer.push(&frame, security) {
                Ok(Some(packet)) => {
                    self.reframer = None;
                    self.read_callbacks.call_for_frame(&packet, &self.context());
                    return Ok(packet);
                },
                Ok(None) => {},
                Err(error) => {
                    self.reframer = None;
                    self.reframing_failed = true;
                    return Err(InStreamError::ReframingError(error));
                },
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

        self.read_callbacks.call_for_packet(&p, &context)?;
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
    use bytes::BytesMut;
    use skrillax_codec::{FrameEncodeError, MAX_FRAME_CONTENT_SIZE};
    use skrillax_serde::{ByteSize, Deserialize, SerializationError, Serialize};
    use std::sync::atomic::{AtomicBool, Ordering};

    #[derive(Copy, Clone, Default)]
    struct CustomFlag(u8);

    struct FailingWrite;

    struct YieldOnceRead {
        data: Vec<u8>,
        split_at: usize,
        position: usize,
        yielded_pending: bool,
    }

    impl AsyncRead for YieldOnceRead {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buffer: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<Result<(), io::Error>> {
            if self.position == self.split_at && !self.yielded_pending {
                self.yielded_pending = true;
                cx.waker().wake_by_ref();
                return std::task::Poll::Pending;
            }

            if self.position == self.data.len() {
                return std::task::Poll::Ready(Ok(()));
            }

            let section_end = if self.position < self.split_at {
                self.split_at
            } else {
                self.data.len()
            };
            let available = section_end - self.position;
            let copied = available.min(buffer.remaining());
            let end = self.position + copied;
            buffer.put_slice(&self.data[self.position..end]);
            self.position = end;
            std::task::Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for FailingWrite {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &[u8],
        ) -> std::task::Poll<Result<usize, io::Error>> {
            std::task::Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "test transport is closed",
            )))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), io::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), io::Error>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[derive(Packet, Deserialize, Serialize, ByteSize)]
    #[packet(opcode = 0x0042)]
    struct Empty;

    struct FailingPacket;

    impl Packet for FailingPacket {
        const ID: u16 = 0x0044;
        const NAME: &'static str = "FailingPacket";
        const MASSIVE: bool = false;
        const ENCRYPTED: bool = false;
    }

    impl ByteSize for FailingPacket {
        fn byte_size(&self) -> usize {
            0
        }
    }

    impl Serialize for FailingPacket {
        fn write_to(
            &self,
            _writer: &mut BytesMut,
            _ctx: &SerdeContext,
        ) -> Result<(), SerializationError> {
            Err(SerializationError::NoMatchingVariant {
                enum_name: "FailingPacket",
            })
        }
    }

    fn assert_failing_packet_error(error: OutStreamError) {
        assert!(matches!(
            error,
            OutStreamError::PacketError(PacketError::SerializationError(
                SerializationError::NoMatchingVariant {
                    enum_name: "FailingPacket"
                }
            ))
        ));
    }

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
        let registry = PacketRegistry::builder()
            .register::<Empty>()
            .build()
            .expect("unique packet registration should succeed");
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
    async fn frame_limit_rejects_massive_header_before_waiting_for_containers() {
        let wire = SilkroadFrame::MassiveHeader {
            count: 0,
            crc: 0,
            contained_opcode: 0x1234,
            contained_count: 2,
        }
        .serialize()
        .expect("the massive header should be representable");
        let mut reader = SilkroadStreamRead::new(
            FramedRead::new(wire.as_ref(), SilkroadCodec),
            PacketRegistry::builder()
                .build()
                .expect("empty registry should build"),
            SharedState::new(),
        );
        let limits = ReframingLimits::unlimited().with_max_frames_per_packet(2);
        reader.set_reframing_limits(limits);
        assert_eq!(limits, reader.reframing_limits());

        let error = reader
            .next()
            .await
            .expect_err("the declared three-frame packet should exceed the limit");

        assert!(matches!(
            error,
            InStreamError::ReframingError(ReframingError::FrameCountLimitExceeded {
                required: 3,
                maximum: 2,
            })
        ));

        let retry_error = reader
            .next()
            .await
            .expect_err("a reframing failure should terminate the logical stream");
        assert!(matches!(retry_error, InStreamError::ReframingTerminated));
    }

    #[tokio::test]
    async fn cancelled_read_preserves_partial_reframing_state() {
        let header = SilkroadFrame::MassiveHeader {
            count: 0,
            crc: 0,
            contained_opcode: 0x1234,
            contained_count: 1,
        }
        .serialize()
        .expect("the massive header should be representable");
        let unexpected = SilkroadFrame::Packet {
            count: 0,
            crc: 0,
            opcode: 0x5678,
            data: Bytes::new(),
        }
        .serialize()
        .expect("the unexpected packet should be representable");
        let split_at = header.len();
        let mut data = header.to_vec();
        data.extend_from_slice(&unexpected);
        let transport = YieldOnceRead {
            data,
            split_at,
            position: 0,
            yielded_pending: false,
        };
        let mut reader = SilkroadStreamRead::new(
            FramedRead::new(transport, SilkroadCodec),
            PacketRegistry::builder()
                .build()
                .expect("empty registry should build"),
            SharedState::new(),
        );

        let mut pending_read = Box::pin(reader.next());
        assert!(matches!(
            futures::poll!(&mut pending_read),
            std::task::Poll::Pending
        ));
        drop(pending_read);

        let error = reader
            .next()
            .await
            .expect_err("the pending massive sequence must survive cancellation");
        assert!(matches!(
            error,
            InStreamError::ReframingError(ReframingError::MixedFrames)
        ));
    }

    #[tokio::test]
    async fn payload_limit_rejects_simple_packet() {
        let wire = SilkroadFrame::Packet {
            count: 0,
            crc: 0,
            opcode: 0x1234,
            data: Bytes::from_static(&[1, 2, 3]),
        }
        .serialize()
        .expect("the packet should be representable");
        let mut reader = SilkroadStreamRead::new(
            FramedRead::new(wire.as_ref(), SilkroadCodec),
            PacketRegistry::builder()
                .build()
                .expect("empty registry should build"),
            SharedState::new(),
        );
        reader.set_reframing_limits(
            ReframingLimits::unlimited().with_max_payload_bytes_per_packet(2),
        );

        let error = reader
            .next()
            .await
            .expect_err("the three-byte payload should exceed the limit");

        assert!(matches!(
            error,
            InStreamError::ReframingError(ReframingError::PayloadByteLimitExceeded {
                attempted: 3,
                maximum: 2,
            })
        ));

        reader.clear_reframing_limits();
        assert_eq!(ReframingLimits::unlimited(), reader.reframing_limits());
    }

    #[tokio::test]
    async fn zero_container_header_preserves_stream_synchronization() {
        let zero_header = SilkroadFrame::MassiveHeader {
            count: 0,
            crc: 0,
            contained_opcode: 0x1234,
            contained_count: 0,
        };
        let following_frame = SilkroadFrame::Packet {
            count: 0,
            crc: 0,
            opcode: 0x5678,
            data: Bytes::from_static(&[1, 2, 3]),
        };
        let mut wire = zero_header
            .serialize()
            .expect("the zero-container header should be representable")
            .to_vec();
        wire.extend_from_slice(
            &following_frame
                .serialize()
                .expect("the following frame should be representable"),
        );
        let mut reader = SilkroadStreamRead::new(
            FramedRead::new(wire.as_slice(), SilkroadCodec),
            PacketRegistry::builder()
                .build()
                .expect("empty registry should build"),
            SharedState::new(),
        );

        let first = reader
            .next()
            .await
            .expect("the zero-container header should complete immediately");
        let second = reader
            .next()
            .await
            .expect("the frame after the zero-container header should remain available");

        assert_eq!((0x1234, Bytes::new()), first.consume());
        assert_eq!((0x5678, Bytes::from_static(&[1, 2, 3])), second.consume());
    }

    #[tokio::test]
    async fn zero_container_header_completes_before_eof() {
        let wire = SilkroadFrame::MassiveHeader {
            count: 0,
            crc: 0,
            contained_opcode: 0x1234,
            contained_count: 0,
        }
        .serialize()
        .expect("the zero-container header should be representable");
        let mut reader = SilkroadStreamRead::new(
            FramedRead::new(wire.as_ref(), SilkroadCodec),
            PacketRegistry::builder()
                .build()
                .expect("empty registry should build"),
            SharedState::new(),
        );

        let packet = reader
            .next()
            .await
            .expect("the header should complete without waiting for another frame");

        assert_eq!((0x1234, Bytes::new()), packet.consume());
    }

    #[tokio::test]
    pub async fn test_write_packet_to_stream() {
        let mut buffer: Vec<u8> = Vec::new();
        let mut writer = SilkroadStreamWrite::new(
            FramedWrite::new(&mut buffer, SilkroadCodec),
            PacketRegistry::builder()
                .register::<Empty>()
                .build()
                .expect("unique packet registration should succeed"),
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

    #[test]
    fn packet_registry_encode_preserves_serialization_failure() {
        let registry = PacketRegistry::builder()
            .register_outgoing::<FailingPacket>()
            .build()
            .expect("unique packet registration should succeed");

        let error = registry
            .encode(FailingPacket.into(), &SerdeContext::default())
            .expect_err("packet construction should fail");

        assert_failing_packet_error(error);
    }

    #[tokio::test]
    async fn write_packet_emits_nothing_after_serialization_failure() {
        let mut buffer = Vec::new();
        let registry = PacketRegistry::builder()
            .register_outgoing::<FailingPacket>()
            .build()
            .expect("unique packet registration should succeed");
        let mut writer = SilkroadStreamWrite::new(
            FramedWrite::new(&mut buffer, SilkroadCodec),
            registry,
            SharedState::new(),
        );
        let frame_callback_called = Arc::new(AtomicBool::new(false));
        let callback_state = Arc::clone(&frame_callback_called);
        writer.on_before_write(move |_, _| callback_state.store(true, Ordering::SeqCst));

        let error = writer
            .write_packet(FailingPacket)
            .await
            .expect_err("packet construction should fail");

        assert_failing_packet_error(error);
        assert!(!frame_callback_called.load(Ordering::SeqCst));
        drop(writer);
        assert!(buffer.is_empty());
    }

    #[tokio::test]
    async fn framing_failure_emits_nothing_and_does_not_update_last_sent() {
        let mut buffer = Vec::new();
        let mut writer = SilkroadStreamWrite::new(
            FramedWrite::new(&mut buffer, SilkroadCodec),
            PacketRegistry::builder()
                .build()
                .expect("empty registry should build"),
            SharedState::new(),
        );
        let packet = OutgoingPacket::Simple {
            opcode: 0x1234,
            data: Bytes::from(vec![0; MAX_FRAME_CONTENT_SIZE + 1]),
        };

        let error = writer
            .write(packet)
            .await
            .expect_err("an oversized packet should fail during framing");

        assert!(matches!(
            error,
            OutStreamError::Framing(FramingError::FrameEncoding(
                FrameEncodeError::ContentTooLarge { .. }
            ))
        ));
        assert!(writer.context().get::<LastSentPacket>().is_none());
        drop(writer);
        assert!(buffer.is_empty());
    }

    #[tokio::test]
    async fn transport_failure_does_not_update_last_sent() {
        let mut writer = SilkroadStreamWrite::new(
            FramedWrite::new(FailingWrite, SilkroadCodec),
            PacketRegistry::builder()
                .build()
                .expect("empty registry should build"),
            SharedState::new(),
        );

        let error = writer
            .write(OutgoingPacket::Simple {
                opcode: 0x1234,
                data: Bytes::new(),
            })
            .await
            .expect_err("a closed transport should reject the write");

        assert!(matches!(error, OutStreamError::IoError(_)));
        assert!(writer.context().get::<LastSentPacket>().is_none());
    }

    #[tokio::test]
    pub async fn test_context_received_sent() {
        let mut buffer: Vec<u8> = Vec::new();
        let state = SharedState::default();
        let registry = PacketRegistry::builder()
            .register::<Empty>()
            .register::<Conditional>()
            .build()
            .expect("unique packet registrations should succeed");
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
