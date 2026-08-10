//! `skrillax-serde` provides definitions for serialization/deserialization of
//! data structures used in Silkroad Online.
//!
//! Generally, you won't implement the traits provided here manually, but will
//! derive them instead. [Serialize] writes a value fallibly, [Deserialize]
//! reads it, and [ByteSize] reports the exact wire size of a well-formed value.
//! `ByteSize` is infallible and non-validating; see its contract before using
//! it for allocation.
//!
//! Collection decoding can be restricted with [`DeserializationLimits`] on a
//! [`SerdeContext`]. The policy is opt-in, unlimited by default, measured in
//! elements per collection, and affects deserialization only. It is not a byte,
//! packet, frame, reassembly, or stream limit.
//!
//! Booleans use one canonical byte: `0` for false and `1` for true. Other
//! values are rejected during deserialization.

pub mod error;
mod time;

use byteorder::ReadBytesExt;
use bytes::{BufMut, BytesMut};
pub use error::SerializationError;
#[cfg(feature = "derive")]
pub use skrillax_serde_derive::{ByteSize, Deserialize, Serialize};
use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::io::Read;
use std::sync::{Arc, RwLock};
#[cfg(feature = "chrono")]
pub use time::{ExpandedSilkroadTime, PackedSilkroadTime, TimeError};

// This is necessary, because otherwise we'd need to make the user of our derive
// traits add `use` definitions for `bytes` and `byteorder`. Which would require
// them also to add these as dependencies of their own. Yikes.
#[doc(hidden)]
pub mod __internal {
    pub use byteorder;
    pub use bytes;
}

macro_rules! implement_primitive {
    ($tt:ty, $read:ident) => {
        impl Serialize for $tt {
            fn write_to(
                &self,
                writer: &mut ::bytes::BytesMut,
                _ctx: &SerdeContext,
            ) -> Result<(), SerializationError> {
                writer.put_slice(&self.to_le_bytes());
                Ok(())
            }
        }

        impl ByteSize for $tt {
            fn byte_size(&self) -> usize {
                std::mem::size_of::<$tt>()
            }
        }

        impl Deserialize for $tt {
            fn read_from<T: std::io::Read + ::byteorder::ReadBytesExt>(
                reader: &mut T,
                _ctx: &SerdeContext,
            ) -> Result<Self, SerializationError> {
                Ok(reader.$read::<::byteorder::LittleEndian>()?)
            }
        }
    };
}

type ContextMap = HashMap<TypeId, Box<dyn Any + Send + Sync>>;

/// Receiver policy for collection deserialization.
///
/// The limit applies independently to each decoded collection, is measured in
/// elements, and is consulted only during deserialization. It is not a byte,
/// packet, frame, reassembly, stream, or cumulative nested-collection limit.
/// The default is unlimited to preserve the full range accepted by the wire
/// protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct DeserializationLimits {
    max_collection_elements: Option<usize>,
}

impl DeserializationLimits {
    /// Creates a policy with no collection element limit.
    pub const fn unlimited() -> Self {
        Self {
            max_collection_elements: None,
        }
    }

    /// Creates a policy allowing at most `maximum` elements per collection.
    ///
    /// A maximum of zero permits empty collections and rejects every attempted
    /// element.
    pub const fn with_max_collection_elements(maximum: usize) -> Self {
        Self {
            max_collection_elements: Some(maximum),
        }
    }

    /// Returns the configured per-collection element maximum, if any.
    pub const fn max_collection_elements(&self) -> Option<usize> {
        self.max_collection_elements
    }
}

impl Default for DeserializationLimits {
    fn default() -> Self {
        Self::unlimited()
    }
}

/// Context used during serialization and deserialization.
///
/// Silkroad frames can be parsed in a stateless fashion, but the same
/// cannot be said about the operations contained in those frames. There
/// are some operations that rely on outside knowledge as well as others
/// which depend on the request sent that evoked a given response.
///
/// Clones share the same type-indexed configuration. Configure receiver limits
/// before beginning a decode and do not mutate them concurrently with that
/// decode.
pub struct SerdeContext {
    data: Arc<RwLock<ContextMap>>,
}

impl SerdeContext {
    pub fn new(data: Arc<RwLock<ContextMap>>) -> Self {
        Self { data }
    }

    pub fn get<T: Clone + 'static>(&self) -> Option<T> {
        let guard = self.data.read().expect("Lock should not be poisoned.");
        guard
            .get(&TypeId::of::<T>())
            .and_then(|value| value.downcast_ref::<T>())
            .cloned()
    }

    pub fn set<T: Send + Sync + 'static>(&self, value: T) {
        self.data
            .write()
            .expect("Lock should not be poisoned.")
            .insert(TypeId::of::<T>(), Box::new(value));
    }

    pub fn unset<T: 'static>(&self) {
        let _ = self
            .data
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&TypeId::of::<T>());
    }

    /// Sets the collection policy used by subsequent deserialization.
    ///
    /// Context clones observe the same setting. This policy is ignored by
    /// serialization and [`ByteSize`].
    pub fn set_deserialization_limits(&self, limits: DeserializationLimits) {
        self.set(limits);
    }

    /// Returns the active deserialization policy.
    ///
    /// An unset policy is equivalent to [`DeserializationLimits::unlimited`].
    pub fn deserialization_limits(&self) -> DeserializationLimits {
        self.get().unwrap_or_default()
    }

    /// Restores unlimited collection deserialization.
    pub fn clear_deserialization_limits(&self) {
        self.unset::<DeserializationLimits>();
    }

    /// Checks a decoded collection length against the receiver policy.
    ///
    /// This method is public because derive output calls it from downstream
    /// crates; it is not intended as a general validation API.
    #[doc(hidden)]
    pub fn check_collection_length(
        &self,
        field: &'static str,
        actual: u64,
    ) -> Result<(), SerializationError> {
        if let Some(maximum) = self.deserialization_limits().max_collection_elements()
            && u64::try_from(maximum).is_ok_and(|maximum| actual > maximum)
        {
            return Err(SerializationError::CollectionLengthLimitExceeded {
                field,
                actual,
                maximum,
            });
        }

        Ok(())
    }
}

impl Clone for SerdeContext {
    fn clone(&self) -> Self {
        Self {
            data: Arc::clone(&self.data),
        }
    }
}

impl Default for SerdeContext {
    fn default() -> Self {
        Self::new(Arc::new(RwLock::new(ContextMap::new())))
    }
}

/// Fallibly serializes a value into its Silkroad wire representation.
///
/// Implementations validate representability and value-dependent wire
/// invariants while writing. A failure is not atomic: bytes written before the
/// error remain in the destination. Callers that reuse a buffer and require
/// rollback should record its original length and truncate it on error.
///
/// This trait requires [ByteSize] for allocation. `byte_size()` is exact for
/// well-formed values, but is not validation and does not guarantee that an
/// ill-formed value will serialize successfully.
pub trait Serialize: ByteSize {
    /// Appends this value's wire bytes to `writer` using `ctx`.
    ///
    /// This method does not reserve space. It may return an error after earlier
    /// fields or nested values have already appended bytes.
    fn write_to(&self, writer: &mut BytesMut, ctx: &SerdeContext)
    -> Result<(), SerializationError>;

    /// Reserves `self.byte_size()` bytes, then calls [Serialize::write_to].
    ///
    /// Reservation happens before serialization and may therefore overallocate
    /// when an ill-formed value subsequently returns an error. Existing and
    /// partially written bytes are not rolled back.
    fn write_to_end(
        &self,
        writer: &mut BytesMut,
        ctx: &SerdeContext,
    ) -> Result<(), SerializationError> {
        writer.reserve(self.byte_size());
        self.write_to(writer, ctx)
    }
}

/// Creates a value from its Silkroad wire representation.
///
/// Deserialization is fallible because input may be truncated, malformed,
/// inconsistent with the supplied [SerdeContext], rejected by its receiver
/// policy, or impossible to allocate. On success, an implementation consumes
/// exactly the bytes belonging to one value and leaves trailing bytes in the
/// reader untouched.
///
/// Derived collection decoders consult [`DeserializationLimits`] before known
/// counts are allocated or elements are read. Sentinel-framed collections
/// enforce the same policy incrementally.
pub trait Deserialize {
    /// Reads one `Self` from `reader` using `ctx`.
    ///
    /// Returns an error when the input does not match the expected wire format.
    fn read_from<T: Read + ReadBytesExt>(
        reader: &mut T,
        ctx: &SerdeContext,
    ) -> Result<Self, SerializationError>
    where
        Self: Sized; // Technically, we don't care about being `Sized`, but unfortunately, Result
    // does.
}

/// Reports a value's wire size without validation.
///
/// For every well-formed value and matching [SerdeContext], this size is
/// exactly the number of bytes emitted by [Serialize]. It excludes Rust layout
/// padding and may differ from [`std::mem::size_of`].
///
/// `ByteSize` is deliberately infallible and context-free. For an ill-formed
/// value that serialization would reject, its result is not guaranteed to be
/// useful or authoritative. Callers may use it for allocation, but must not use
/// it as validation.
pub trait ByteSize {
    /// Returns the serialized byte count for a well-formed value.
    ///
    /// Implementations must not panic merely because a protocol length cannot
    /// fit its configured prefix; that check belongs to [Serialize].
    fn byte_size(&self) -> usize;
}

impl Serialize for u8 {
    fn write_to(
        &self,
        writer: &mut BytesMut,
        _ctx: &SerdeContext,
    ) -> Result<(), SerializationError> {
        writer.put_u8(*self);
        Ok(())
    }
}

impl ByteSize for u8 {
    fn byte_size(&self) -> usize {
        size_of::<u8>()
    }
}

impl Deserialize for u8 {
    fn read_from<T: Read + ReadBytesExt>(
        reader: &mut T,
        _ctx: &SerdeContext,
    ) -> Result<Self, SerializationError>
    where
        Self: Sized,
    {
        Ok(reader.read_u8()?)
    }
}

impl Serialize for bool {
    fn write_to(
        &self,
        writer: &mut BytesMut,
        ctx: &SerdeContext,
    ) -> Result<(), SerializationError> {
        let value = u8::from(*self);
        value.write_to(writer, ctx)
    }
}

impl ByteSize for bool {
    fn byte_size(&self) -> usize {
        1
    }
}

impl Deserialize for bool {
    fn read_from<T: Read + ReadBytesExt>(
        reader: &mut T,
        _ctx: &SerdeContext,
    ) -> Result<Self, SerializationError>
    where
        Self: Sized,
    {
        match reader.read_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            value => Err(SerializationError::InvalidBooleanValue { value }),
        }
    }
}

implement_primitive!(u16, read_u16);
implement_primitive!(i16, read_i16);
implement_primitive!(u32, read_u32);
implement_primitive!(i32, read_i32);
implement_primitive!(u64, read_u64);
implement_primitive!(i64, read_i64);
implement_primitive!(f32, read_f32);
implement_primitive!(f64, read_f64);

impl<T: ByteSize, const N: usize> ByteSize for [T; N] {
    fn byte_size(&self) -> usize {
        self.iter().map(ByteSize::byte_size).sum()
    }
}

impl<T: Serialize, const N: usize> Serialize for [T; N] {
    fn write_to(
        &self,
        writer: &mut BytesMut,
        ctx: &SerdeContext,
    ) -> Result<(), SerializationError> {
        for element in self {
            element.write_to(writer, ctx)?;
        }
        Ok(())
    }
}

impl<T: Deserialize, const N: usize> Deserialize for [T; N] {
    fn read_from<R: Read + ReadBytesExt>(
        reader: &mut R,
        ctx: &SerdeContext,
    ) -> Result<Self, SerializationError> {
        let mut elements = Vec::with_capacity(N);
        for _ in 0..N {
            elements.push(T::read_from(reader, ctx)?);
        }

        elements
            .try_into()
            .map_err(|elements: Vec<T>| SerializationError::ArrayLengthMismatch {
                expected: N,
                actual: elements.len(),
            })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use bytes::Buf;

    #[test]
    fn test_deserialize_primitive() {
        let one = u8::read_from(&mut [1u8].reader(), &SerdeContext::default())
            .expect("Should be able to read primitive");
        assert_eq!(1, one);
        let one = u16::read_from(&mut [1u8, 0u8].reader(), &SerdeContext::default())
            .expect("Should be able to read primitive");
        assert_eq!(1, one);
        let one = u32::read_from(&mut [1u8, 0u8, 0u8, 0u8].reader(), &SerdeContext::default())
            .expect("Should be able to read primitive");
        assert_eq!(1, one);
        let one = u64::read_from(
            &mut [1u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8].reader(),
            &SerdeContext::default(),
        )
        .expect("Should be able to read primitive");
        assert_eq!(1, one);
    }

    #[test]
    fn test_deserialize_float_primitives() {
        let result = f32::read_from(
            &mut [0x14, 0xAE, 0x29, 0x42].reader(),
            &SerdeContext::default(),
        )
        .expect("Should be able to read primitive");
        assert!((42.42 - result).abs() < 0.00000001);
        let result = f64::read_from(
            &mut [0xF6, 0x28, 0x5C, 0x8F, 0xC2, 0x35, 0x45, 0x40].reader(),
            &SerdeContext::default(),
        )
        .expect("Should be able to read primitive");
        assert!((42.42 - result).abs() < 0.00000001);
    }

    #[test]
    fn test_serialize_primitive() {
        let mut buffer = BytesMut::new();
        1u8.write_to_end(&mut buffer, &SerdeContext::default())
            .unwrap();
        assert_eq!(&[1], buffer.freeze().as_ref());
        let mut buffer = BytesMut::new();
        1u16.write_to_end(&mut buffer, &SerdeContext::default())
            .unwrap();
        assert_eq!(&[1, 0], buffer.freeze().as_ref());
        let mut buffer = BytesMut::new();
        1u32.write_to_end(&mut buffer, &SerdeContext::default())
            .unwrap();
        assert_eq!(&[1, 0, 0, 0], buffer.freeze().as_ref());
        let mut buffer = BytesMut::new();
        1u64.write_to_end(&mut buffer, &SerdeContext::default())
            .unwrap();
        assert_eq!(&[1, 0, 0, 0, 0, 0, 0, 0], buffer.freeze().as_ref());
    }

    #[test]
    fn test_serialize_float_primitives() {
        let mut buffer = BytesMut::new();
        42.42f32
            .write_to_end(&mut buffer, &SerdeContext::default())
            .unwrap();
        assert_eq!(&[0x14, 0xAE, 0x29, 0x42], buffer.freeze().as_ref());
        let mut buffer = BytesMut::new();
        42.42f64
            .write_to_end(&mut buffer, &SerdeContext::default())
            .unwrap();
        assert_eq!(
            &[0xF6, 0x28, 0x5C, 0x8F, 0xC2, 0x35, 0x45, 0x40],
            buffer.freeze().as_ref()
        );
    }

    #[test]
    fn test_size_primitives() {
        assert_eq!(1, 1u8.byte_size());
        assert_eq!(2, 1u16.byte_size());
        assert_eq!(4, 1u32.byte_size());
        assert_eq!(8, 1u64.byte_size());
        assert_eq!(4, 1.1f32.byte_size());
        assert_eq!(8, 1.1f64.byte_size());
    }

    #[test]
    fn zero_length_array_has_no_wire_bytes() {
        let array: [u8; 0] = [];
        let context = SerdeContext::default();
        let mut buffer = BytesMut::new();

        array.write_to(&mut buffer, &context).unwrap();

        assert_eq!(array.byte_size(), 0);
        assert!(buffer.is_empty());

        let mut reader = [0xAA].as_slice();
        let decoded = <[u8; 0]>::read_from(&mut reader, &context).unwrap();
        assert_eq!(decoded, array);
        assert_eq!(reader, &[0xAA]);
    }

    #[test]
    fn u16_array_uses_exact_little_endian_bytes_and_summed_size() {
        let array = [0x1234u16, 0xABCD];
        let context = SerdeContext::default();
        let mut buffer = BytesMut::new();

        array.write_to(&mut buffer, &context).unwrap();

        assert_eq!(array.byte_size(), 4);
        assert_eq!(buffer.as_ref(), &[0x34, 0x12, 0xCD, 0xAB]);
    }

    #[test]
    fn array_round_trip_consumes_exactly_its_elements() {
        let array = [1u16, 258, u16::MAX];
        let context = SerdeContext::default();
        let mut buffer = BytesMut::new();
        array.write_to(&mut buffer, &context).unwrap();
        buffer.extend_from_slice(&[0xAA]);
        let mut reader = buffer.as_ref();

        let decoded = <[u16; 3]>::read_from(&mut reader, &context).unwrap();

        assert_eq!(decoded, array);
        assert_eq!(reader, &[0xAA]);
    }

    #[test]
    fn truncated_array_deserialization_returns_io_error() {
        let context = SerdeContext::default();
        let mut reader = [0x34, 0x12, 0x56].as_slice();

        let error = <[u16; 2]>::read_from(&mut reader, &context).unwrap_err();

        assert!(matches!(
            error,
            SerializationError::IoError(error)
                if error.kind() == std::io::ErrorKind::UnexpectedEof
        ));
    }

    #[test]
    fn bool_uses_canonical_wire_values() {
        let context = SerdeContext::default();
        let mut output = BytesMut::new();

        false
            .write_to(&mut output, &context)
            .expect("false should serialize");
        true.write_to(&mut output, &context)
            .expect("true should serialize");
        assert_eq!(output.as_ref(), &[0, 1]);

        assert!(!bool::read_from(&mut &b"\0"[..], &context).expect("zero should decode"));
        assert!(bool::read_from(&mut &b"\x01"[..], &context).expect("one should decode"));
    }

    #[test]
    fn bool_rejects_noncanonical_values_without_reading_a_suffix() {
        for value in [2, u8::MAX] {
            let bytes = [value, 0xaa];
            let mut input = &bytes[..];

            let error = bool::read_from(&mut input, &SerdeContext::default())
                .expect_err("a boolean must be encoded as zero or one");

            assert!(matches!(
                error,
                SerializationError::InvalidBooleanValue { value: actual } if actual == value
            ));
            assert_eq!(input, &[0xaa]);
        }
    }

    #[test]
    fn context_set_remove() {
        let context = SerdeContext::default();

        context.set(String::from("Hello!"));
        let option = context.get::<String>();
        assert!(option.is_some());
        assert_eq!("Hello!", option.unwrap());
        context.unset::<String>();
        assert!(context.get::<String>().is_none());
    }

    #[test]
    fn context_type_mismatch_is_treated_as_missing() {
        let mut data = ContextMap::new();
        data.insert(TypeId::of::<String>(), Box::new(42u32));
        let context = SerdeContext::new(Arc::new(RwLock::new(data)));

        assert_eq!(context.get::<String>(), None);
    }

    #[test]
    fn context_simple_struct() {
        #[derive(Copy, Clone)]
        struct MyData(u16);

        let context = SerdeContext::default();
        context.set(MyData(12));
        let data = context
            .get::<MyData>()
            .expect("Context should have my data");
        assert_eq!(12, data.0);

        context.set(MyData(9));
        let data = context
            .get::<MyData>()
            .expect("Context should have my data");
        assert_eq!(9, data.0);
        context.unset::<MyData>();
        assert!(context.get::<MyData>().is_none());
    }

    #[test]
    fn deserialization_limits_are_unlimited_by_default() {
        let context = SerdeContext::default();

        assert_eq!(
            context.deserialization_limits(),
            DeserializationLimits::unlimited()
        );
        assert_eq!(
            context.deserialization_limits().max_collection_elements(),
            None
        );
        assert!(context.check_collection_length("items", u64::MAX).is_ok());
    }

    #[test]
    fn deserialization_limits_can_be_set_retrieved_and_cleared() {
        let context = SerdeContext::default();
        let limits = DeserializationLimits::with_max_collection_elements(12);

        context.set_deserialization_limits(limits);
        assert_eq!(context.deserialization_limits(), limits);

        context.clear_deserialization_limits();
        assert_eq!(
            context.deserialization_limits(),
            DeserializationLimits::unlimited()
        );
    }

    #[test]
    fn cloned_context_observes_deserialization_limit_updates() {
        let context = SerdeContext::default();
        let clone = context.clone();

        context.set_deserialization_limits(DeserializationLimits::with_max_collection_elements(3));
        assert_eq!(
            clone.deserialization_limits().max_collection_elements(),
            Some(3)
        );

        clone.clear_deserialization_limits();
        assert_eq!(
            context.deserialization_limits().max_collection_elements(),
            None
        );
    }

    #[test]
    fn zero_collection_limit_accepts_empty_and_rejects_first_element() {
        let context = SerdeContext::default();
        context.set_deserialization_limits(DeserializationLimits::with_max_collection_elements(0));

        assert!(context.check_collection_length("items", 0).is_ok());
        assert!(matches!(
            context.check_collection_length("items", 1),
            Err(SerializationError::CollectionLengthLimitExceeded {
                field: "items",
                actual: 1,
                maximum: 0,
            })
        ));
    }

    #[test]
    fn collection_policy_error_preserves_fields_and_u64_count() {
        let context = SerdeContext::default();
        context.set_deserialization_limits(DeserializationLimits::with_max_collection_elements(7));

        let error = context
            .check_collection_length("wide_items", u64::MAX)
            .expect_err("the finite policy must reject u64::MAX");

        assert!(matches!(
            error,
            SerializationError::CollectionLengthLimitExceeded {
                field: "wide_items",
                actual: u64::MAX,
                maximum: 7,
            }
        ));
    }
}
