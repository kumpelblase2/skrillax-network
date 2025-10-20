//! `skrillax-serde` provides definitions for serialization/deserialization of
//! data structures used in Silkroad Online.
//!
//! Generally, you won't be implementing the traits provided here, but will be
//! automatically deriving these instead. We provide three traits: [Serialize],
//! [Deserialize], and [ByteSize], for serializing, deserializing, and
//! estimating the size respectively.

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
pub use time::SilkroadTime;

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
            fn write_to(&self, writer: &mut ::bytes::BytesMut, _ctx: &SerdeContext) {
                writer.put_slice(&self.to_le_bytes());
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

/// Context used during serialization and deserialization.
///
/// Silkroad frames can be parsed in a stateless fashion, but the same
/// cannot be said about the operations contained in those frames. There
/// are some operations that rely on outside knowledge as well as others
/// which depend on the request sent that evoked a given response.
pub struct SerdeContext {
    data: Arc<RwLock<ContextMap>>,
}

impl SerdeContext {
    pub fn new(data: Arc<RwLock<ContextMap>>) -> Self {
        Self { data }
    }

    pub fn get<T: Clone + 'static>(&self) -> Option<T> {
        let guard = self.data.read().expect("");
        let option = guard.get(&TypeId::of::<T>()).map(|value| {
            value
                .downcast_ref()
                .expect("Downcast to the same typeid should work.")
        });
        option.cloned()
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
            .expect("Lock should not be poisoned.")
            .remove(&TypeId::of::<T>());
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

/// The `Serialize` trait allows an item to be serialized into a binary
/// representation of itself, which may then be used to send it off over
/// the network. This trait requires the [ByteSize] trait to also be
/// present in order to pre-allocate the necessary amount of space for
/// the serialized data.
///
/// `Serialize` only provides one method: [Serialize::write_to]. This
/// method is used to serialize the data and write it into the given
/// buffer. This buffer may already contain data unrelated to this item
/// and may have more space available for more items to follow. However,
/// it is always at least the size provided by [ByteSize].
pub trait Serialize: ByteSize {
    /// Writes all bytes representing the content of the struct to the writer
    /// output.
    fn write_to(&self, writer: &mut BytesMut, ctx: &SerdeContext);

    /// Convenience around [self.write_to] which already reserves the necessary
    /// space.
    fn write_to_end(&self, writer: &mut BytesMut, ctx: &SerdeContext) {
        writer.reserve(self.byte_size());
        self.write_to(writer, ctx);
    }
}

/// `Deserialize` allows an item to be created from a binary representation.
/// Given that there are many different ways such a conversion may fail, this
/// operation will always yield a [Result]. It is not even sure that there
/// are enough bytes available to be read for the deserialization of this
/// item to be completed successfully.
pub trait Deserialize {
    /// Tries to read the data contained in `reader` to create and instance of
    /// `Self`.
    ///
    /// May return an error if the data did not match the expected format.
    fn read_from<T: Read + ReadBytesExt>(
        reader: &mut T,
        ctx: &SerdeContext,
    ) -> Result<Self, SerializationError>
    where
        Self: Sized; // Technically, we don't care about being `Sized`, but unfortunately, Result
                     // does.
}

/// An item having a [ByteSize] implementation specifies it has a known
/// size, independent of if it's [Sized] or not. The size reported by
/// [ByteSize] may sometimes not be the same as [size_of], as
/// alignment should not be taken into account for [ByteSize]. The size returned
/// should not be taken as an exact value, though it should always match
/// the final size. Assume this to be a good estimate instead.
pub trait ByteSize {
    /// Given the current element, provides the number of bytes necessary to
    /// represent this element. This should never error and instead return a
    /// size of 0.
    fn byte_size(&self) -> usize;
}

impl Serialize for u8 {
    fn write_to(&self, writer: &mut BytesMut, _ctx: &SerdeContext) {
        writer.put_u8(*self);
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
    fn write_to(&self, writer: &mut BytesMut, ctx: &SerdeContext) {
        let value = u8::from(*self);
        value.write_to(writer, ctx);
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
        Ok(reader.read_u8()? == 1)
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
        1u8.write_to_end(&mut buffer, &SerdeContext::default());
        assert_eq!(&[1], buffer.freeze().as_ref());
        let mut buffer = BytesMut::new();
        1u16.write_to_end(&mut buffer, &SerdeContext::default());
        assert_eq!(&[1, 0], buffer.freeze().as_ref());
        let mut buffer = BytesMut::new();
        1u32.write_to_end(&mut buffer, &SerdeContext::default());
        assert_eq!(&[1, 0, 0, 0], buffer.freeze().as_ref());
        let mut buffer = BytesMut::new();
        1u64.write_to_end(&mut buffer, &SerdeContext::default());
        assert_eq!(&[1, 0, 0, 0, 0, 0, 0, 0], buffer.freeze().as_ref());
    }

    #[test]
    fn test_serialize_float_primitives() {
        let mut buffer = BytesMut::new();
        42.42f32.write_to_end(&mut buffer, &SerdeContext::default());
        assert_eq!(&[0x14, 0xAE, 0x29, 0x42], buffer.freeze().as_ref());
        let mut buffer = BytesMut::new();
        42.42f64.write_to_end(&mut buffer, &SerdeContext::default());
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
}
