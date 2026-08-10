use std::io;
use std::string::{FromUtf8Error, FromUtf16Error};
use thiserror::Error;

/// A failure while serializing or deserializing Silkroad wire data.
///
/// Serialization variants report unrepresentable values and violated wire
/// invariants. Deserialization variants report malformed or truncated input,
/// receiver-policy rejection, and collection allocation failure.
#[derive(Error, Debug)]
pub enum SerializationError {
    #[error("I/O error when serialize/deserializing packet. {0:?}")]
    IoError(#[from] io::Error),
    #[error("I/O error when serialize/deserializing packet at field {0}. {1:?}")]
    FieldIoError(&'static str, io::Error),
    #[error("The enum {1} does not have a variation for value {0}")]
    UnknownVariation(u64, &'static str),
    #[error(
        "field {field} has length {actual}, which does not fit in a {width}-byte prefix (maximum \
         {maximum})"
    )]
    LengthOutOfRange {
        field: &'static str,
        actual: usize,
        maximum: u64,
        width: usize,
    },
    #[error(
        "conditional field {field} has presence {present}, but its condition evaluated to \
         {condition}"
    )]
    ConditionalPresenceMismatch {
        field: &'static str,
        condition: bool,
        present: bool,
    },
    #[error(
        "calculated collection {field} contains {actual} elements, but its calculated length is \
         {expected}"
    )]
    CalculatedLengthMismatch {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("calculated length for field {field} cannot be represented as usize")]
    CalculatedLengthOutOfRange { field: &'static str },
    #[error(
        "variant {variant} of enum {enum_name} is not the first variant selected by its predicates"
    )]
    VariantConditionMismatch {
        enum_name: &'static str,
        variant: &'static str,
    },
    #[error("no variant of enum {enum_name} matched the available tag or context")]
    NoMatchingVariant { enum_name: &'static str },
    #[error("field {field} contained invalid presence marker {value}")]
    InvalidPresenceMarker { field: &'static str, value: u64 },
    #[error("boolean contained non-canonical value {value}; expected 0 or 1")]
    InvalidBooleanValue { value: u8 },
    #[error("field {field} contained invalid sequence marker {value}")]
    InvalidSequenceMarker { field: &'static str, value: u64 },
    #[error("decoded length {value} for field {field} cannot be represented as usize")]
    DecodedLengthOutOfRange { field: &'static str, value: u64 },
    #[error("decoded {actual} array elements, but exactly {expected} were required")]
    ArrayLengthMismatch { expected: usize, actual: usize },
    /// A decoded collection count exceeded the receiver policy before the
    /// collection was allocated or the rejected element was read.
    ///
    /// This is an application policy failure, not evidence that the wire data
    /// is malformed or truncated.
    #[error(
        "collection field {field} declares {actual} elements, exceeding the configured maximum \
         {maximum}"
    )]
    CollectionLengthLimitExceeded {
        field: &'static str,
        actual: u64,
        maximum: usize,
    },
    /// Reserving storage for a decoded collection failed.
    ///
    /// This is distinct from a configured collection limit and can occur even
    /// when deserialization limits are unlimited.
    #[error("could not reserve space for {elements} elements in collection field {field}")]
    CollectionAllocationFailed {
        field: &'static str,
        elements: u64,
        #[source]
        source: std::collections::TryReserveError,
    },
    #[error("Could not convert bytes to a string")]
    StringParsingFailed(#[from] FromUtf8Error),
    #[error("Could not convert bytes to a utf16 string")]
    Utf16ParsingFailed(#[from] FromUtf16Error),
    #[cfg(feature = "chrono")]
    #[error(transparent)]
    Time(#[from] crate::time::TimeError),
}

impl SerializationError {
    pub fn field_io_error(field: &'static str, err: SerializationError) -> Self {
        match err {
            SerializationError::IoError(e) => Self::FieldIoError(field, e),
            e => e,
        }
    }
}
