use std::io;
use std::string::{FromUtf16Error, FromUtf8Error};
use thiserror::Error;

/// Any kind of problem that may occur when trying to deserialize data.
#[derive(Error, Debug)]
pub enum SerializationError {
    #[error("I/O error when serialize/deserializing packet. {0:?}")]
    IoError(#[from] io::Error),
    #[error("I/O error when serialize/deserializing packet at field {0}. {1:?}")]
    FieldIoError(&'static str, io::Error),
    #[error("The enum {1} does not have a variation for value {0}")]
    UnknownVariation(usize, &'static str),
    #[error("Could not convert bytes to a string")]
    StringParsingFailed(#[from] FromUtf8Error),
    #[error("Could not convert bytes to a utf16 string")]
    Utf16ParsingFailed(#[from] FromUtf16Error),
}

impl SerializationError {
    pub fn field_io_error(field: &'static str, err: SerializationError) -> Self {
        match err {
            SerializationError::IoError(e) => Self::FieldIoError(field, e),
            e => e,
        }
    }
}
