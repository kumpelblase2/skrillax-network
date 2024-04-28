//! This module underpins the security aspects of the network communication between a Silkroad
//! Online client and server. It provides the building blocks to establish a common encryption
//! secret ([SilkroadEncryption]) through a handshake ([handshake::ActiveHandshake],
//! [handshake::PassiveHandshake]), which als provide CRC and count security checks. This provided
//! without any I/O, such that you could feasibly add it to whatever setup you have, or you can use
//! the [skrillax-stream](https://docs.rs/skrillax-stream) crate that provides an async version on
//! top of tokio (albeit with a bit more than just the handshake).
//!
//! The main way you want to be interfacing with this crate is through the handshake structs of
//! which there are two: [handshake::ActiveHandshake] & [handshake::PassiveHandshake]. As the name
//! suggests, the handshake is composed of an active and a passive part, usually being the server
//! and the client respectively. The server is considered the active part of the handshake, because
//! it will start the handshake procedure by sending the passive part (i.e. the client)
//! initialization data. After which a few more messages will be exchanged until both parties have
//! both setup their security bytes ([MessageCounter] & [Checksum]) as well as the shared encryption
//! ([SilkroadEncryption]). Please refer to the documentation of the individual handshake element
//! for more information about the procedure of a handshake.
//!
//! Each of the three elements ([MessageCounter], [Checksum], and [SilkroadEncryption]) can be used
//! independently of each other if so desired.

mod checksum;
mod count;
pub mod handshake;

pub use crate::checksum::*;
pub use crate::count::*;
pub use crate::handshake::ActiveHandshake;
pub use crate::handshake::PassiveHandshake;
pub use crate::handshake::SecurityFeature;
use blowfish::cipher::{Block, BlockDecrypt, BlockEncrypt, KeyInit};
use blowfish::BlowfishLE;

use bytes::{BufMut, Bytes};
use thiserror::Error;

const BLOCK_SIZE: usize = 8;
// Convenience shorthand.
type BlowfishBlock = Block<BlowfishLE>;

#[derive(Error, Debug)]
pub enum SilkroadSecurityError {
    /// The handshake hasn't been started or hasn't completed, yet the operation required it.
    #[error("Security has not been initialized")]
    SecurityUninitialized,
    /// The handshake has already completed. The security would need to be reset before continuing.
    #[error("Security is already initialized")]
    AlreadyInitialized,
    /// Finalizing the handshake requires the handshake to have exchanged public key data, which hasn't happened yet.
    #[error("Security has not completed the initialization")]
    InitializationUnfinished,
    /// The given encrypted data is not the correct block length, as required for decryption.
    #[error("{0} is an invalid block length")]
    InvalidBlockLength(usize),
    /// We calculated a different secret than the client, something went wrong in the handshake.
    #[error("Local calculated key was {calculated} but received {received}")]
    KeyExchangeMismatch { received: u64, calculated: u64 },
}

const BLOWFISH_BLOCK_SIZE: usize = 8;

/// Handles the encryption/decryption of data in Silkroad Online.
///
/// Generally only the client encrypts data, but this is a generic encryption setup. This is
/// essentially a thin veil around [BlowfishCompat], only ensuring the right block size has been
/// used.
///
/// You can create this with a predefined key:
/// ```
/// # use skrillax_security::SilkroadEncryption;
/// let encryption = SilkroadEncryption::from_key(0xFF00FF00FF00FF00);
/// ```
/// Though generally the security should be set up through a handshake.
pub struct SilkroadEncryption {
    blowfish: Box<BlowfishLE>,
}

impl SilkroadEncryption {
    /// Creates an encryption setup from a predefined key.
    pub fn from_key(key: u64) -> Self {
        Self {
            blowfish: Box::new(blowfish_from_int(key)),
        }
    }

    /// Decrypt an encrypted message sent by the client.
    ///
    /// Decrypts the given input by splitting it into the individual encrypted blocks. The output is all decrypted data,
    /// which may contain padding that was added before encryption. Bytes are copied before performing decryption.
    /// To decrypt in place, use [decrypt_mut][Self::decrypt_mut()].
    ///
    /// If the input doesn't match the required block length it will return [SilkroadSecurityError::InvalidBlockLength].
    pub fn decrypt(&self, data: &[u8]) -> Result<Bytes, SilkroadSecurityError> {
        let mut result = bytes::BytesMut::from(data);
        self.decrypt_mut(&mut result)?;
        Ok(result.freeze())
    }

    /// Decrypt an encrypted message sent by the client.
    ///
    /// Decrypts the given input by splitting it into the individual encrypted blocks in place. The decrypted data may
    /// still be padded to match block length (8 bytes).
    ///
    /// If the input doesn't match the required block length it will return [SilkroadSecurityError::InvalidBlockLength].
    pub fn decrypt_mut(&self, data: &mut [u8]) -> Result<(), SilkroadSecurityError> {
        if data.len() % BLOWFISH_BLOCK_SIZE != 0 {
            return Err(SilkroadSecurityError::InvalidBlockLength(data.len()));
        }

        for chunk in data.chunks_mut(BLOWFISH_BLOCK_SIZE) {
            let block = BlowfishBlock::from_mut_slice(chunk);
            self.blowfish.decrypt_block(block);
        }
        Ok(())
    }

    /// Encrypt a message to be sent to the client.
    ///
    /// Encrypts the given bytes using the previously established secret. Requires that the handshake has been completed.
    /// It will copy the bytes and return the encrypted bytes as an owned reference. Bytes will be padded automatically
    /// to the necessary block length. Use [encrypt_mut][Self::encrypt_mut()] for encryption in place.
    pub fn encrypt(&self, data: &[u8]) -> Result<Bytes, SilkroadSecurityError> {
        let target_buffer_size = Self::find_encrypted_length(data.len());
        let mut result = bytes::BytesMut::with_capacity(target_buffer_size);
        result.extend_from_slice(data);
        for _ in 0..(target_buffer_size - data.len()) {
            result.put_u8(0);
        }
        self.encrypt_mut(&mut result)?;
        Ok(result.freeze())
    }

    /// Encrypt a message to be sent to the client.
    ///
    /// Encrypts the given bytes using the previously established secret. Requires that the handshake has been completed
    /// and that `data` is a multiple of the block length.
    ///
    /// If the data is not block-aligned, will result in [SilkroadSecurityError::InvalidBlockLength]
    pub fn encrypt_mut(&self, data: &mut [u8]) -> Result<(), SilkroadSecurityError> {
        if data.len() % BLOCK_SIZE != 0 {
            return Err(SilkroadSecurityError::InvalidBlockLength(data.len()));
        }

        for chunk in data.chunks_mut(BLOWFISH_BLOCK_SIZE) {
            let block = BlowfishBlock::from_mut_slice(chunk);
            self.blowfish.encrypt_block(block);
        }
        Ok(())
    }

    /// Find the nearest block-aligned length.
    ///
    /// Given the current length of data to encrypt, calculates the length of the encrypted output, which includes
    /// padding. Can at most increase by `BLOWFISH_BLOCK_SIZE - 1`, which is `7`.
    pub fn find_encrypted_length(given_length: usize) -> usize {
        let aligned_length = given_length % BLOWFISH_BLOCK_SIZE;
        if aligned_length == 0 {
            // Already block-aligned, no need to pad
            return given_length;
        }

        given_length + (8 - aligned_length) // Add padding
    }
}

pub(crate) fn blowfish_from_int(key: u64) -> BlowfishLE {
    BlowfishLE::new_from_slice(&key.to_le_bytes()).expect("Could not create blowfish key")
}
