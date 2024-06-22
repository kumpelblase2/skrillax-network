//! The handshake module provides both sides of the handshake used to establish
//! the security features of a connection between two Silkroad Online
//! participants, usually a server and a client.
//!
//! The handshake always happens between an active and a passive party. The
//! active party initiates the handshake and determines what features shall be
//! used. The passive party essentially always accepts what is provided by the
//! active party. This handshake how it is implemented here does not
//! concern itself with actually exchanging the information. How that is done is
//! up to the user of this api, and they might choose whatever makes sense in
//! the given situation. You might also choose to use the [skrillax-stream](https://docs.rs/skrillax-stream) crate instead to handle the
//! handshake for you in an async fashion.
//!
//! Generally, the active party is a server, while the passive party is a
//! client. This at least holds true for the official Silkroad Online. Thus, if
//! you want to interface or emulate it, you want to keep these roles. In any
//! other situation, you may choose a different role assignment.
//!
//! The handshake of Silkroad Online is similar to a [Diffie–Hellman key exchange](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange);
//! Each party generates a private key (or something like a key). Then they
//! perform an operation on the private key and share the resulting value. Using
//! the shared value and performing the same operation using their original
//! private key, they can generate a shared secret without having to ever share
//! their private key. I say similar to, because the implementation Silkroad
//! Online uses is a little weaker, as it's pretty easy to brute force, which I have shown in my [decryptor](https://github.com/kumpelblase2/skrillax/tree/master/silkroad-packet-decryptor#why-it-works).
//! After the shared secret has been established, it is used as the key material
//! for a blowfish cipher.
//!
//! Most of the internals are abstracted away in this implementation. If you're
//! looking for a more in-depth overview of how the handshake works, you may want to look at the ['Silkroad Doc'](https://github.com/DummkopfOfHachtenduden/SilkroadDoc/wiki/silkroad-security).
//!
//! Depending on which party you're assuming, you either want to use the
//! [ActiveHandshake], or [PassiveHandshake] if you're assumed to be the active
//! party or passive party respectively.

use crate::{blowfish_from_int, BlowfishBlock, SilkroadEncryption, SilkroadSecurityError};
use bitflags::bitflags;
use blowfish::cipher::{BlockDecrypt, BlockEncrypt};
use blowfish::BlowfishLE;
use byteorder::{ByteOrder, LittleEndian};
use rand::random;

bitflags! {
    /// Defines the available security features of a Silkroad Online connection.
    pub struct SecurityFeature: u8 {
        /// Adds the checks/Generates security bytes (CRC & Count) for all packets.
        const CHECKS = 1;
        /// Allows/Enables the encryption of packets.
        const ENCRYPTION = 2;
    }
}

impl Default for SecurityFeature {
    fn default() -> Self {
        SecurityFeature::all()
    }
}

#[derive(Copy, Clone)]
struct ActiveEncryptionData {
    handshake_seed: u64,
    value_x: u32,
    value_p: u32,
    value_a: u32,
}

#[derive(Default)]
enum ActiveHandshakeState {
    #[default]
    Uninitialized,
    HandshakeStarted {
        encryption_seed: Option<ActiveEncryptionData>,
    },
    Challenged {
        blowfish: Box<BlowfishLE>,
    },
    FinishedEmpty,
}

#[derive(Copy, Clone)]
pub struct PassiveEncryptionInitializationData {
    pub seed: u64,
    pub handshake_seed: u64,
    pub additional_seeds: [u32; 3],
}

#[derive(Copy, Clone)]
pub struct CheckBytesInitialization {
    pub count_seed: u32,
    pub crc_seed: u32,
}

#[derive(Copy, Clone)]
pub struct PassiveInitializationData {
    pub checks: Option<CheckBytesInitialization>,
    pub encryption_seed: Option<PassiveEncryptionInitializationData>,
}

/// Provides the active part of a handshake.
///
/// The active part of the handshake initializes the handshake procedure. It
/// will generate the necessary initialization data and provide the passive part
/// with a challenge, before it will complete the handshake. Generally, you're
/// expected to transfer the returned data to the other side by whatever means
/// appropriate. Depending on the security features that you want, you can
/// decide to end the handshake early. However, the following will assume you
/// want all security features enabled.
///
/// An example procedure would be as follows:
/// ```
/// # use skrillax_security::{ActiveHandshake, PassiveHandshake, SecurityFeature};
/// let mut handshake = ActiveHandshake::default();
/// let init = handshake
///     .initialize(SecurityFeature::all())
///     .expect("Should be able to initialize handshake.");
/// # let mut passive = PassiveHandshake::default();
/// // You should now transfer the data contained in `init` to the other side.
/// // The other side would then give you their public part of their side. With that, you can
/// // generate a challenge.
/// # let (value_key, value_b) = passive.initialize(init.encryption_seed).unwrap().unwrap();
/// // You should get `value_b` & `value_key` from the passive side of the handshake.
/// let challenge = handshake
///     .start_challenge(value_b, value_key)
///     .expect("Should be able to start the challenge.");
/// // This challenge should again be transferred to the other side. At this point the handshake it
/// // technically complete; all data has been exchanged. However, we should wait for the passive
/// // side to acknowledge the challenge.
/// # passive.finish(challenge).unwrap();
/// let encryption = handshake
///     .finish()
///     .expect("Should have finished handshake.")
///     .expect("Encryption should've been established.");
/// ```
#[derive(Default)]
pub struct ActiveHandshake {
    features: SecurityFeature,
    state: ActiveHandshakeState,
}

impl ActiveHandshake {
    /// Starts the handshake process.
    ///
    /// This generates the private key parts and returns
    /// [PassiveInitializationData], which should be transferred to the
    /// client. This should later be followed by calling
    /// [start_challenge()][Self::start_challenge()] with the client response.
    /// The content of the [PassiveInitializationData] may vary depending on
    /// the configured security features.
    ///
    /// If a handshake has already been started or completed, will return
    /// [SilkroadSecurityError::AlreadyInitialized].
    pub fn initialize(
        &mut self,
        features: SecurityFeature,
    ) -> Result<PassiveInitializationData, SilkroadSecurityError> {
        if !matches!(self.state, ActiveHandshakeState::Uninitialized) {
            return Err(SilkroadSecurityError::AlreadyInitialized);
        }

        let check_init = if features.contains(SecurityFeature::CHECKS) {
            Some((u32::from(random::<u8>()), u32::from(random::<u8>())))
        } else {
            None
        };

        if features.contains(SecurityFeature::ENCRYPTION) {
            let seed = random::<u64>();
            let handshake_seed = random::<u64>();
            let value_x = random::<u32>() & 0x7FFFFFFF;
            let value_g = random::<u32>() & 0x7FFFFFFF;
            let value_p = random::<u32>() & 0x7FFFFFFF;
            let value_a = g_pow_x_mod_p(value_p.into(), value_x, value_g);
            self.state = ActiveHandshakeState::HandshakeStarted {
                encryption_seed: Some(ActiveEncryptionData {
                    handshake_seed,
                    value_x,
                    value_p,
                    value_a,
                }),
            };

            Ok(PassiveInitializationData {
                checks: check_init.map(|(crc, count)| CheckBytesInitialization {
                    count_seed: count,
                    crc_seed: crc,
                }),
                encryption_seed: Some(PassiveEncryptionInitializationData {
                    seed,
                    handshake_seed,
                    additional_seeds: [value_g, value_p, value_a],
                }),
            })
        } else {
            self.state = ActiveHandshakeState::FinishedEmpty;
            Ok(PassiveInitializationData {
                checks: check_init.map(|(crc, count)| CheckBytesInitialization {
                    count_seed: count,
                    crc_seed: crc,
                }),
                encryption_seed: None,
            })
        }
    }

    /// Initialize the security with a predefined set of values.
    /// These are the same values that would be generated randomly in
    /// [initialize()]. This effectively does the initialization, just with
    /// the predefined values, resulting in a deterministic handshake.
    #[allow(unused)]
    fn initialize_with(&mut self, encryption_data: Option<ActiveEncryptionData>) {
        self.state = ActiveHandshakeState::HandshakeStarted {
            encryption_seed: encryption_data,
        }
    }

    /// Create a challenge to the client.
    ///
    /// This creates a challenge for the client, signaling a switch to an
    /// encrypted channel using the exchanged key material. We also check if
    /// the key, that the client sent us, matches what we would expect given
    /// what we've witnessed in the key exchange.
    ///
    /// If successful, returns the challenge for the client. If
    /// [initialize][Self::initialize()] hasn't been called,
    /// returns [SilkroadSecurityError::SecurityUninitialized]. If the passed
    /// key does not match the key we expected, will return
    /// [SilkroadSecurityError::KeyExchangeMismatch].
    pub fn start_challenge(
        &mut self,
        value_b: u32,
        client_key: u64,
    ) -> Result<u64, SilkroadSecurityError> {
        let ActiveHandshakeState::HandshakeStarted { encryption_seed } = self.state else {
            return Err(SilkroadSecurityError::SecurityUninitialized);
        };

        let Some(encryption_setup) = encryption_seed else {
            return Err(SilkroadSecurityError::SecurityUninitialized);
        };

        let value_k = g_pow_x_mod_p(
            encryption_setup.value_p.into(),
            encryption_setup.value_x,
            value_b,
        );
        let new_key = to_u64(encryption_setup.value_a, value_b);
        let new_key = transform_key(new_key, value_k, LOBYTE(LOWORD(value_k)) & 0x03);
        let blowfish = blowfish_from_int(new_key);

        let mut key_bytes: [u8; 8] = client_key.to_le_bytes();
        blowfish.decrypt_block(BlowfishBlock::from_mut_slice(&mut key_bytes));

        let client_key = LittleEndian::read_u64(&key_bytes);
        let new_key = to_u64(value_b, encryption_setup.value_a);
        let new_key = transform_key(new_key, value_k, LOBYTE(LOWORD(value_b)) & 0x07);
        if new_key != client_key {
            return Err(SilkroadSecurityError::KeyExchangeMismatch {
                received: client_key,
                calculated: new_key,
            });
        }

        let new_key = to_u64(encryption_setup.value_a, value_b);
        let new_key = transform_key(new_key, value_k, LOBYTE(LOWORD(value_k)) & 0x03);
        let blowfish = blowfish_from_int(new_key);

        let challenge_key = to_u64(encryption_setup.value_a, value_b);
        let challenge_key = transform_key(
            challenge_key,
            value_k,
            LOBYTE(LOWORD(encryption_setup.value_a)) & 0x07,
        );
        let mut key_bytes: [u8; 8] = challenge_key.to_le_bytes();
        blowfish.encrypt_block(BlowfishBlock::from_mut_slice(&mut key_bytes));
        let encrypted_challenge = LittleEndian::read_u64(&key_bytes);

        let handshake_seed = transform_key(encryption_setup.handshake_seed, value_k, 3);

        self.state = ActiveHandshakeState::Challenged {
            blowfish: Box::new(blowfish_from_int(handshake_seed)),
        };

        Ok(encrypted_challenge)
    }

    /// Finishes the handshake process.
    ///
    /// This will try to finish the handshake process, at whatever stage we are.
    /// Depending on the configured settings, this may be at different
    /// stages. If no security features are configured: at any point.
    /// If only check bytes are configured: after initialization.
    /// If encryption is configured: after having created the client challenge.
    pub fn finish(self) -> Result<Option<SilkroadEncryption>, SilkroadSecurityError> {
        match self.state {
            ActiveHandshakeState::Challenged { blowfish } => {
                Ok(Some(SilkroadEncryption { blowfish }))
            },
            ActiveHandshakeState::Uninitialized if self.features.is_empty() => Ok(None),
            ActiveHandshakeState::FinishedEmpty => Ok(None),
            ActiveHandshakeState::HandshakeStarted { encryption_seed }
                if encryption_seed.is_none() =>
            {
                Ok(None)
            },
            _ => Err(SilkroadSecurityError::InitializationUnfinished),
        }
    }
}

struct PassiveEncryptionData {
    blowfish: Box<BlowfishLE>,
    local_public: u32,
    remote_public: u32,
    shared_secret: u32,
    initial_seed: u64,
}

#[derive(Default)]
enum PassiveHandshakeState {
    #[default]
    Uninitialized,
    AuthStarted {
        encryption_seed: Option<PassiveEncryptionData>,
    },
    Challenging {
        blowfish: Box<BlowfishLE>,
    },
}

/// Provides the passive part of the handshake.
///
/// The passive part of the handshake only really responds to the stuff the
/// active part tells it. This includes the enabled features, which cannot be
/// configured here but will be part of the setup sent from the active part.
/// We're currently expecting the other side to initialize a handshake, but this
/// is technically not required. How you deal with that is up to you.
///
/// An example exchange could look like this:
/// ```
/// # use skrillax_security::{ActiveHandshake, PassiveHandshake, SecurityFeature};
/// # let mut handshake = ActiveHandshake::default();
/// # let init = handshake.initialize(SecurityFeature::all()).expect("Should be able to initialize handshake.");
/// let mut passive = PassiveHandshake::default();
/// // The active side will create an initialization, which will be sent to the passive side.
/// // We simply plug that information into our procedure. For now, we assume they're setting up
/// // encryption as well, so we simply `unwrap()` everything here.
/// let (value_key, value_b) = passive.initialize(init.encryption_seed).unwrap().unwrap();
/// // These two values should then be sent to the active side again. That side will then respond
/// // with a challenge for us, to verify everything went fine.
/// # let challenge = handshake.start_challenge(value_b, value_key).expect("Should be able to start the challenge.");
/// passive.finish(challenge).unwrap();
/// // We then need to complete the handshake, which we should signal to the active part as well.
/// // `finish` and `done` are separate things, because if the active part does not actually send
/// // encryption information we can't call `finish`. We'd instead just call `done`.
/// let encryption = passive.done().expect("Handshake should have completed.");
/// ```
#[derive(Default)]
pub struct PassiveHandshake {
    state: PassiveHandshakeState,
}

impl PassiveHandshake {
    /// Initialize the handshake with the data from the active side.
    ///
    /// We have received the initialization data from the active handshake side
    /// and want to initialize our side as well. Depending on the security
    /// features selected by the active side, the initialization data may
    /// actually be `None`, which is why this accepts and [Option].
    /// Technically, if you haven't received any encryption initialization data,
    /// you can simply call [PassiveHandshake::done] and complete the
    /// handshake - there's nothing more to be exchanged.
    /// This is essentially a convenience to stay more consistent with what we
    /// receive from the active part.
    ///
    /// This may error if we're already initialized, returning
    /// [SilkroadSecurityError::InitializationUnfinished].
    pub fn initialize(
        &mut self,
        init: Option<PassiveEncryptionInitializationData>,
    ) -> Result<Option<(u64, u32)>, SilkroadSecurityError> {
        if !matches!(self.state, PassiveHandshakeState::Uninitialized) {
            return Err(SilkroadSecurityError::InitializationUnfinished);
        }

        let (encryption_data, challenge) = if let Some(encryption_setup) = &init {
            let value_g = encryption_setup.additional_seeds[0];
            let value_p = encryption_setup.additional_seeds[1];
            let value_a = encryption_setup.additional_seeds[2];
            let local_private = random::<u32>();
            let remote_public = g_pow_x_mod_p(value_p as i64, local_private, value_g);
            let shared_secret = g_pow_x_mod_p(value_p as i64, local_private, value_a);
            let key = transform_key(
                to_u64(value_a, remote_public),
                shared_secret,
                LOBYTE(LOWORD(shared_secret)) & 0x03,
            );
            let blowfish = blowfish_from_int(key);
            let challenge = transform_key(
                to_u64(remote_public, value_a),
                shared_secret,
                LOBYTE(LOWORD(remote_public)) & 0x07,
            );
            let mut challenge_bytes: [u8; 8] = challenge.to_le_bytes();
            blowfish.encrypt_block(BlowfishBlock::from_mut_slice(&mut challenge_bytes));
            let encrypted_challenge = u64::from_le_bytes(challenge_bytes);
            (
                Some(PassiveEncryptionData {
                    blowfish: Box::new(blowfish),
                    local_public: value_a,
                    remote_public,
                    shared_secret,
                    initial_seed: encryption_setup.handshake_seed,
                }),
                Some((encrypted_challenge, remote_public)),
            )
        } else {
            (None, None)
        };

        self.state = PassiveHandshakeState::AuthStarted {
            encryption_seed: encryption_data,
        };

        Ok(challenge)
    }

    /// Complete the handshake by verifying the challenge.
    ///
    /// After we have sent our initialization data to the active part, they
    /// provide us with a sort of challenge. If we can verify the challenge
    /// with what we internally calculated, we know the key exchange was
    /// successful, and we now have a shared secret. At this point, the
    /// handshake is essentially completed. This should be signaled to the
    /// active side by switching to an encrypted channel.
    pub fn finish(&mut self, challenge: u64) -> Result<(), SilkroadSecurityError> {
        let PassiveHandshakeState::AuthStarted {
            encryption_seed: Some(ref encryption_data),
        } = self.state
        else {
            return Err(SilkroadSecurityError::InitializationUnfinished);
        };

        let expected = to_u64(encryption_data.local_public, encryption_data.remote_public);
        let expected_key = transform_key(
            expected,
            encryption_data.shared_secret,
            LOBYTE(LOWORD(encryption_data.local_public)) & 0x07,
        );
        let mut expected_key_bytes: [u8; 8] = expected_key.to_le_bytes();
        encryption_data
            .blowfish
            .encrypt_block(BlowfishBlock::from_mut_slice(&mut expected_key_bytes));
        let encrypted_key = u64::from_le_bytes(expected_key_bytes);
        if encrypted_key != challenge {
            return Err(SilkroadSecurityError::KeyExchangeMismatch {
                received: challenge,
                calculated: encrypted_key,
            });
        }
        let transformed_key = transform_key(
            encryption_data.initial_seed,
            encryption_data.shared_secret,
            3,
        );
        let blowfish = Box::new(blowfish_from_int(transformed_key));

        self.state = PassiveHandshakeState::Challenging { blowfish };

        Ok(())
    }

    /// Return the resulting encryption from the handshake.
    ///
    /// If the selected security features of the active handshake part included
    /// setting up the encryption, the final result will be returned. If it
    /// didn't contain that feature, it will return `None` instead.
    ///
    /// Will return [SilkroadSecurityError::InitializationUnfinished] if we
    /// haven't completed the handshake yet.
    pub fn done(self) -> Result<Option<SilkroadEncryption>, SilkroadSecurityError> {
        match self.state {
            PassiveHandshakeState::AuthStarted { encryption_seed } if encryption_seed.is_some() => {
                Err(SilkroadSecurityError::InitializationUnfinished)
            },
            PassiveHandshakeState::Challenging { blowfish } => {
                Ok(Some(SilkroadEncryption { blowfish }))
            },
            _ => Ok(None),
        }
    }
}

#[allow(unused_parens)]
fn transform_key(val: u64, key: u32, key_byte: u8) -> u64 {
    let mut stream = val.to_le_bytes();

    stream[0] ^= (stream[0]
        .wrapping_add(LOBYTE(LOWORD(key)))
        .wrapping_add(key_byte));
    stream[1] ^= (stream[1]
        .wrapping_add(HIBYTE(LOWORD(key)))
        .wrapping_add(key_byte));
    stream[2] ^= (stream[2]
        .wrapping_add(LOBYTE(HIWORD(key)))
        .wrapping_add(key_byte));
    stream[3] ^= (stream[3]
        .wrapping_add(HIBYTE(HIWORD(key)))
        .wrapping_add(key_byte));
    stream[4] ^= (stream[4]
        .wrapping_add(LOBYTE(LOWORD(key)))
        .wrapping_add(key_byte));
    stream[5] ^= (stream[5]
        .wrapping_add(HIBYTE(LOWORD(key)))
        .wrapping_add(key_byte));
    stream[6] ^= (stream[6]
        .wrapping_add(LOBYTE(HIWORD(key)))
        .wrapping_add(key_byte));
    stream[7] ^= (stream[7]
        .wrapping_add(HIBYTE(HIWORD(key)))
        .wrapping_add(key_byte));

    LittleEndian::read_u64(&stream)
}

#[allow(non_snake_case)]
fn LOWORD(a: u32) -> u16 {
    (a & 0xFFFF) as u16
}

#[allow(non_snake_case)]
fn HIWORD(a: u32) -> u16 {
    ((a >> 16) & 0xFFFF) as u16
}

#[allow(non_snake_case)]
fn LOBYTE(a: u16) -> u8 {
    (a & 0xFF) as u8
}

#[allow(non_snake_case)]
fn HIBYTE(a: u16) -> u8 {
    ((a >> 8) & 0xFF) as u8
}

fn g_pow_x_mod_p(p: i64, mut x: u32, g: u32) -> u32 {
    let mut current: i64 = 1;
    let mut mult: i64 = g as i64;

    while x != 0 {
        if (x & 1) > 0 {
            current = (mult * current) % p;
        }
        x >>= 1;
        mult = (mult * mult) % p;
    }
    current as u32
}

fn to_u64(low: u32, high: u32) -> u64 {
    ((high as u64) << 32) | low as u64
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_equal() {
        let mut server_handshake = ActiveHandshake::default();
        let mut client_handshake = PassiveHandshake::default();

        let init = server_handshake
            .initialize(SecurityFeature::all())
            .expect("should be able to initialize");
        assert!(init.encryption_seed.is_some());
        assert!(init.checks.is_some());
        let (key, value_b) = client_handshake
            .initialize(init.encryption_seed)
            .expect("should accept initialization")
            .unwrap();
        let response = server_handshake
            .start_challenge(value_b, key)
            .expect("should accept challenge");
        client_handshake
            .finish(response)
            .expect("should do challenge");
        let active_encryption = server_handshake
            .finish()
            .expect("server should be finished.")
            .unwrap();
        let passive_encryption = client_handshake
            .done()
            .expect("client should be finished.")
            .unwrap();

        let encrypted = active_encryption
            .encrypt(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
            .expect("Should be able to encrypt");

        let decrypted = passive_encryption
            .decrypt(&encrypted)
            .expect("Should be able to decrypt");

        assert_eq!(
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            decrypted.as_ref()
        );
    }

    #[test]
    fn finishes_encoding() {
        let handshake_seed =
            LittleEndian::read_u64(&[0xbf, 0x89, 0x96, 0x76, 0xae, 0x97, 0x5e, 0x17]);
        let _value_g = LittleEndian::read_u32(&[0x95, 0x0b, 0xf5, 0x20]);
        let value_p = LittleEndian::read_u32(&[0x0d, 0xf4, 0x13, 0x52]);
        let value_x = 189993144; // brute forced
        let value_a = LittleEndian::read_u32(&[0x36, 0x44, 0x96, 0x24]);

        let mut security = ActiveHandshake::default();
        security.initialize_with(Some(ActiveEncryptionData {
            handshake_seed,
            value_x,
            value_p,
            value_a,
        }));

        let value_b = LittleEndian::read_u32(&[0x7a, 0x04, 0x39, 0x43]);
        let key = LittleEndian::read_u64(&[0x69, 0x02, 0xec, 0x3f, 0x16, 0xbb, 0x18, 0x64]);

        let result = security.start_challenge(value_b, key).unwrap();

        let result_expected_bytes = &[0xbe, 0x6f, 0x5e, 0xd4, 0x19, 0x79, 0x7d, 0x26];
        let result_expected = LittleEndian::read_u64(result_expected_bytes);

        assert_eq!(result, result_expected);
        assert!(security.finish().is_ok());
    }
}
