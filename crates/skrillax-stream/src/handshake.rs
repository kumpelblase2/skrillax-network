//! The handshake module provides procedures to asynchronously handle the
//! handshake.
//!
//! In most cases, the first thing that happens in a connection between a
//! Silkroad server and client is the security handshake. This should always
//! happend, but doesn't necessarily have to establish encryption. The handshake
//! is split into the active part and the passive part. In normal operation, the
//! server takes on the active role, while the client takes on the passive role.
//! Active in this case means it will actively initiate the handshake, while the
//! passive party will wait for the handshake to be initiated. Therefor, a
//! server would use the [ActiveSecuritySetup], while a client would turn to the
//! [PassiveSecuritySetup]. Both operate on a Silkroad Stream, i.e. a
//! [crate::stream::SilkroadStreamRead]
//! and [crate::stream::SilkroadStreamWrite].
//!
//! Both sides provide a `handle` method which will complete the handshake from
//! its perspective:
//!
//! ```no_run
//! # async fn test() {
//! # use tokio::net::TcpSocket;
//! # use skrillax_stream::stream::SilkroadTcpExt;
//! # use skrillax_stream::handshake::ActiveSecuritySetup;
//! # use skrillax_stream::handshake::PassiveSecuritySetup;
//! # let listen_addr = "127.0.0.1:1337".parse().unwrap();
//! # let socket = TcpSocket::new_v4().unwrap().connect(listen_addr).await.unwrap();
//! let (mut reader, mut writer) = socket.into_silkroad_stream();
//! ActiveSecuritySetup::handle(&mut reader, &mut writer)
//!     .await
//!     .expect("Active setup should complete.");
//! // OR
//! PassiveSecuritySetup::handle(&mut reader, &mut writer)
//!     .await
//!     .expect("Passive setup should complete.");
//! # }
//! ```
//!
//! After the handshake is finished, we can continue using the reader and writer
//! to send packets. If we used the default or specifically configured
//! encryption as a security feature, we can also now send and receive encrypted
//! packets.

use crate::stream::{
    InStreamError, InputProtocol, OutStreamError, SilkroadStreamRead, SilkroadStreamWrite,
};
use bitflags::bitflags;
use skrillax_packet::{
    AsPacket, OutgoingPacket, Packet, PacketError, SecurityBytes, TryFromPacket,
};
use skrillax_security::handshake::{CheckBytesInitialization, PassiveEncryptionInitializationData};
use skrillax_security::{
    ActiveHandshake, PassiveHandshake, SecurityFeature, SilkroadSecurityError,
};
use skrillax_serde::{ByteSize, Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};

#[derive(Error, Debug)]
pub enum HandshakeError {
    #[error("An error occurred while receiving data")]
    InputError(#[from] InStreamError),
    #[error("An error occurred while writing data")]
    OutputError(#[from] OutStreamError),
    #[error("A security level error occurred")]
    SecurityError(#[from] SilkroadSecurityError),
    #[error("An error occurred at the packet level")]
    PacketError(#[from] PacketError),
    #[error("Expected to receive a challenge, but received something else")]
    NoChallengeReceived,
    #[error("We didn't get an acknowledgment for the challenge response")]
    FinalizationNotAccepted,
    #[error("The flag inside the security packet did not match our expectations")]
    InvalidContentFlag,
}

#[derive(Serialize, Deserialize, ByteSize, Copy, Clone, Eq, PartialEq, Debug)]
struct HandshakeContent(u8);

impl Default for HandshakeContent {
    fn default() -> Self {
        Self::empty()
    }
}

bitflags! {
    impl HandshakeContent: u8 {
        const NONE = 1;
        const INIT_BLOWFISH = 2;
        const SETUP_CHECKS = 4;
        const START_HANDSHAKE = 8;
        const FINISH = 16;
    }
}

#[derive(Serialize, ByteSize, Deserialize, Copy, Clone, Debug)]
struct HandshakeInitialization {
    handshake_seed: u64,
    a: u32,
    b: u32,
    c: u32,
}

#[derive(Packet, ByteSize, Serialize, Deserialize, Default, Copy, Clone, Debug)]
#[packet(opcode = 0x5000)]
struct SecurityCapabilityCheck {
    flag: HandshakeContent,
    #[silkroad(when = "flag.contains(HandshakeContent::INIT_BLOWFISH)")]
    blowfish_seed: Option<u64>,
    #[silkroad(when = "flag.contains(HandshakeContent::SETUP_CHECKS)")]
    seed_count: Option<u32>,
    #[silkroad(when = "flag.contains(HandshakeContent::SETUP_CHECKS)")]
    seed_crc: Option<u32>,
    #[silkroad(when = "flag.contains(HandshakeContent::START_HANDSHAKE)")]
    handshake_init: Option<HandshakeInitialization>,
    #[silkroad(when = "flag.contains(HandshakeContent::FINISH)")]
    challenge: Option<u64>,
}

impl SecurityCapabilityCheck {
    fn check_bytes_init(&self) -> Option<CheckBytesInitialization> {
        match (self.seed_crc, self.seed_count) {
            (Some(crc_seed), Some(count_seed)) => Some(CheckBytesInitialization {
                count_seed,
                crc_seed,
            }),
            _ => None,
        }
    }

    fn passive_encryption_init(&self) -> Option<PassiveEncryptionInitializationData> {
        match (self.blowfish_seed, self.handshake_init) {
            (Some(seed), Some(init)) => Some(PassiveEncryptionInitializationData {
                seed,
                handshake_seed: init.handshake_seed,
                additional_seeds: [init.a, init.b, init.c],
            }),
            _ => None,
        }
    }
}

impl From<SecurityCapabilityCheck> for HandshakeActiveProtocol {
    fn from(value: SecurityCapabilityCheck) -> Self {
        HandshakeActiveProtocol::SecurityCapabilityCheck(value)
    }
}

enum HandshakeActiveProtocol {
    SecurityCapabilityCheck(SecurityCapabilityCheck),
}

impl From<&HandshakeActiveProtocol> for OutgoingPacket {
    fn from(value: &HandshakeActiveProtocol) -> Self {
        match value {
            HandshakeActiveProtocol::SecurityCapabilityCheck(check) => check.as_packet(),
        }
    }
}

impl InputProtocol for HandshakeActiveProtocol {
    type Proto = HandshakeActiveProtocol;

    fn create_from(opcode: u16, data: &[u8]) -> Result<(usize, Self), InStreamError> {
        match opcode {
            SecurityCapabilityCheck::ID => {
                let (consumed, check) = SecurityCapabilityCheck::try_deserialize(data)?;
                Ok((
                    consumed,
                    HandshakeActiveProtocol::SecurityCapabilityCheck(check),
                ))
            },
            _ => Err(InStreamError::UnmatchedOpcode(opcode)),
        }
    }
}

#[derive(Packet, ByteSize, Serialize, Deserialize, Debug)]
#[packet(opcode = 0x5000)]
struct HandshakeChallenge {
    pub b: u32,
    pub key: u64,
}

impl From<HandshakeChallenge> for HandshakePassiveProtocol {
    fn from(value: HandshakeChallenge) -> Self {
        HandshakePassiveProtocol::HandshakeChallenge(value)
    }
}

#[derive(Packet, ByteSize, Serialize, Deserialize, Debug)]
#[packet(opcode = 0x9000)]
struct HandshakeAccepted;

impl From<HandshakeAccepted> for HandshakePassiveProtocol {
    fn from(value: HandshakeAccepted) -> Self {
        HandshakePassiveProtocol::HandshakeAccepted(value)
    }
}

enum HandshakePassiveProtocol {
    HandshakeChallenge(HandshakeChallenge),
    HandshakeAccepted(HandshakeAccepted),
}

impl InputProtocol for HandshakePassiveProtocol {
    type Proto = HandshakePassiveProtocol;

    fn create_from(opcode: u16, data: &[u8]) -> Result<(usize, Self), InStreamError> {
        match opcode {
            HandshakeAccepted::ID => {
                let (consumed, accepted) = HandshakeAccepted::try_deserialize(data)?;
                Ok((
                    consumed,
                    HandshakePassiveProtocol::HandshakeAccepted(accepted),
                ))
            },
            HandshakeChallenge::ID => {
                let (consumed, challenge) = HandshakeChallenge::try_deserialize(data)?;
                Ok((
                    consumed,
                    HandshakePassiveProtocol::HandshakeChallenge(challenge),
                ))
            },
            _ => Err(InStreamError::UnmatchedOpcode(opcode)),
        }
    }
}

impl From<&HandshakePassiveProtocol> for OutgoingPacket {
    fn from(value: &HandshakePassiveProtocol) -> Self {
        match value {
            HandshakePassiveProtocol::HandshakeChallenge(challenge) => challenge.as_packet(),
            HandshakePassiveProtocol::HandshakeAccepted(accept) => accept.as_packet(),
        }
    }
}

/// Active part of a Silkroad Online connection handshake.
///
/// The active part in a handshake thats the initialization process and will
/// also decide the security features ([SecurityFeature]) available for the
/// connection. By default, all security features will be made available.
/// Using [ActiveSecuritySetup::handle] will default to all features, while
/// [ActiveSecuritySetup::handle_with_features] allows you to pick which
/// features should be enabled, if any.
///
/// ```ignore
/// AsyncSecuritySetup::handle(&mut reader, &mut writer).await
/// // OR
/// AsyncSecuritySetup::handle_with_features(&mut reader, &mut writer, SecurityFeature::CHECKS).await
/// ```
///
/// Once complete, it will set the [skrillax_packet::SecurityContext] of the
/// reader & writer with the enabled features. This will then allow, for
/// example, sending and receiving of encrypted packets.
pub struct ActiveSecuritySetup<'a, T: AsyncRead + Unpin, S: AsyncWrite + Unpin> {
    reader: &'a mut SilkroadStreamRead<T>,
    writer: &'a mut SilkroadStreamWrite<S>,
    enabled_features: SecurityFeature,
}

impl<T: AsyncRead + Unpin, S: AsyncWrite + Unpin> ActiveSecuritySetup<'_, T, S> {
    /// Starts and executes the handshake procedures as the active participant
    /// with default security features.
    pub async fn handle(
        reader: &mut SilkroadStreamRead<T>,
        writer: &mut SilkroadStreamWrite<S>,
    ) -> Result<(), HandshakeError> {
        ActiveSecuritySetup {
            reader,
            writer,
            enabled_features: SecurityFeature::all(),
        }
        .initialize()
        .await
    }

    /// Starts and executes the handshake procedures as the active participant
    /// with predefined security features.
    pub async fn handle_with_features(
        reader: &mut SilkroadStreamRead<T>,
        writer: &mut SilkroadStreamWrite<S>,
        enabled_features: SecurityFeature,
    ) -> Result<(), HandshakeError> {
        ActiveSecuritySetup {
            reader,
            writer,
            enabled_features,
        }
        .initialize()
        .await
    }

    async fn initialize(self) -> Result<(), HandshakeError> {
        let (reader, writer) = (self.reader, self.writer);
        let mut setup = ActiveHandshake::default();
        let init = setup.initialize(self.enabled_features)?;

        if let Some(checks) = init.checks.as_ref() {
            let security_bytes = Arc::new(SecurityBytes::from_seeds(
                checks.crc_seed,
                checks.count_seed,
            ));
            reader.enable_security_checks(security_bytes);
        }

        let mut flag = HandshakeContent::START_HANDSHAKE;
        let (blowfish_seed, encryption) = if let Some(encryption) = &init.encryption_seed {
            flag |= HandshakeContent::INIT_BLOWFISH;
            (
                Some(encryption.seed),
                Some(HandshakeInitialization {
                    handshake_seed: encryption.handshake_seed,
                    a: encryption.additional_seeds[0],
                    b: encryption.additional_seeds[1],
                    c: encryption.additional_seeds[2],
                }),
            )
        } else {
            (None, None)
        };

        let (crc, count) = if let Some(checks) = &init.checks {
            flag |= HandshakeContent::SETUP_CHECKS;
            (Some(checks.crc_seed), Some(checks.count_seed))
        } else {
            (None, None)
        };

        let init_packet = SecurityCapabilityCheck {
            flag: HandshakeContent::INIT_BLOWFISH
                | HandshakeContent::SETUP_CHECKS
                | HandshakeContent::START_HANDSHAKE,
            blowfish_seed,
            seed_count: count,
            seed_crc: crc,
            handshake_init: encryption,
            ..Default::default()
        };
        writer.write_packet(init_packet).await?;

        let response = reader.next_packet::<HandshakePassiveProtocol>().await?;

        let HandshakePassiveProtocol::HandshakeChallenge(challenge) = response else {
            return Err(HandshakeError::NoChallengeReceived);
        };

        let challenge = setup.start_challenge(challenge.b, challenge.key)?;
        writer
            .write_packet(SecurityCapabilityCheck {
                flag: HandshakeContent::FINISH,
                challenge: Some(challenge),
                ..Default::default()
            })
            .await?;

        let response = reader.next_packet::<HandshakePassiveProtocol>().await?;
        if !matches!(response, HandshakePassiveProtocol::HandshakeAccepted(_)) {
            return Err(HandshakeError::FinalizationNotAccepted);
        }

        if let Some(encryption) = setup.finish()? {
            let security = Arc::new(encryption);
            reader.enable_encryption(Arc::clone(&security));
            writer.enable_encryption(security);
        }

        Ok(())
    }
}

/// Passive part of a Silkroad Online connection handshake.
///
/// The passive part of the handshake simply accepts the settings the
/// active part suggests to use and there is no negotiation happening.
/// Right now, we expect the other part of the connection to be the
/// active part and also that it will want to do a handshake. We do not
/// yet account for both sides to be passive.
///
/// Since we're play not active role in choosing which features are
/// available, there's only one way to perform the handshake:
/// ```ignore
/// PassiveSecuritySetup::handle(&mut reader, &mut writer).await
/// ```
///
/// Similarly to the active setup, this will configure the security
/// context in the reader & writer according to the features set by the
/// active part.
pub struct PassiveSecuritySetup<'a, T: AsyncRead + Unpin, S: AsyncWrite + Unpin> {
    reader: &'a mut SilkroadStreamRead<T>,
    writer: &'a mut SilkroadStreamWrite<S>,
}

impl<T: AsyncRead + Unpin, S: AsyncWrite + Unpin> PassiveSecuritySetup<'_, T, S> {
    /// Perform the handshake with the features decided by the active part.
    pub async fn handle(
        reader: &mut SilkroadStreamRead<T>,
        writer: &mut SilkroadStreamWrite<S>,
    ) -> Result<(), HandshakeError> {
        PassiveSecuritySetup { reader, writer }.initialize().await
    }

    async fn initialize(self) -> Result<(), HandshakeError> {
        let (reader, writer) = (self.reader, self.writer);
        let mut handshake = PassiveHandshake::default();

        let init = reader.next_packet::<HandshakeActiveProtocol>().await?;
        let HandshakeActiveProtocol::SecurityCapabilityCheck(capability) = init;

        if capability.flag == HandshakeContent::NONE {
            return Ok(());
        }

        if let Some(checks) = capability.check_bytes_init() {
            let security_bytes = Arc::new(SecurityBytes::from_seeds(
                checks.crc_seed,
                checks.count_seed,
            ));
            writer.enable_security_checks(security_bytes);
        }

        let encryption_seed = capability.passive_encryption_init();
        let challenge = handshake.initialize(encryption_seed)?;

        if let Some((key, b)) = challenge {
            writer.write_packet(HandshakeChallenge { b, key }).await?;

            let finalize = reader.next_packet::<HandshakeActiveProtocol>().await?;
            let HandshakeActiveProtocol::SecurityCapabilityCheck(capability) = finalize;
            if !capability.flag == HandshakeContent::FINISH {
                return Err(HandshakeError::InvalidContentFlag);
            }

            let Some(challenge) = capability.challenge else {
                return Err(HandshakeError::NoChallengeReceived);
            };

            handshake.finish(challenge)?;
            writer.write_packet(HandshakeAccepted).await?;
        }

        if let Some(encryption) = handshake.done()? {
            let encryption = Arc::new(encryption);
            reader.enable_encryption(Arc::clone(&encryption));
            writer.enable_encryption(encryption);
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::stream::SilkroadTcpExt;
    use tokio::net::TcpSocket;

    #[derive(Packet, ByteSize, Serialize, Deserialize)]
    #[packet(opcode = 0x4242, encrypted = true)]
    struct Test {
        content: String,
    }

    #[tokio::test]
    async fn test() {
        let server = TcpSocket::new_v4().unwrap();
        server.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let listen_addr = server.local_addr().unwrap();
        let server_listener = server.listen(0).unwrap();
        let server_await = tokio::spawn(async move {
            let (client_socket, _) = server_listener.accept().await.unwrap();
            let (mut reader, mut writer) = client_socket.into_silkroad_stream();
            ActiveSecuritySetup::handle(&mut reader, &mut writer)
                .await
                .unwrap();
            assert!(reader.encryption().is_some());
            assert!(writer.encryption().is_some());
            let packet = reader.next_packet::<Test>().await.unwrap();
            assert_eq!(packet.content, "Hello!");
        });

        let client = TcpSocket::new_v4()
            .unwrap()
            .connect(listen_addr)
            .await
            .unwrap();
        let (mut reader, mut writer) = client.into_silkroad_stream();
        PassiveSecuritySetup::handle(&mut reader, &mut writer)
            .await
            .unwrap();
        assert!(reader.encryption().is_some());
        assert!(writer.encryption().is_some());
        writer
            .write_packet(Test {
                content: String::from("Hello!"),
            })
            .await
            .unwrap();
        server_await.await.unwrap();
    }
}
