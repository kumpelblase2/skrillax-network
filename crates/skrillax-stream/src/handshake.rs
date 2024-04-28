use crate::stream::{SilkroadStreamRead, SilkroadStreamWrite, StreamError};
use bitflags::bitflags;
use skrillax_packet::{OutgoingPacket, Packet, SecurityBytes};
use skrillax_security::handshake::{CheckBytesInitialization, PassiveEncryptionInitializationData};
use skrillax_security::{
    ActiveHandshake, PassiveHandshake, SecurityFeature, SilkroadSecurityError,
};
use skrillax_serde::{ByteSize, Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;

macro_rules! define_protocol {
    ($name:ident, $($enumValue:ident),*) => {
        enum $name {
            $(
                $enumValue($enumValue),
            )*
        }

        impl skrillax_packet::TryFromPacket for $name {
            fn try_deserialize(opcode: u16, data: &[u8]) -> Result<(usize, Self), skrillax_packet::PacketError> {
                match opcode {
                    $(
                        $enumValue::ID => {
                            let (consumed, res) = $enumValue::try_deserialize(opcode, data)?;
                            Ok((consumed, $name::$enumValue(res)))
                        }
                    )*
                    _ => Err(skrillax_packet::PacketError::MismatchedOpcode {
                        expected: 0,
                        received: opcode
                    })
                }
            }
        }

        impl skrillax_packet::TryIntoPacket for $name {
            fn serialize(&self) -> OutgoingPacket {
                match self {
                    $(
                        $name::$enumValue(inner) => inner.serialize(),
                    )*
                }
            }
        }

        $(
            impl From<$enumValue> for $name {
                fn from(value: $enumValue) -> Self {
                    $name::$enumValue(value)
                }
            }
        )*
    };
}

#[derive(Error, Debug)]
pub enum HandshakeError {
    #[error("An error occurred at the stream level")]
    StreamError(#[from] StreamError),
    #[error("A security level error occurred")]
    SecurityError(#[from] SilkroadSecurityError),
    #[error("Expected to receive a challenge, but received something else")]
    NoChallengeReceived,
    #[error("We didn't get an acknowledgment for the challenge response")]
    FinalizationNotAccepted,
    #[error("The flag inside the security packet did not match our expectations")]
    InvalidContentFlag,
}

#[derive(Serialize, Deserialize, ByteSize, Copy, Clone, Eq, PartialEq)]
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

#[derive(Serialize, ByteSize, Deserialize, Copy, Clone)]
struct HandshakeInitialization {
    handshake_seed: u64,
    a: u32,
    b: u32,
    c: u32,
}

#[derive(Packet, ByteSize, Serialize, Deserialize, Default, Copy, Clone)]
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

define_protocol! {
    HandshakeActiveProtocol,
    SecurityCapabilityCheck
}

#[derive(Packet, ByteSize, Serialize, Deserialize)]
#[packet(opcode = 0x5000)]
pub struct HandshakeChallenge {
    pub b: u32,
    pub key: u64,
}

#[derive(Packet, ByteSize, Serialize, Deserialize)]
#[packet(opcode = 0x9000)]
pub struct HandshakeAccepted;

define_protocol! {
    HandshakePassiveProtocol,
    HandshakeChallenge,
    HandshakeAccepted
}

pub struct ActiveSecuritySetup<'a> {
    reader: &'a mut SilkroadStreamRead,
    writer: &'a mut SilkroadStreamWrite,
}

impl ActiveSecuritySetup<'_> {
    pub async fn handle(
        reader: &mut SilkroadStreamRead,
        writer: &mut SilkroadStreamWrite,
    ) -> Result<(), HandshakeError> {
        ActiveSecuritySetup { reader, writer }.initialize().await
    }

    pub async fn initialize(self) -> Result<(), HandshakeError> {
        let (reader, writer) = (self.reader, self.writer);
        let mut setup = ActiveHandshake::default();
        let init = setup.initialize(SecurityFeature::all())?;

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
        writer
            .send::<HandshakeActiveProtocol>(init_packet.into())
            .await?;

        let response = reader.next_packet::<HandshakePassiveProtocol>().await?;
        let HandshakePassiveProtocol::HandshakeChallenge(challenge) = response else {
            return Err(HandshakeError::NoChallengeReceived);
        };

        let challenge = setup.start_challenge(challenge.b, challenge.key)?;
        writer
            .send::<HandshakeActiveProtocol>(
                SecurityCapabilityCheck {
                    flag: HandshakeContent::FINISH,
                    challenge: Some(challenge),
                    ..Default::default()
                }
                .into(),
            )
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

pub struct PassiveSecuritySetup<'a> {
    reader: &'a mut SilkroadStreamRead,
    writer: &'a mut SilkroadStreamWrite,
}

impl PassiveSecuritySetup<'_> {
    pub async fn handle(
        reader: &mut SilkroadStreamRead,
        writer: &mut SilkroadStreamWrite,
    ) -> Result<(), HandshakeError> {
        PassiveSecuritySetup { reader, writer }.initialize().await
    }

    pub async fn initialize(self) -> Result<(), HandshakeError> {
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
            writer
                .send::<HandshakePassiveProtocol>(HandshakeChallenge { b, key }.into())
                .await?;

            let finalize = reader.next_packet::<HandshakeActiveProtocol>().await?;
            let HandshakeActiveProtocol::SecurityCapabilityCheck(capability) = finalize;
            if !capability.flag == HandshakeContent::FINISH {
                return Err(HandshakeError::InvalidContentFlag);
            }

            let Some(challenge) = capability.challenge else {
                return Err(HandshakeError::NoChallengeReceived);
            };

            handshake.finish(challenge)?;
            writer
                .send::<HandshakePassiveProtocol>(HandshakeAccepted.into())
                .await?;
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
            .send(Test {
                content: String::from("Hello!"),
            })
            .await
            .unwrap();
        server_await.await.unwrap();
    }
}
