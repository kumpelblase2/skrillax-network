use crate::stream::{SilkroadStreamRead, SilkroadStreamWrite, StreamError};
use skrillax_packet::{OutgoingPacket, Packet};
use skrillax_security::{ServerSecuritySetup, SilkroadSecurityError};
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
enum HandshakeError {
    #[error("An error occurred at the stream level")]
    StreamError(#[from] StreamError),
    #[error("A security level error occurred")]
    SecurityError(#[from] SilkroadSecurityError),
    #[error("Expected to receive a challenge, but received something else")]
    NoChallengeReceived,
    #[error("We didn't get an acknowledgment for the challenge response")]
    FinalizationNotAccepted,
}

#[derive(Packet, ByteSize, Serialize, Deserialize)]
#[packet(opcode = 0x5000)]
enum InitializeSecurityCapabilities {
    #[silkroad(value = 0x0E)]
    Initialize {
        blowfish_seed: u64,
        seed_count: u32,
        seed_crc: u32,
        handshake_seed: u64,
        a: u32,
        b: u32,
        c: u32,
    },
    #[silkroad(value = 0x10)]
    Finalize { challenge: u64 },
}

define_protocol! {
    HanshakeActiveProtocol,
    InitializeSecurityCapabilities
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

pub struct SecuritySetup<'a> {
    reader: &'a mut SilkroadStreamRead,
    writer: &'a mut SilkroadStreamWrite,
}

impl SecuritySetup<'_> {
    pub async fn initialize(mut self) -> Result<(), HandshakeError> {
        let (mut reader, mut writer) = (self.reader, self.writer);
        let mut setup = ServerSecuritySetup::default();
        let init = setup.initialize()?;
        let init_packet = InitializeSecurityCapabilities::Initialize {
            blowfish_seed: init.seed,
            seed_count: init.count_seed,
            seed_crc: init.crc_seed,
            handshake_seed: init.handshake_seed,
            a: init.additional_seeds[0],
            b: init.additional_seeds[1],
            c: init.additional_seeds[2],
        };
        writer
            .send::<HanshakeActiveProtocol>(init_packet.into())
            .await?;

        let response = reader.next_packet::<HandshakePassiveProtocol>().await?;
        let HandshakePassiveProtocol::HandshakeChallenge(challenge) = response else {
            return Err(HandshakeError::NoChallengeReceived);
        };

        let challenge = setup.start_challenge(challenge.b, challenge.key)?;
        writer
            .send::<HanshakeActiveProtocol>(
                InitializeSecurityCapabilities::Finalize { challenge }.into(),
            )
            .await?;

        let response = reader.next_packet::<HandshakePassiveProtocol>().await?;
        if !matches!(response, HandshakePassiveProtocol::HandshakeAccepted(_)) {
            return Err(HandshakeError::FinalizationNotAccepted);
        }

        let security = setup.finish()?;
        let security = Arc::new(security);
        reader.enable_encryption(Arc::clone(&security));
        writer.enable_encryption(security);

        Ok(())
    }
}
