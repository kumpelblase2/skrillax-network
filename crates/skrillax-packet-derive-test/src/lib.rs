#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use skrillax_packet::{OutgoingPacket, Packet, TryFromPacket, TryIntoPacket};
    use skrillax_serde::{ByteSize, Deserialize, Serialize};

    #[derive(Packet, ByteSize, Serialize, Deserialize)]
    #[packet(opcode = 0x0001)]
    struct TestPacket {}

    #[derive(Packet, ByteSize, Serialize)]
    #[packet(opcode = 0x0001)]
    struct TestSerializeOnly {
        field: u16,
    }

    #[derive(Packet, Deserialize)]
    #[packet(opcode = 0x0001)]
    struct TestDeserializeOnly {
        field: u16,
    }

    #[test]
    fn test_serialize() {
        assert!(!TestPacket::MASSIVE);
        assert!(!TestPacket::ENCRYPTED);
        assert_eq!(TestPacket::ID, 0x0001);

        assert_eq!(
            OutgoingPacket::Simple {
                opcode: 0x0001,
                data: Bytes::copy_from_slice(&[0x00, 0x00]),
            },
            TestSerializeOnly { field: 0 }.serialize()
        );
    }

    #[test]
    fn test_deserialize() {
        let (_, deserialized) =
            TestDeserializeOnly::try_deserialize(0x0001, &[0x42, 0x42]).unwrap();
        assert_eq!(deserialized.field, 0x4242);
    }
}
