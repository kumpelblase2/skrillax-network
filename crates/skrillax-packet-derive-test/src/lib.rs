#[cfg(test)]
mod tests {
    use bytes::{Bytes, BytesMut};
    use skrillax_packet::{OutgoingPacket, Packet, TryIntoPacket};
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
    fn test() {
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
}
