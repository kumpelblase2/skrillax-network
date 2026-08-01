#![cfg(feature = "serde")]

use bytes::{BufMut, Bytes, BytesMut};
use skrillax_codec::{MAX_MASSIVE_CONTAINER_INNER_SIZE, SilkroadFrame};
use skrillax_packet::{
    AsFrames, AsPacket, FramingError, FromFrames, IncomingPacket, OutgoingPacket, Packet,
    SecurityContext,
};
use skrillax_serde::{ByteSize, SerdeContext, Serialize};

struct RawMassive(Vec<u8>);

impl Packet for RawMassive {
    const ID: u16 = 0x4242;
    const NAME: &'static str = "RawMassive";
    const MASSIVE: bool = true;
    const ENCRYPTED: bool = false;
}

impl ByteSize for RawMassive {
    fn byte_size(&self) -> usize {
        self.0.len()
    }
}

impl Serialize for RawMassive {
    fn write_to(
        &self,
        writer: &mut BytesMut,
        _ctx: &SerdeContext,
    ) -> Result<(), skrillax_serde::SerializationError> {
        writer.put_slice(&self.0);
        Ok(())
    }
}

fn payload(size: usize) -> Vec<u8> {
    (0..size).map(|index| (index % 251) as u8).collect()
}

fn boundary_cases() -> Vec<(usize, Vec<usize>)> {
    let max = MAX_MASSIVE_CONTAINER_INNER_SIZE;
    vec![
        (0, vec![0]),
        (1, vec![1]),
        (max - 1, vec![max - 1]),
        (max, vec![max]),
        (max + 1, vec![max, 1]),
        (2 * max, vec![max, max]),
        (2 * max + 17, vec![max, max, 17]),
    ]
}

fn assert_massive_round_trip(
    outgoing: OutgoingPacket,
    expected_payload: &[u8],
    expected_container_sizes: &[usize],
) {
    let OutgoingPacket::Massive { opcode, packets } = &outgoing else {
        panic!("massive packet should use massive framing");
    };
    assert_eq!(RawMassive::ID, *opcode);
    assert_eq!(
        expected_container_sizes,
        packets
            .iter()
            .map(|packet| packet.len())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        expected_payload,
        packets
            .iter()
            .flat_map(|packet| packet.iter().copied())
            .collect::<Vec<_>>()
    );

    let frames = outgoing
        .as_frames(SecurityContext::default())
        .expect("valid massive packet should produce frames");
    assert_eq!(expected_container_sizes.len() + 1, frames.len());
    assert!(matches!(
        frames.first(),
        Some(SilkroadFrame::MassiveHeader {
            contained_opcode: RawMassive::ID,
            contained_count,
            ..
        }) if usize::from(*contained_count) == expected_container_sizes.len()
    ));

    let mut parsed_frames = Vec::with_capacity(frames.len());
    for frame in &frames {
        let wire = frame.serialize();
        let declared_length = u16::from_le_bytes([wire[0], wire[1]]);
        assert_eq!(0, declared_length & 0x8000);
        if let SilkroadFrame::MassiveContainer { inner, .. } = frame {
            assert_eq!(inner.len() + 1, usize::from(declared_length));
        }

        let (consumed, parsed) = SilkroadFrame::parse(&wire)
            .expect("a generated massive frame should parse successfully");
        assert_eq!(wire.len(), consumed);
        assert!(!matches!(parsed, SilkroadFrame::Encrypted { .. }));
        parsed_frames.push(parsed);
    }

    let incoming = IncomingPacket::from_frames(&parsed_frames, SecurityContext::default())
        .expect("generated massive frames should reassemble");
    let (opcode, data) = incoming.consume();
    assert_eq!(RawMassive::ID, opcode);
    assert_eq!(expected_payload, data.as_ref());
}

#[test]
fn single_massive_packet_preserves_boundary_payloads() {
    for (size, expected_container_sizes) in boundary_cases() {
        let expected = payload(size);
        let outgoing = RawMassive(expected.clone()).as_packet(&SerdeContext::default());

        assert_massive_round_trip(outgoing, &expected, &expected_container_sizes);
    }
}

#[test]
fn massive_packet_slice_preserves_boundary_payloads() {
    for (size, expected_container_sizes) in boundary_cases() {
        let expected = payload(size);
        let parts = expected
            .chunks(10_003)
            .map(|part| RawMassive(part.to_vec()))
            .collect::<Vec<_>>();
        let outgoing = parts.as_slice().as_packet(&SerdeContext::default());

        assert_massive_round_trip(outgoing, &expected, &expected_container_sizes);
    }
}

#[test]
fn manually_constructed_oversized_massive_container_is_rejected() {
    let outgoing = OutgoingPacket::Massive {
        opcode: RawMassive::ID,
        packets: vec![Bytes::from(vec![0; MAX_MASSIVE_CONTAINER_INNER_SIZE + 1])],
    };

    let result = outgoing.as_frames(SecurityContext::default());

    assert!(matches!(
        result,
        Err(FramingError::MassiveContainerTooLarge {
            actual,
            maximum: MAX_MASSIVE_CONTAINER_INNER_SIZE,
        }) if actual == MAX_MASSIVE_CONTAINER_INNER_SIZE + 1
    ));
}

#[test]
fn massive_packet_with_too_many_containers_is_rejected() {
    let container_count = usize::from(u16::MAX) + 1;
    let outgoing = OutgoingPacket::Massive {
        opcode: RawMassive::ID,
        packets: vec![Bytes::new(); container_count],
    };

    let result = outgoing.as_frames(SecurityContext::default());

    assert!(matches!(
        result,
        Err(FramingError::TooManyMassiveContainers {
            actual,
            maximum,
        }) if actual == container_count && maximum == usize::from(u16::MAX)
    ));
}
