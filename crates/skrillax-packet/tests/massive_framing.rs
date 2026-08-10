#![cfg(feature = "serde")]

use bytes::{BufMut, Bytes, BytesMut};
use skrillax_codec::{MAX_MASSIVE_CONTAINER_INNER_SIZE, SilkroadFrame};
use skrillax_packet::{
    AsFrames, AsPacket, FramingError, FromFrames, IncomingPacket, OutgoingPacket, Packet,
    PacketError, ReframingError, ReframingLimits, SecurityBytes, SecurityContext,
};
use skrillax_serde::{ByteSize, SerdeContext, SerializationError, Serialize};

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
    ) -> Result<(), SerializationError> {
        writer.put_slice(&self.0);
        Ok(())
    }
}

struct NonMassive;

impl Packet for NonMassive {
    const ID: u16 = 0x4141;
    const NAME: &'static str = "NonMassive";
    const MASSIVE: bool = false;
    const ENCRYPTED: bool = false;
}

impl ByteSize for NonMassive {
    fn byte_size(&self) -> usize {
        0
    }
}

impl Serialize for NonMassive {
    fn write_to(
        &self,
        _writer: &mut BytesMut,
        _ctx: &SerdeContext,
    ) -> Result<(), SerializationError> {
        Ok(())
    }
}

struct SizeOverflowMassive;

impl Packet for SizeOverflowMassive {
    const ID: u16 = 0x4240;
    const NAME: &'static str = "SizeOverflowMassive";
    const MASSIVE: bool = true;
    const ENCRYPTED: bool = false;
}

impl ByteSize for SizeOverflowMassive {
    fn byte_size(&self) -> usize {
        usize::MAX
    }
}

impl Serialize for SizeOverflowMassive {
    fn write_to(
        &self,
        _writer: &mut BytesMut,
        _ctx: &SerdeContext,
    ) -> Result<(), SerializationError> {
        Ok(())
    }
}

struct FailingMassive;

impl Packet for FailingMassive {
    const ID: u16 = 0x4343;
    const NAME: &'static str = "FailingMassive";
    const MASSIVE: bool = true;
    const ENCRYPTED: bool = false;
}

impl ByteSize for FailingMassive {
    fn byte_size(&self) -> usize {
        0
    }
}

impl Serialize for FailingMassive {
    fn write_to(
        &self,
        _writer: &mut BytesMut,
        _ctx: &SerdeContext,
    ) -> Result<(), SerializationError> {
        Err(SerializationError::NoMatchingVariant {
            enum_name: "FailingMassive",
        })
    }
}

fn assert_failing_massive_error(result: Result<OutgoingPacket, PacketError>) {
    assert!(matches!(
        result,
        Err(PacketError::SerializationError(
            SerializationError::NoMatchingVariant {
                enum_name: "FailingMassive"
            }
        ))
    ));
}

#[test]
fn massive_slice_size_overflow_returns_packet_error() {
    let packets = [SizeOverflowMassive, SizeOverflowMassive];

    let result = packets.as_slice().as_packet(&SerdeContext::default());

    assert!(matches!(
        result,
        Err(PacketError::PacketSizeOverflow {
            packet: "SizeOverflowMassive"
        })
    ));
}

#[test]
fn non_massive_slice_returns_packet_error() {
    let packets = [NonMassive];

    let result = packets.as_slice().as_packet(&SerdeContext::default());

    assert!(matches!(
        result,
        Err(PacketError::NonMassivePacketSequence {
            packet: "NonMassive"
        })
    ));
}

fn payload(size: usize) -> Vec<u8> {
    (0..size).map(|index| (index % 251) as u8).collect()
}

fn secured_empty_massive_frames() -> (Vec<SilkroadFrame>, SecurityBytes) {
    let sender_security = SecurityBytes::from_seeds(0x1234_5678, 0x9ABC_DEF0);
    let receiver_security = SecurityBytes::from_seeds(0x1234_5678, 0x9ABC_DEF0);
    let outgoing = OutgoingPacket::Massive {
        opcode: RawMassive::ID,
        packets: vec![],
    };
    let frames = outgoing
        .as_frames(SecurityContext::new(None, Some(&sender_security)))
        .expect("a zero-container massive packet should produce a header");

    (frames, receiver_security)
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
        let wire = frame
            .serialize()
            .expect("a generated massive frame should be representable");
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
fn reframing_limits_are_unlimited_and_composable() {
    let unlimited = ReframingLimits::unlimited();
    assert_eq!(None, unlimited.max_frames_per_packet());
    assert_eq!(None, unlimited.max_payload_bytes_per_packet());
    assert_eq!(unlimited, ReframingLimits::default());

    let limited = unlimited
        .with_max_frames_per_packet(3)
        .with_max_payload_bytes_per_packet(4);
    assert_eq!(Some(3), limited.max_frames_per_packet());
    assert_eq!(Some(4), limited.max_payload_bytes_per_packet());
}

#[test]
fn simple_packet_observes_frame_and_payload_limits() {
    let frame = SilkroadFrame::Packet {
        count: 0,
        crc: 0,
        opcode: 0x1234,
        data: Bytes::from_static(&[1, 2, 3]),
    };
    let exact_limits = ReframingLimits::unlimited()
        .with_max_frames_per_packet(1)
        .with_max_payload_bytes_per_packet(3);

    let incoming = IncomingPacket::from_frames_with_limits(
        std::slice::from_ref(&frame),
        SecurityContext::default(),
        exact_limits,
    )
    .expect("limits should be inclusive");
    assert_eq!(&[1, 2, 3], incoming.data());

    let frame_error = IncomingPacket::from_frames_with_limits(
        std::slice::from_ref(&frame),
        SecurityContext::default(),
        exact_limits.with_max_frames_per_packet(0),
    );
    assert!(matches!(
        frame_error,
        Err(ReframingError::FrameCountLimitExceeded {
            required: 1,
            maximum: 0,
        })
    ));

    let payload_error = IncomingPacket::from_frames_with_limits(
        std::slice::from_ref(&frame),
        SecurityContext::default(),
        exact_limits.with_max_payload_bytes_per_packet(2),
    );
    assert!(matches!(
        payload_error,
        Err(ReframingError::PayloadByteLimitExceeded {
            attempted: 3,
            maximum: 2,
        })
    ));
}

#[test]
fn massive_header_limit_includes_header_and_rejects_before_containers() {
    let frame = SilkroadFrame::MassiveHeader {
        count: 0,
        crc: 0,
        contained_opcode: RawMassive::ID,
        contained_count: 2,
    };
    let limits = ReframingLimits::unlimited().with_max_frames_per_packet(2);

    let result =
        IncomingPacket::from_frames_with_limits(&[frame], SecurityContext::default(), limits);

    assert!(matches!(
        result,
        Err(ReframingError::FrameCountLimitExceeded {
            required: 3,
            maximum: 2,
        })
    ));
}

#[test]
fn massive_payload_limit_is_cumulative_and_inclusive() {
    let frames = [
        SilkroadFrame::MassiveHeader {
            count: 0,
            crc: 0,
            contained_opcode: RawMassive::ID,
            contained_count: 2,
        },
        SilkroadFrame::MassiveContainer {
            count: 0,
            crc: 0,
            inner: Bytes::from_static(&[1, 2]),
        },
        SilkroadFrame::MassiveContainer {
            count: 0,
            crc: 0,
            inner: Bytes::from_static(&[3, 4]),
        },
    ];
    let exact_limits = ReframingLimits::unlimited()
        .with_max_frames_per_packet(3)
        .with_max_payload_bytes_per_packet(4);

    let incoming =
        IncomingPacket::from_frames_with_limits(&frames, SecurityContext::default(), exact_limits)
            .expect("the exact cumulative payload limit should be accepted");
    assert_eq!(&[1, 2, 3, 4], incoming.data());

    let result = IncomingPacket::from_frames_with_limits(
        &frames,
        SecurityContext::default(),
        exact_limits.with_max_payload_bytes_per_packet(3),
    );
    assert!(matches!(
        result,
        Err(ReframingError::PayloadByteLimitExceeded {
            attempted: 4,
            maximum: 3,
        })
    ));
}

#[test]
fn encrypted_packet_observes_payload_limit_after_validation() {
    let encryption = skrillax_security::SilkroadEncryption::from_key(0xFF00FF00FF00FF00);
    let outgoing = OutgoingPacket::Encrypted {
        opcode: 0x1234,
        data: Bytes::from_static(&[1, 2, 3]),
    };
    let frames = outgoing
        .as_frames(SecurityContext::new(Some(&encryption), None))
        .expect("the encrypted packet should produce a frame");
    let limits = ReframingLimits::unlimited().with_max_payload_bytes_per_packet(2);

    let result = IncomingPacket::from_frames_with_limits(
        &frames,
        SecurityContext::new(Some(&encryption), None),
        limits,
    );

    assert!(matches!(
        result,
        Err(ReframingError::PayloadByteLimitExceeded {
            attempted: 3,
            maximum: 2,
        })
    ));
}

#[test]
fn zero_container_header_completes_empty_payload() {
    let frame = SilkroadFrame::MassiveHeader {
        count: 0,
        crc: 0,
        contained_opcode: RawMassive::ID,
        contained_count: 0,
    };

    let incoming = IncomingPacket::from_frames(&[frame], SecurityContext::default())
        .expect("a zero-container header should complete immediately");

    assert_eq!(RawMassive::ID, incoming.opcode());
    assert!(incoming.data().is_empty());
}

#[test]
fn zero_container_header_does_not_append_undeclared_container() {
    let frames = [
        SilkroadFrame::MassiveHeader {
            count: 0,
            crc: 0,
            contained_opcode: RawMassive::ID,
            contained_count: 0,
        },
        SilkroadFrame::MassiveContainer {
            count: 0,
            crc: 0,
            inner: Bytes::from_static(&[1, 2, 3]),
        },
    ];

    let incoming = IncomingPacket::from_frames(&frames, SecurityContext::default())
        .expect("the zero-container sequence should already be complete");

    assert_eq!(RawMassive::ID, incoming.opcode());
    assert!(incoming.data().is_empty());
}

#[test]
fn manually_empty_massive_packet_round_trips() {
    let outgoing = OutgoingPacket::Massive {
        opcode: RawMassive::ID,
        packets: vec![],
    };

    assert_massive_round_trip(outgoing, &[], &[]);
}

#[test]
fn zero_container_header_counter_is_validated_before_completion() {
    let (mut frames, receiver_security) = secured_empty_massive_frames();
    let SilkroadFrame::MassiveHeader { count, .. } = &mut frames[0] else {
        panic!("an empty massive packet should produce only a header");
    };
    *count = count.wrapping_add(1);

    let result = IncomingPacket::from_frames(
        &frames,
        SecurityContext::new(None, Some(&receiver_security)),
    );

    assert!(matches!(
        result,
        Err(ReframingError::CounterCheckFailed { expected, received })
            if expected != received
    ));
}

#[test]
fn zero_container_header_crc_is_validated_before_completion() {
    let (mut frames, receiver_security) = secured_empty_massive_frames();
    let SilkroadFrame::MassiveHeader { crc, .. } = &mut frames[0] else {
        panic!("an empty massive packet should produce only a header");
    };
    *crc = crc.wrapping_add(1);

    let result = IncomingPacket::from_frames(
        &frames,
        SecurityContext::new(None, Some(&receiver_security)),
    );

    assert!(matches!(
        result,
        Err(ReframingError::CrcCheckFailed { expected, received })
            if expected != received
    ));
}

#[test]
fn incomplete_secured_from_frames_can_be_retried_with_the_same_security() {
    let sender_security = SecurityBytes::from_seeds(0x1234_5678, 0x9ABC_DEF0);
    let receiver_security = SecurityBytes::from_seeds(0x1234_5678, 0x9ABC_DEF0);
    let outgoing = OutgoingPacket::Massive {
        opcode: RawMassive::ID,
        packets: vec![Bytes::from_static(&[1, 2, 3])],
    };
    let frames = outgoing
        .as_frames(SecurityContext::new(None, Some(&sender_security)))
        .expect("secured massive packet should produce frames");

    let incomplete = IncomingPacket::from_frames(
        &frames[..1],
        SecurityContext::new(None, Some(&receiver_security)),
    );
    assert!(matches!(
        incomplete,
        Err(ReframingError::Incomplete(Some(1)))
    ));

    let incoming = IncomingPacket::from_frames(
        &frames,
        SecurityContext::new(None, Some(&receiver_security)),
    )
    .expect("an incomplete compatibility call must not consume security state");
    assert_eq!(&[1, 2, 3], incoming.data());
}

#[test]
fn secured_header_integrity_errors_take_precedence_over_limits() {
    let (mut frames, receiver_security) = secured_empty_massive_frames();
    let SilkroadFrame::MassiveHeader { count, .. } = &mut frames[0] else {
        panic!("an empty massive packet should produce only a header");
    };
    *count = count.wrapping_add(1);
    let limits = ReframingLimits::unlimited().with_max_frames_per_packet(0);

    let result = IncomingPacket::from_frames_with_limits(
        &frames,
        SecurityContext::new(None, Some(&receiver_security)),
        limits,
    );

    assert!(matches!(
        result,
        Err(ReframingError::CounterCheckFailed { expected, received })
            if expected != received
    ));
}

#[test]
fn secured_massive_packet_round_trips() {
    let expected = payload(MAX_MASSIVE_CONTAINER_INNER_SIZE + 1);
    let outgoing = RawMassive(expected.clone())
        .as_packet(&SerdeContext::default())
        .expect("valid massive packet should serialize");
    let sender_security = SecurityBytes::from_seeds(0x1234_5678, 0x9ABC_DEF0);
    let receiver_security = SecurityBytes::from_seeds(0x1234_5678, 0x9ABC_DEF0);
    let frames = outgoing
        .as_frames(SecurityContext::new(None, Some(&sender_security)))
        .expect("secured massive packet should produce frames");
    let parsed_frames = frames
        .iter()
        .map(|frame| {
            let wire = frame
                .serialize()
                .expect("a generated secured massive frame should be representable");
            SilkroadFrame::parse(&wire)
                .map(|(_, parsed)| parsed)
                .expect("generated massive frame should parse")
        })
        .collect::<Vec<_>>();

    let incoming = IncomingPacket::from_frames(
        &parsed_frames,
        SecurityContext::new(None, Some(&receiver_security)),
    )
    .expect("secured massive packet should pass integrity verification");

    let (opcode, data) = incoming.consume();
    assert_eq!(RawMassive::ID, opcode);
    assert_eq!(expected, data.as_ref());
}

#[test]
fn secured_massive_packet_rejects_tampered_container_payload() {
    let sender_security = SecurityBytes::from_seeds(0x1234_5678, 0x9ABC_DEF0);
    let receiver_security = SecurityBytes::from_seeds(0x1234_5678, 0x9ABC_DEF0);
    let outgoing = OutgoingPacket::Massive {
        opcode: RawMassive::ID,
        packets: vec![Bytes::from_static(&[1, 2, 3])],
    };
    let mut frames = outgoing
        .as_frames(SecurityContext::new(None, Some(&sender_security)))
        .expect("secured massive packet should produce frames");
    let SilkroadFrame::MassiveContainer { inner, .. } = &mut frames[1] else {
        panic!("non-empty massive packet should contain a container");
    };
    *inner = Bytes::from_static(&[1, 2, 4]);

    let result = IncomingPacket::from_frames(
        &frames,
        SecurityContext::new(None, Some(&receiver_security)),
    );

    assert!(matches!(result, Err(ReframingError::CrcCheckFailed { .. })));
}

#[test]
fn secured_massive_packet_rejects_tampered_container_crc() {
    let sender_security = SecurityBytes::from_seeds(0x1234_5678, 0x9ABC_DEF0);
    let receiver_security = SecurityBytes::from_seeds(0x1234_5678, 0x9ABC_DEF0);
    let outgoing = OutgoingPacket::Massive {
        opcode: RawMassive::ID,
        packets: vec![Bytes::from_static(&[1, 2, 3])],
    };
    let mut frames = outgoing
        .as_frames(SecurityContext::new(None, Some(&sender_security)))
        .expect("secured massive packet should produce frames");
    let SilkroadFrame::MassiveContainer { crc, .. } = &mut frames[1] else {
        panic!("non-empty massive packet should contain a container");
    };
    *crc = crc.wrapping_add(1);

    let result = IncomingPacket::from_frames(
        &frames,
        SecurityContext::new(None, Some(&receiver_security)),
    );

    assert!(matches!(result, Err(ReframingError::CrcCheckFailed { .. })));
}

#[test]
fn single_massive_packet_preserves_boundary_payloads() {
    for (size, expected_container_sizes) in boundary_cases() {
        let expected = payload(size);
        let outgoing = RawMassive(expected.clone())
            .as_packet(&SerdeContext::default())
            .expect("valid massive packet should serialize");

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
        let outgoing = parts
            .as_slice()
            .as_packet(&SerdeContext::default())
            .expect("valid massive packet slice should serialize");

        assert_massive_round_trip(outgoing, &expected, &expected_container_sizes);
    }
}

#[test]
fn individual_as_packet_preserves_serialization_failure() {
    let result = FailingMassive.as_packet(&SerdeContext::default());

    assert_failing_massive_error(result);
}

#[test]
fn massive_slice_as_packet_preserves_serialization_failure() {
    let packets = [FailingMassive];

    let result = packets.as_slice().as_packet(&SerdeContext::default());

    assert_failing_massive_error(result);
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
fn maximum_container_count_remains_incomplete_without_containers() {
    let frame = SilkroadFrame::MassiveHeader {
        count: 0,
        crc: 0,
        contained_opcode: RawMassive::ID,
        contained_count: u16::MAX,
    };

    let result = IncomingPacket::from_frames(&[frame], SecurityContext::default());

    assert!(matches!(
        result,
        Err(ReframingError::Incomplete(Some(remaining)))
            if remaining == usize::from(u16::MAX)
    ));
}

#[test]
fn maximum_container_count_is_accepted_for_framing() {
    let outgoing = OutgoingPacket::Massive {
        opcode: RawMassive::ID,
        packets: vec![Bytes::new(); usize::from(u16::MAX)],
    };

    let frames = outgoing
        .as_frames(SecurityContext::default())
        .expect("the full u16 container-count range should remain valid");

    assert_eq!(usize::from(u16::MAX) + 1, frames.len());
    assert!(matches!(
        frames.first(),
        Some(SilkroadFrame::MassiveHeader {
            contained_count: u16::MAX,
            ..
        })
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
