use bytes::Bytes;
use skrillax_codec::{FrameContentSize, FrameEncodeError, MAX_FRAME_CONTENT_SIZE, SilkroadFrame};
use skrillax_packet::{AsFrames, FramingError, OutgoingPacket, SecurityBytes, SecurityContext};
use skrillax_security::SilkroadEncryption;

#[test]
fn oversized_plain_packet_is_rejected_before_framing() {
    let packet = OutgoingPacket::Simple {
        opcode: 0x1234,
        data: Bytes::from(vec![0; MAX_FRAME_CONTENT_SIZE + 1]),
    };

    let error = packet
        .as_frames(SecurityContext::default())
        .expect_err("oversized plain packets must not become malformed wire frames");

    assert!(matches!(
        error,
        FramingError::FrameEncoding(FrameEncodeError::ContentTooLarge {
            actual,
            maximum: MAX_FRAME_CONTENT_SIZE,
        }) if actual == MAX_FRAME_CONTENT_SIZE + 1
    ));
}

#[test]
fn maximum_plain_packet_length_is_representable() {
    let packet = OutgoingPacket::Simple {
        opcode: 0x1234,
        data: Bytes::from(vec![0xAB; MAX_FRAME_CONTENT_SIZE]),
    };

    let frames = packet
        .as_frames(SecurityContext::default())
        .expect("the maximum plain packet length should be accepted");
    let wire = frames[0]
        .serialize()
        .expect("the resulting frame should remain representable");

    assert_eq!([0xFF, 0x7F], wire[..2]);
}

#[test]
fn rejected_plain_packet_does_not_advance_security_state() {
    let used_security = SecurityBytes::from_seeds(0x12, 0x3456_7890);
    let fresh_security = SecurityBytes::from_seeds(0x12, 0x3456_7890);
    let oversized = OutgoingPacket::Simple {
        opcode: 0x1234,
        data: Bytes::from(vec![0; MAX_FRAME_CONTENT_SIZE + 1]),
    };

    oversized
        .as_frames(SecurityContext::new(None, Some(&used_security)))
        .expect_err("the oversized packet should be rejected");

    let valid = OutgoingPacket::Simple {
        opcode: 0x1234,
        data: Bytes::from_static(b"valid"),
    };
    let after_rejection = valid
        .as_frames(SecurityContext::new(None, Some(&used_security)))
        .expect("a valid packet should frame after rejection");
    let fresh = valid
        .as_frames(SecurityContext::new(None, Some(&fresh_security)))
        .expect("a valid packet should frame with fresh security");

    assert_eq!(fresh, after_rejection);
}

#[test]
fn oversized_encrypted_packet_is_rejected_before_security_is_required() {
    let packet = OutgoingPacket::Encrypted {
        opcode: 0x1234,
        data: Bytes::from(vec![0; MAX_FRAME_CONTENT_SIZE + 1]),
    };

    let error = packet
        .as_frames(SecurityContext::default())
        .expect_err("length validation must happen before security operations");

    assert!(matches!(
        error,
        FramingError::FrameEncoding(FrameEncodeError::ContentTooLarge {
            actual,
            maximum: MAX_FRAME_CONTENT_SIZE,
        }) if actual == MAX_FRAME_CONTENT_SIZE + 1
    ));
}

#[test]
fn maximum_encrypted_packet_length_is_representable() {
    let encryption = SilkroadEncryption::from_key(0x0123_4567_89AB_CDEF);
    let packet = OutgoingPacket::Encrypted {
        opcode: 0x1234,
        data: Bytes::from(vec![0xAB; MAX_FRAME_CONTENT_SIZE]),
    };

    let frames = packet
        .as_frames(SecurityContext::new(Some(&encryption), None))
        .expect("the maximum encrypted packet length should be accepted");

    assert!(matches!(
        frames.as_slice(),
        [SilkroadFrame::Encrypted {
            content_size: MAX_FRAME_CONTENT_SIZE,
            encrypted_data,
        }] if encrypted_data.len()
            == FrameContentSize::try_from(MAX_FRAME_CONTENT_SIZE)
                .expect("the maximum content size is valid")
                .encrypted_data_len()
    ));
    let wire = frames[0]
        .serialize()
        .expect("the encrypted frame should remain representable");
    let (consumed, parsed) =
        SilkroadFrame::parse(&wire).expect("the encrypted boundary frame should parse");

    assert_eq!([0xFF, 0xFF], wire[..2]);
    assert_eq!(wire.len(), consumed);
    assert_eq!(frames[0], parsed);
}
