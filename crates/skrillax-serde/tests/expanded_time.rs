#![cfg(feature = "chrono")]

use chrono::{FixedOffset, TimeZone, Timelike, Utc};
use skrillax_serde::{
    ByteSize, Deserialize, ExpandedSilkroadTime, SerdeContext, SerializationError, Serialize,
    TimeError,
};

fn expanded_bytes(
    year: u16,
    month: u16,
    day: u16,
    hour: u16,
    minute: u16,
    second: u16,
    nanosecond: u32,
) -> [u8; 16] {
    let mut bytes = [0; 16];
    for (index, field) in [year, month, day, hour, minute, second]
        .into_iter()
        .enumerate()
    {
        bytes[index * 2..index * 2 + 2].copy_from_slice(&field.to_le_bytes());
    }
    bytes[12..].copy_from_slice(&nanosecond.to_le_bytes());
    bytes
}

fn invalid_calendar(fields: (u16, u16, u16, u16, u16, u16)) -> (u16, u16, u16, u16, u16, u16) {
    let (year, month, day, hour, minute, second) = fields;
    let bytes = expanded_bytes(year, month, day, hour, minute, second, 0);
    let mut input = bytes.as_slice();
    let error = ExpandedSilkroadTime::read_from(&mut input, &SerdeContext::default()).unwrap_err();

    match error {
        SerializationError::Time(TimeError::InvalidExpandedCalendar {
            year,
            month,
            day,
            hour,
            minute,
            second,
        }) => (year, month, day, hour, minute, second),
        other => panic!("expected InvalidExpandedCalendar, got {other:?}"),
    }
}

#[test]
fn invalid_expanded_month_returns_all_raw_calendar_fields() {
    for month in [0, 13] {
        let fields = (2026, month, 1, 2, 3, 4);
        assert_eq!(invalid_calendar(fields), fields);
    }
}

#[test]
fn every_malformed_expanded_calendar_returns_all_raw_fields() {
    for fields in [
        (2026, 1, 0, 2, 3, 4),
        (2026, 2, 30, 2, 3, 4),
        (2026, 4, 31, 2, 3, 4),
        (2026, 1, 1, 24, 3, 4),
        (2026, 1, 1, 2, 60, 4),
        (2026, 1, 1, 2, 65, 4),
        (2026, 1, 1, 2, u16::MAX, 4),
        (2026, 1, 1, 2, 3, 60),
        (2026, 1, 1, 2, 3, 65),
        (2026, 1, 1, 2, 3, u16::MAX),
        (2025, 2, 29, 2, 3, 4),
    ] {
        assert_eq!(invalid_calendar(fields), fields);
    }
}

#[test]
fn official_nonzero_fraction_has_exact_serialized_bytes() {
    let value = ExpandedSilkroadTime::try_from(
        Utc.with_ymd_and_hms(2026, 7, 24, 12, 9, 17)
            .single()
            .unwrap()
            .with_nanosecond(790_000_000)
            .unwrap(),
    )
    .unwrap();
    let expected = [
        0xea, 0x07, 0x07, 0x00, 0x18, 0x00, 0x0c, 0x00, 0x09, 0x00, 0x11, 0x00, 0x80, 0x71, 0x16,
        0x2f,
    ];
    let mut output = bytes::BytesMut::new();

    value
        .write_to(&mut output, &SerdeContext::default())
        .unwrap();

    assert_eq!(output.as_ref(), expected);
}

#[test]
fn official_fixture_spans_decode_to_exact_instants() {
    const FIXTURE: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/joymax-gateway-notice-A104-2026-08-01T225034Z.payload.bin"
    ));
    let cases = [
        (1035, (2026, 7, 24, 12, 9, 17, 790_000_000)),
        (2113, (2026, 7, 20, 17, 14, 18, 667_000_000)),
        (3117, (2026, 7, 7, 11, 27, 55, 913_000_000)),
        (4121, (2026, 7, 2, 17, 57, 21, 420_000_000)),
    ];

    for (offset, (year, month, day, hour, minute, second, nanosecond)) in cases {
        let span = &FIXTURE[offset..offset + 16];
        assert_eq!(
            span,
            expanded_bytes(
                year as u16,
                month as u16,
                day as u16,
                hour as u16,
                minute as u16,
                second as u16,
                nanosecond
            )
        );
        let mut input = span;
        let decoded =
            ExpandedSilkroadTime::read_from(&mut input, &SerdeContext::default()).unwrap();
        let expected = Utc
            .with_ymd_and_hms(year, month, day, hour, minute, second)
            .single()
            .unwrap()
            .with_nanosecond(nanosecond)
            .unwrap();

        assert_eq!(*decoded, expected);
        assert_eq!(decoded.nanosecond(), nanosecond);
        assert!(input.is_empty());
    }
}

#[test]
fn expanded_fractions_roundtrip_exactly_and_byte_size_stays_fixed() {
    for nanosecond in [0, 1, 999_999_999] {
        let datetime = Utc
            .with_ymd_and_hms(2024, 2, 29, 23, 59, 59)
            .single()
            .unwrap()
            .with_nanosecond(nanosecond)
            .unwrap();
        let value = ExpandedSilkroadTime::try_from(datetime).unwrap();
        assert_eq!(value.byte_size(), 16);
        let mut output = bytes::BytesMut::new();
        value
            .write_to(&mut output, &SerdeContext::default())
            .unwrap();
        let mut input = output.as_ref();

        let decoded =
            ExpandedSilkroadTime::read_from(&mut input, &SerdeContext::default()).unwrap();

        assert_eq!(*decoded, *value);
        assert_eq!(decoded.nanosecond(), nanosecond);
        assert!(input.is_empty());
    }
}

#[test]
fn fixed_offset_input_serializes_as_utc_calendar_fields() {
    let offset = FixedOffset::east_opt(2 * 60 * 60).unwrap();
    let local = offset
        .with_ymd_and_hms(2026, 8, 1, 0, 30, 34)
        .single()
        .unwrap()
        .with_nanosecond(169_807_992)
        .unwrap();
    let expected = Utc
        .with_ymd_and_hms(2026, 7, 31, 22, 30, 34)
        .single()
        .unwrap()
        .with_nanosecond(169_807_992)
        .unwrap();
    let value = ExpandedSilkroadTime::try_from(local).unwrap();
    let mut output = bytes::BytesMut::new();

    value
        .write_to(&mut output, &SerdeContext::default())
        .unwrap();

    assert_eq!(value.as_datetime(), &expected);
    assert_eq!(*value, expected);
    assert_eq!(
        output.as_ref(),
        expanded_bytes(2026, 7, 31, 22, 30, 34, 169_807_992)
    );
    assert_eq!(value.into_datetime(), expected);
}

#[test]
fn out_of_range_expanded_years_do_not_construct_or_append_output() {
    for year in [-1, 65_536] {
        let datetime = Utc.with_ymd_and_hms(year, 1, 2, 3, 4, 5).single().unwrap();
        let output = bytes::BytesMut::from(&[0xa5][..]);

        let error = ExpandedSilkroadTime::try_from(datetime).unwrap_err();

        assert!(matches!(
            error,
            TimeError::ExpandedYearOutOfRange { year: actual } if actual == year
        ));
        assert_eq!(output.as_ref(), &[0xa5]);
    }
}

#[test]
fn outbound_fraction_above_one_second_does_not_construct_or_append_output() {
    let datetime = Utc
        .with_ymd_and_hms(2026, 8, 1, 22, 50, 59)
        .single()
        .unwrap()
        .with_nanosecond(1_000_000_000)
        .unwrap();
    let output = bytes::BytesMut::from(&[0xa5][..]);

    let error = ExpandedSilkroadTime::try_from(datetime).unwrap_err();

    assert!(matches!(
        error,
        TimeError::InvalidExpandedFraction {
            value: 1_000_000_000,
            maximum: 999_999_999,
            unit: "nanoseconds",
        }
    ));
    assert_eq!(output.as_ref(), &[0xa5]);
}

#[test]
fn every_expanded_truncation_returns_unexpected_eof() {
    let bytes = expanded_bytes(2026, 8, 1, 22, 50, 34, 169_807_992);

    for length in 0..16 {
        let mut input = &bytes[..length];
        let error =
            ExpandedSilkroadTime::read_from(&mut input, &SerdeContext::default()).unwrap_err();

        assert!(
            matches!(
                error,
                SerializationError::IoError(ref io_error)
                    if io_error.kind() == std::io::ErrorKind::UnexpectedEof
            ),
            "length {length} should return IoError(UnexpectedEof), got {error:?}"
        );
    }
}

#[test]
fn successful_expanded_decode_consumes_exactly_sixteen_bytes() {
    const CANARY: u8 = 0xa5;
    let mut bytes = expanded_bytes(2026, 8, 1, 22, 50, 34, 169_807_992).to_vec();
    bytes.push(CANARY);
    let mut input = bytes.as_slice();

    let decoded = ExpandedSilkroadTime::read_from(&mut input, &SerdeContext::default()).unwrap();

    assert_eq!(
        *decoded,
        Utc.with_ymd_and_hms(2026, 8, 1, 22, 50, 34)
            .single()
            .unwrap()
            .with_nanosecond(169_807_992)
            .unwrap()
    );
    assert_eq!(input, &[CANARY]);
}

#[test]
fn invalid_calendar_is_reported_only_after_trailing_field_is_read() {
    let bytes = expanded_bytes(2026, 13, 1, 2, 3, 4, 0);
    let mut input = &bytes[..15];

    let error = ExpandedSilkroadTime::read_from(&mut input, &SerdeContext::default()).unwrap_err();

    assert!(matches!(
        error,
        SerializationError::IoError(ref io_error)
            if io_error.kind() == std::io::ErrorKind::UnexpectedEof
    ));
}

#[test]
fn expanded_fraction_above_one_second_is_rejected() {
    let bytes = expanded_bytes(2026, 8, 1, 22, 50, 34, 1_000_000_000);
    let mut input = bytes.as_slice();

    let error = ExpandedSilkroadTime::read_from(&mut input, &SerdeContext::default()).unwrap_err();

    assert!(matches!(
        error,
        SerializationError::Time(TimeError::InvalidExpandedFraction {
            value: 1_000_000_000,
            maximum: 999_999_999,
            unit: "nanoseconds",
        })
    ));
}
