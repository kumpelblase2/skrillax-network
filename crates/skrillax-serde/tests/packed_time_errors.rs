#![cfg(feature = "chrono")]

use chrono::{TimeZone, Utc};
use skrillax_serde::{
    Deserialize, PackedSilkroadTime, SerdeContext, SerializationError, TimeError,
};

fn packed_raw(year: i32, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> u32 {
    debug_assert!((2000..=2063).contains(&year));
    debug_assert!((1..=16).contains(&month));
    debug_assert!((1..=32).contains(&day));
    debug_assert!(hour <= 31);
    debug_assert!(minute <= 63);
    debug_assert!(second <= 63);

    (year - 2000) as u32
        | (month - 1) << 6
        | (day - 1) << 10
        | hour << 15
        | minute << 20
        | second << 26
}

fn invalid_calendar(raw: u32) -> (u32, i32, u32, u32, u32, u32, u32) {
    let bytes = raw.to_le_bytes();
    let mut input = bytes.as_slice();
    let error = PackedSilkroadTime::read_from(&mut input, &SerdeContext::default()).unwrap_err();

    match error {
        SerializationError::Time(TimeError::InvalidPackedCalendar {
            raw,
            year,
            month,
            day,
            hour,
            minute,
            second,
        }) => (raw, year, month, day, hour, minute, second),
        other => panic!("expected InvalidPackedCalendar, got {other:?}"),
    }
}

#[test]
fn every_encoded_invalid_month_returns_diagnostic_components() {
    for month in 13..=16 {
        let raw = packed_raw(2000, month, 1, 0, 0, 0);

        assert_eq!(invalid_calendar(raw), (raw, 2000, month, 1, 0, 0, 0));
    }
}

#[test]
fn invalid_days_return_diagnostic_components() {
    for month in 1..=12 {
        let raw = packed_raw(2000, month, 32, 0, 0, 0);
        assert_eq!(invalid_calendar(raw), (raw, 2000, month, 32, 0, 0, 0));
    }

    for (month, day) in [(2, 30), (2, 31), (4, 31), (6, 31), (9, 31), (11, 31)] {
        let raw = packed_raw(2000, month, day, 0, 0, 0);
        assert_eq!(invalid_calendar(raw), (raw, 2000, month, day, 0, 0, 0));
    }
}

#[test]
fn every_encoded_invalid_hour_returns_diagnostic_components() {
    for hour in 24..=31 {
        let raw = packed_raw(2000, 1, 1, hour, 0, 0);
        assert_eq!(invalid_calendar(raw), (raw, 2000, 1, 1, hour, 0, 0));
    }
}

#[test]
fn every_encoded_invalid_minute_returns_diagnostic_components() {
    for minute in 60..=63 {
        let raw = packed_raw(2000, 1, 1, 0, minute, 0);
        assert_eq!(invalid_calendar(raw), (raw, 2000, 1, 1, 0, minute, 0));
    }
}

#[test]
fn every_encoded_invalid_second_returns_diagnostic_components() {
    for second in 60..=63 {
        let raw = packed_raw(2000, 1, 1, 0, 0, second);
        assert_eq!(invalid_calendar(raw), (raw, 2000, 1, 1, 0, 0, second));
    }
}

#[test]
fn valid_leap_day_decodes_successfully() {
    let raw = packed_raw(2000, 2, 29, 23, 59, 59);
    let bytes = raw.to_le_bytes();
    let mut input = bytes.as_slice();

    let decoded = PackedSilkroadTime::read_from(&mut input, &SerdeContext::default()).unwrap();

    assert_eq!(
        *decoded,
        Utc.with_ymd_and_hms(2000, 2, 29, 23, 59, 59)
            .single()
            .unwrap()
    );
}

#[test]
fn non_leap_february_29_returns_diagnostic_components() {
    let raw = packed_raw(2001, 2, 29, 12, 34, 56);

    assert_eq!(invalid_calendar(raw), (raw, 2001, 2, 29, 12, 34, 56));
}

#[test]
fn every_truncated_length_returns_unexpected_eof() {
    let bytes = packed_raw(2000, 1, 1, 0, 0, 0).to_le_bytes();

    for length in 0..4 {
        let mut input = &bytes[..length];
        let error =
            PackedSilkroadTime::read_from(&mut input, &SerdeContext::default()).unwrap_err();

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
fn successful_decode_consumes_exactly_four_bytes() {
    const CANARY: u8 = 0xa5;
    let raw = packed_raw(2001, 10, 20, 14, 24, 40);
    let mut bytes = raw.to_le_bytes().to_vec();
    bytes.push(CANARY);
    let mut input = bytes.as_slice();

    let decoded = PackedSilkroadTime::read_from(&mut input, &SerdeContext::default()).unwrap();

    assert_eq!(
        *decoded,
        Utc.with_ymd_and_hms(2001, 10, 20, 14, 24, 40)
            .single()
            .unwrap()
    );
    assert_eq!(input, &[CANARY]);
}
