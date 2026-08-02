#![cfg(feature = "chrono")]

use chrono::{FixedOffset, TimeZone, Timelike, Utc};
use skrillax_serde::{
    ByteSize, Deserialize, PackedSilkroadTime, SerdeContext, Serialize, TimeError,
};
use std::time::Duration;

fn utc(
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(year, month, day, hour, minute, second)
        .single()
        .unwrap()
}

fn duration_through(value: chrono::DateTime<Utc>) -> Duration {
    Duration::from_secs((value.timestamp() - utc(2000, 1, 1, 0, 0, 0).timestamp()) as u64)
}

#[test]
fn valid_packed_time_roundtrips_and_has_fixed_byte_size() {
    let original = PackedSilkroadTime::try_from(utc(2000, 2, 29, 12, 34, 56)).unwrap();
    assert_eq!(original.byte_size(), 4);

    let mut output = bytes::BytesMut::new();
    original
        .write_to(&mut output, &SerdeContext::default())
        .unwrap();
    let mut input = &output[..];
    let decoded = PackedSilkroadTime::read_from(&mut input, &SerdeContext::default()).unwrap();

    assert_eq!(*decoded, *original);
    assert!(input.is_empty());
}

#[test]
fn invalid_from_u32_returns_invalid_packed_calendar() {
    let raw = (16 - 1) << 6;

    let error = PackedSilkroadTime::from_u32(raw).unwrap_err();

    assert!(matches!(
        error,
        TimeError::InvalidPackedCalendar {
            raw: actual_raw,
            year: 2000,
            month: 16,
            day: 1,
            hour: 0,
            minute: 0,
            second: 0,
        } if actual_raw == raw
    ));
}

#[test]
fn duration_max_returns_a_typed_range_error() {
    let error = PackedSilkroadTime::try_from(Duration::MAX).unwrap_err();

    assert!(matches!(
        error,
        TimeError::DurationOutOfRange {
            seconds,
            nanoseconds
        } if seconds == Duration::MAX.as_secs()
            && nanoseconds == Duration::MAX.subsec_nanos()
    ));
}

#[test]
fn fractional_duration_is_rejected_without_truncation() {
    let error = PackedSilkroadTime::try_from(Duration::new(0, 1)).unwrap_err();

    assert!(matches!(
        error,
        TimeError::PackedSubsecondOutOfRange { nanosecond: 1 }
    ));
}

#[test]
fn duration_one_second_beyond_the_packed_range_is_rejected() {
    let first_invalid = duration_through(utc(2063, 12, 31, 23, 59, 59)) + Duration::from_secs(1);

    let error = PackedSilkroadTime::try_from(first_invalid).unwrap_err();

    assert!(matches!(
        error,
        TimeError::PackedYearOutOfRange { year: 2064 }
    ));
}

#[test]
fn maximum_valid_duration_reaches_the_last_packed_second() {
    let maximum = utc(2063, 12, 31, 23, 59, 59);

    let packed = PackedSilkroadTime::try_from(duration_through(maximum)).unwrap();

    assert_eq!(*packed, maximum);
}

#[test]
fn zero_duration_is_the_packed_epoch() {
    let packed: Result<PackedSilkroadTime, TimeError> =
        PackedSilkroadTime::try_from(Duration::ZERO);
    let packed = packed.unwrap();

    assert_eq!(*packed, utc(2000, 1, 1, 0, 0, 0));
    assert_eq!(packed.as_u32().unwrap(), 0);
}

#[test]
fn nonzero_nanoseconds_are_rejected() {
    let value = utc(2001, 10, 20, 14, 24, 40).with_nanosecond(1).unwrap();

    let error = PackedSilkroadTime::try_from(value).unwrap_err();

    assert!(matches!(
        error,
        TimeError::PackedSubsecondOutOfRange { nanosecond: 1 }
    ));
}

#[test]
fn years_outside_the_packed_range_are_rejected() {
    for year in [1999, 2064] {
        let error = PackedSilkroadTime::try_from(utc(year, 1, 1, 0, 0, 0)).unwrap_err();
        assert!(
            matches!(error, TimeError::PackedYearOutOfRange { year: actual } if actual == year)
        );
    }
}

#[test]
fn minimum_maximum_and_leap_day_are_representable() {
    for value in [
        utc(2000, 1, 1, 0, 0, 0),
        utc(2063, 12, 31, 23, 59, 59),
        utc(2000, 2, 29, 23, 59, 59),
    ] {
        let packed = PackedSilkroadTime::try_from(value).unwrap();
        assert_eq!(
            *PackedSilkroadTime::from_u32(packed.as_u32().unwrap()).unwrap(),
            value
        );
    }
}

#[test]
fn known_packed_vector_has_exact_value_and_little_endian_bytes() {
    let packed = PackedSilkroadTime::try_from(utc(2001, 10, 20, 14, 24, 40)).unwrap();

    assert_eq!(packed.as_u32().unwrap(), 2_709_999_169);

    let mut output = bytes::BytesMut::new();
    packed
        .write_to(&mut output, &SerdeContext::default())
        .unwrap();
    assert_eq!(&output[..], &2_709_999_169_u32.to_le_bytes());
}

#[test]
fn fixed_offset_input_is_normalized_to_utc_and_can_be_extracted() {
    let offset = FixedOffset::east_opt(2 * 60 * 60).unwrap();
    let local = offset
        .with_ymd_and_hms(2001, 10, 21, 0, 24, 40)
        .single()
        .unwrap();
    let expected = utc(2001, 10, 20, 22, 24, 40);

    let packed = PackedSilkroadTime::try_from(local).unwrap();

    assert_eq!(packed.as_datetime(), &expected);
    assert_eq!(*packed, expected);
    assert_eq!(packed.into_datetime(), expected);
}
