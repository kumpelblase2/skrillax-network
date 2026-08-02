//! Silkroad packed and expanded time wire formats.
//!
//! This module is available with the `chrono` feature. [`PackedSilkroadTime`]
//! is the four-byte packed format, while [`ExpandedSilkroadTime`] is the
//! 16-byte expanded format. Both formats validate complete values and report
//! failures through [`TimeError`].
#![cfg(feature = "chrono")]

use crate::{ByteSize, Deserialize, SerdeContext, SerializationError, Serialize};
use byteorder::{LittleEndian, ReadBytesExt};
use bytes::{BufMut, BytesMut};
use chrono::{DateTime, Datelike, Duration as CDuration, TimeZone, Timelike, Utc};
use std::io::Read;
use std::ops::Deref;
use std::time::Duration;
use thiserror::Error;

/// A packed- or expanded-time validation failure.
///
/// Serialization and deserialization wrap this error in
/// `SerializationError::Time`. An input that ends before the complete four- or
/// 16-byte value is available remains an I/O error instead.
#[derive(Debug, Error)]
pub enum TimeError {
    /// A complete packed value contains invalid calendar components.
    #[error(
        "packed time {raw:#010x} contains an invalid calendar value: \
         {year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}"
    )]
    InvalidPackedCalendar {
        raw: u32,
        year: i32,
        month: u32,
        day: u32,
        hour: u32,
        minute: u32,
        second: u32,
    },
    /// A date's year is outside the packed `2000..=2063` range.
    #[error("year {year} is outside the packed time range")]
    PackedYearOutOfRange { year: i32 },
    /// A packed value has subsecond precision, which the format cannot encode.
    #[error("nanosecond value {nanosecond} cannot be represented by packed time")]
    PackedSubsecondOutOfRange { nanosecond: u32 },
    /// A standard duration cannot be added to the packed epoch without
    /// overflow.
    #[error("duration with {seconds} seconds and {nanoseconds} nanoseconds is out of range")]
    DurationOutOfRange { seconds: u64, nanoseconds: u32 },
    /// A complete expanded value contains invalid calendar components.
    #[error(
        "expanded time contains an invalid calendar value: {year:04}-{month:02}-{day:02} \
         {hour:02}:{minute:02}:{second:02}"
    )]
    InvalidExpandedCalendar {
        year: u16,
        month: u16,
        day: u16,
        hour: u16,
        minute: u16,
        second: u16,
    },
    /// An expanded value's fractional field is not a valid nanosecond value.
    #[error("expanded time {unit} value {value} exceeds maximum {maximum}")]
    InvalidExpandedFraction {
        value: u32,
        maximum: u32,
        unit: &'static str,
    },
    /// A date's UTC year cannot be represented by the expanded `u16` year.
    #[error("year {year} is outside the expanded time range")]
    ExpandedYearOutOfRange { year: i32 },
    /// An expanded calendar component cannot be represented by its `u16` field.
    #[error("expanded time {component} value {value} is outside the u16 wire range")]
    ExpandedComponentOutOfRange { component: &'static str, value: u32 },
}

const MAX_EXPANDED_NANOSECOND: u32 = 999_999_999;

#[derive(Copy, Clone)]
struct ExpandedTimeFields {
    year: u16,
    month: u16,
    day: u16,
    hour: u16,
    minute: u16,
    second: u16,
    nanosecond: u32,
}

impl ExpandedTimeFields {
    fn from_datetime<T: TimeZone>(time: &DateTime<T>) -> Result<Self, TimeError> {
        fn component(value: u32, name: &'static str) -> Result<u16, TimeError> {
            u16::try_from(value).map_err(|_| TimeError::ExpandedComponentOutOfRange {
                component: name,
                value,
            })
        }

        let utc_time = time.to_utc();
        let year = utc_time.year();
        let fields = Self {
            year: u16::try_from(year).map_err(|_| TimeError::ExpandedYearOutOfRange { year })?,
            month: component(utc_time.month(), "month")?,
            day: component(utc_time.day(), "day")?,
            hour: component(utc_time.hour(), "hour")?,
            minute: component(utc_time.minute(), "minute")?,
            second: component(utc_time.second(), "second")?,
            nanosecond: utc_time.timestamp_subsec_nanos(),
        };
        fields.to_datetime()?;
        Ok(fields)
    }

    fn to_datetime(self) -> Result<DateTime<Utc>, TimeError> {
        let timestamp = Utc
            .with_ymd_and_hms(
                i32::from(self.year),
                u32::from(self.month),
                u32::from(self.day),
                u32::from(self.hour),
                u32::from(self.minute),
                u32::from(self.second),
            )
            .single()
            .ok_or(TimeError::InvalidExpandedCalendar {
                year: self.year,
                month: self.month,
                day: self.day,
                hour: self.hour,
                minute: self.minute,
                second: self.second,
            })?;

        if self.nanosecond > MAX_EXPANDED_NANOSECOND {
            return Err(TimeError::InvalidExpandedFraction {
                value: self.nanosecond,
                maximum: MAX_EXPANDED_NANOSECOND,
                unit: "nanoseconds",
            });
        }

        timestamp
            .with_nanosecond(self.nanosecond)
            .ok_or(TimeError::InvalidExpandedFraction {
                value: self.nanosecond,
                maximum: MAX_EXPANDED_NANOSECOND,
                unit: "nanoseconds",
            })
    }
}

/// A UTC date and time in Silkroad's four-byte packed representation.
///
/// Packed time represents valid calendar values from `2000-01-01 00:00:00`
/// through `2063-12-31 23:59:59`. It stores whole seconds only; nonzero
/// nanoseconds are not representable. Use `PackedSilkroadTime::try_from` to
/// validate a `DateTime` or `std::time::Duration` before serialization, and
/// deref the result to access its underlying `DateTime<Utc>`.
///
/// This type is distinct from [`ExpandedSilkroadTime`], which occupies 16
/// bytes.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct PackedSilkroadTime(DateTime<Utc>);

impl PackedSilkroadTime {
    /// Borrows the validated UTC date and time.
    pub fn as_datetime(&self) -> &DateTime<Utc> {
        &self.0
    }

    /// Consumes this value and returns its validated UTC date and time.
    pub fn into_datetime(self) -> DateTime<Utc> {
        self.0
    }

    /// Returns the packed 32-bit value after validating representability.
    ///
    /// The value uses the same bit layout that [`Serialize`] writes in
    /// little-endian order. Years outside `2000..=2063` and nonzero
    /// nanoseconds return a [`TimeError`] instead of being masked or truncated.
    pub fn as_u32(&self) -> Result<u32, TimeError> {
        let year = self.year();
        if !(2000..=2063).contains(&year) {
            return Err(TimeError::PackedYearOutOfRange { year });
        }

        let nanosecond = self.nanosecond();
        if nanosecond != 0 {
            return Err(TimeError::PackedSubsecondOutOfRange { nanosecond });
        }

        Ok((year - 2000) as u32
            | (self.month() - 1) << 6
            | (self.day() - 1) << 10
            | self.hour() << 15
            | self.minute() << 20
            | self.second() << 26)
    }

    /// Decodes and validates a packed 32-bit value.
    ///
    /// The argument is the host-order integer obtained from the four-byte wire
    /// value. Encodable but impossible calendars, such as month 16 or a
    /// non-leap February 29, return [`TimeError::InvalidPackedCalendar`].
    pub fn from_u32(raw: u32) -> Result<Self, TimeError> {
        let year = ((raw & 63) + 2000) as i32;
        let month = ((raw >> 6) & 15) + 1;
        let day = ((raw >> 10) & 31) + 1;
        let hour = (raw >> 15) & 31;
        let minute = (raw >> 20) & 63;
        let second = (raw >> 26) & 63;
        let time = Utc
            .with_ymd_and_hms(year, month, day, hour, minute, second)
            .single()
            .ok_or(TimeError::InvalidPackedCalendar {
                raw,
                year,
                month,
                day,
                hour,
                minute,
                second,
            })?;
        Ok(Self(time))
    }
}

/// Fallibly converts a date into packed time without losing precision.
///
/// The instant is normalized to UTC and accepted only when its UTC year is in
/// `2000..=2063` and it has zero nanoseconds.
impl<Tz: TimeZone> TryFrom<DateTime<Tz>> for PackedSilkroadTime {
    type Error = TimeError;

    fn try_from(time: DateTime<Tz>) -> Result<Self, Self::Error> {
        let packed = Self(time.to_utc());
        packed.as_u32()?;
        Ok(packed)
    }
}

/// Treats a duration as elapsed time since `2000-01-01 00:00:00 UTC`.
///
/// The resulting instant must remain in the packed `2000..=2063` range and the
/// duration must contain a whole number of seconds. Conversion is fallible and
/// never truncates fractional seconds or wraps overflowing values.
impl TryFrom<Duration> for PackedSilkroadTime {
    type Error = TimeError;

    fn try_from(duration: Duration) -> Result<Self, Self::Error> {
        let out_of_range = || TimeError::DurationOutOfRange {
            seconds: duration.as_secs(),
            nanoseconds: duration.subsec_nanos(),
        };
        let offset = CDuration::from_std(duration).map_err(|_| out_of_range())?;
        let epoch = Utc
            .with_ymd_and_hms(2000, 1, 1, 0, 0, 0)
            .single()
            .ok_or_else(out_of_range)?;
        let time = epoch.checked_add_signed(offset).ok_or_else(out_of_range)?;
        Self::try_from(time)
    }
}

impl AsRef<DateTime<Utc>> for PackedSilkroadTime {
    fn as_ref(&self) -> &DateTime<Utc> {
        self.as_datetime()
    }
}

/// Exposes the validated UTC date and time represented by this value.
impl Deref for PackedSilkroadTime {
    type Target = DateTime<Utc>;

    fn deref(&self) -> &Self::Target {
        self.as_datetime()
    }
}

impl From<PackedSilkroadTime> for DateTime<Utc> {
    fn from(time: PackedSilkroadTime) -> Self {
        time.into_datetime()
    }
}

/// Writes the validated packed value as four little-endian bytes.
impl Serialize for PackedSilkroadTime {
    fn write_to(
        &self,
        writer: &mut BytesMut,
        ctx: &SerdeContext,
    ) -> Result<(), SerializationError> {
        self.as_u32()?.write_to(writer, ctx)
    }
}

/// Reports the packed format's fixed four-byte width without validating it.
impl ByteSize for PackedSilkroadTime {
    fn byte_size(&self) -> usize {
        4
    }
}

/// Reads exactly four little-endian bytes and validates the packed calendar.
///
/// A complete malformed value becomes `SerializationError::Time`; an input
/// shorter than four bytes remains `SerializationError::IoError`.
impl Deserialize for PackedSilkroadTime {
    fn read_from<T: Read + ReadBytesExt>(
        reader: &mut T,
        _ctx: &SerdeContext,
    ) -> Result<Self, SerializationError>
    where
        Self: Sized,
    {
        let data = reader.read_u32::<LittleEndian>()?;
        Ok(Self::from_u32(data)?)
    }
}

/// A UTC date and time in Silkroad's 16-byte expanded representation.
///
/// The wire format contains six little-endian `u16` calendar fields (year
/// through second) followed by a little-endian `u32` nanosecond-within-second
/// value. Construction normalizes the instant to UTC and validates that the
/// UTC year can be represented by the wire format.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct ExpandedSilkroadTime(DateTime<Utc>);

impl ExpandedSilkroadTime {
    /// Borrows the validated UTC date and time.
    pub fn as_datetime(&self) -> &DateTime<Utc> {
        &self.0
    }

    /// Consumes this value and returns its validated UTC date and time.
    pub fn into_datetime(self) -> DateTime<Utc> {
        self.0
    }
}

impl<Tz: TimeZone> TryFrom<DateTime<Tz>> for ExpandedSilkroadTime {
    type Error = TimeError;

    fn try_from(time: DateTime<Tz>) -> Result<Self, Self::Error> {
        let time = time.to_utc();
        ExpandedTimeFields::from_datetime(&time)?;
        Ok(Self(time))
    }
}

impl AsRef<DateTime<Utc>> for ExpandedSilkroadTime {
    fn as_ref(&self) -> &DateTime<Utc> {
        self.as_datetime()
    }
}

impl Deref for ExpandedSilkroadTime {
    type Target = DateTime<Utc>;

    fn deref(&self) -> &Self::Target {
        self.as_datetime()
    }
}

impl From<ExpandedSilkroadTime> for DateTime<Utc> {
    fn from(time: ExpandedSilkroadTime) -> Self {
        time.into_datetime()
    }
}

/// Writes the validated expanded value as 16 little-endian bytes.
///
/// Validation is completed before output is appended.
impl Serialize for ExpandedSilkroadTime {
    fn write_to(
        &self,
        writer: &mut BytesMut,
        _ctx: &SerdeContext,
    ) -> Result<(), SerializationError> {
        let fields = ExpandedTimeFields::from_datetime(self.as_datetime())?;

        writer.put_u16_le(fields.year);
        writer.put_u16_le(fields.month);
        writer.put_u16_le(fields.day);
        writer.put_u16_le(fields.hour);
        writer.put_u16_le(fields.minute);
        writer.put_u16_le(fields.second);
        writer.put_u32_le(fields.nanosecond);
        Ok(())
    }
}

/// Reports the expanded format's fixed 16-byte width.
impl ByteSize for ExpandedSilkroadTime {
    fn byte_size(&self) -> usize {
        16
    }
}

/// Reads a 16-byte expanded time.
///
/// All 16 bytes are read before validation. The six little-endian `u16`
/// calendar fields are interpreted as UTC, and the final little-endian `u32`
/// is nanoseconds within the second in `0..=999_999_999`. Complete malformed
/// values return a typed `SerializationError::Time`; truncated input remains
/// `SerializationError::IoError`.
impl Deserialize for ExpandedSilkroadTime {
    fn read_from<T: Read + ReadBytesExt>(
        reader: &mut T,
        _ctx: &SerdeContext,
    ) -> Result<Self, SerializationError> {
        let year = reader.read_u16::<LittleEndian>()?;
        let month = reader.read_u16::<LittleEndian>()?;
        let day = reader.read_u16::<LittleEndian>()?;
        let hour = reader.read_u16::<LittleEndian>()?;
        let minute = reader.read_u16::<LittleEndian>()?;
        let second = reader.read_u16::<LittleEndian>()?;
        let nanosecond = reader.read_u32::<LittleEndian>()?;
        let time = ExpandedTimeFields {
            year,
            month,
            day,
            hour,
            minute,
            second,
            nanosecond,
        }
        .to_datetime()?;
        Ok(Self(time))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn serialization_validation_preserves_existing_output() {
        let invalid = PackedSilkroadTime(
            Utc.with_ymd_and_hms(2001, 10, 20, 14, 24, 40)
                .single()
                .unwrap()
                .with_nanosecond(1)
                .unwrap(),
        );
        let mut output = BytesMut::from(&[0xa5][..]);

        let error = invalid
            .write_to(&mut output, &SerdeContext::default())
            .unwrap_err();

        assert!(matches!(
            error,
            SerializationError::Time(TimeError::PackedSubsecondOutOfRange { nanosecond: 1 })
        ));
        assert_eq!(&output[..], &[0xa5]);
    }

    #[test]
    pub fn test_convert_time() {
        let one_year = 60 * 60 * 24 * 366u64;
        let one_day = 60 * 60 * 24u64;

        let time_now = Duration::from_secs(one_year + one_day + 35);
        let sro_time = PackedSilkroadTime::try_from(time_now).unwrap();
        let mut bytes = BytesMut::new();
        sro_time
            .write_to(&mut bytes, &SerdeContext::default())
            .unwrap();
        let written_bytes = bytes.freeze();

        assert_eq!(written_bytes.len(), 4);

        let lowest = written_bytes[0];
        assert_eq!(lowest, 1); // The lowest 6 bits contain the year since year 2000, thus should be 1

        let second = written_bytes[1];
        assert_eq!(second >> 2, 1); // We need to shift by two to get the day part from the second byte

        let highest = written_bytes[3];
        assert_eq!(highest >> 2, 35);
    }

    #[test]
    pub fn test_to_u32() {
        let time =
            PackedSilkroadTime::try_from(Utc.with_ymd_and_hms(2001, 10, 20, 14, 24, 40).unwrap())
                .unwrap();
        let res = time.as_u32().unwrap();
        assert_eq!(res, 2709999169);
    }

    #[test]
    pub fn test_convert_time_back() {
        let time = PackedSilkroadTime::from_u32(2709999169).unwrap();
        assert_eq!(time.year(), 2001);
        assert_eq!(time.month(), 10);
        assert_eq!(time.day(), 20);
        assert_eq!(time.hour(), 14);
        assert_eq!(time.minute(), 24);
        assert_eq!(time.second(), 40);
    }
}
