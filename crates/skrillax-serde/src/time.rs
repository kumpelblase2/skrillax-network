//! Time related convenience structures and serialization/deserialization
//! implementations, as time in Silkroad Online may be a little tricky to
//! display.
#![cfg(feature = "chrono")]

use crate::{ByteSize, Deserialize, SerializationError, Serialize};
use byteorder::{LittleEndian, ReadBytesExt};
use bytes::{BufMut, BytesMut};
use chrono::{DateTime, Datelike, Duration as CDuration, TimeZone, Timelike, Utc};
use std::io::Read;
use std::ops::{Add, Deref};
use std::time::Duration;

/// A date time for Silkroad Online, which assumes the time is _after_
/// 2000-01-01 00:00. This time should only be used as a representation for time
/// to be serialized/deserialized and not for actual timekeeping. Instead, use
/// the [From]/[Deref] traits to convert to or from this type right before or
/// after transferring it over the network. This is essentially just a newtype
/// around the [chrono::DateTime] type.
///
/// Also note that there are serialization/deserialization implementations for
/// [chrono::DateTime] as well, which behaves differently. This is another quirk
/// of Silkroad Online; having multiple ways of representing a date time. A
/// [SilkroadTime] takes 4 bytes, while a [DateTime] will be serialized into 16
/// bytes. Therefor, depending on the data type, one or the other may be chosen.
#[derive(Copy, Clone, Debug)]
pub struct SilkroadTime(DateTime<Utc>);

impl SilkroadTime {
    pub fn as_u32(&self) -> u32 {
        ((self.year() - 2000) as u32) & 63
            | ((self.month() - 1) & 15) << 6
            | ((self.day() - 1) & 31) << 10
            | (self.hour() & 31) << 15
            | (self.minute() & 63) << 20
            | (self.second() & 63) << 26
    }

    pub fn from_u32(data: u32) -> Self {
        let year = (data & 63) + 2000;
        let month = ((data >> 6) & 15) + 1;
        let day = ((data >> 10) & 31) + 1;
        let hours = (data >> 15) & 31;
        let minute = (data >> 20) & 63;
        let second = (data >> 26) & 63;
        SilkroadTime(
            Utc.with_ymd_and_hms(year as i32, month, day, hours, minute, second)
                .unwrap(),
        )
    }
}

impl Default for SilkroadTime {
    fn default() -> Self {
        SilkroadTime(Utc::now())
    }
}

impl From<DateTime<Utc>> for SilkroadTime {
    fn from(time: DateTime<Utc>) -> Self {
        Self(time)
    }
}

impl From<Duration> for SilkroadTime {
    fn from(duration: Duration) -> Self {
        let start = Utc.with_ymd_and_hms(2000, 1, 1, 0, 0, 0).unwrap();
        let new = start.add(CDuration::from_std(duration).unwrap());
        SilkroadTime(new)
    }
}

impl Deref for SilkroadTime {
    type Target = DateTime<Utc>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Serialize for SilkroadTime {
    fn write_to(&self, writer: &mut BytesMut) {
        self.as_u32().write_to(writer)
    }
}

impl ByteSize for SilkroadTime {
    fn byte_size(&self) -> usize {
        4
    }
}

impl Deserialize for SilkroadTime {
    fn read_from<T: Read + ReadBytesExt>(reader: &mut T) -> Result<Self, SerializationError>
    where
        Self: Sized,
    {
        let data = reader.read_u32::<LittleEndian>()?;
        Ok(SilkroadTime::from_u32(data))
    }
}

impl<T: TimeZone> Serialize for DateTime<T> {
    fn write_to(&self, writer: &mut BytesMut) {
        let utc_time = self.to_utc();
        writer.put_u16_le(utc_time.year() as u16);
        writer.put_u16_le(utc_time.month() as u16);
        writer.put_u16_le(utc_time.day() as u16);
        writer.put_u16_le(utc_time.hour() as u16);
        writer.put_u16_le(utc_time.minute() as u16);
        writer.put_u16_le(utc_time.second() as u16);
        writer.put_u32_le(utc_time.timestamp_millis() as u32);
    }
}

impl<T: TimeZone> ByteSize for DateTime<T> {
    fn byte_size(&self) -> usize {
        16
    }
}

impl Deserialize for DateTime<Utc> {
    fn read_from<T: Read + ReadBytesExt>(reader: &mut T) -> Result<Self, SerializationError> {
        let timestamp = Utc
            .with_ymd_and_hms(
                reader.read_u16::<LittleEndian>()? as i32,
                reader.read_u16::<LittleEndian>()? as u32,
                reader.read_u16::<LittleEndian>()? as u32,
                reader.read_u16::<LittleEndian>()? as u32,
                reader.read_u16::<LittleEndian>()? as u32,
                reader.read_u16::<LittleEndian>()? as u32,
            )
            .unwrap();
        Ok(timestamp + Duration::from_millis(reader.read_u32::<LittleEndian>()? as u64))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    pub fn test_convert_time() {
        let one_year = 60 * 60 * 24 * 366u64;
        let one_day = 60 * 60 * 24u64;

        let time_now = Duration::from_secs(one_year + one_day + 35);
        let sro_time = SilkroadTime::from(time_now);
        let mut bytes = BytesMut::new();
        sro_time.write_to(&mut bytes);
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
        let time = SilkroadTime::from(Utc.with_ymd_and_hms(2001, 10, 20, 14, 24, 40).unwrap());
        let res = time.as_u32();
        assert_eq!(res, 2709999169);
    }

    #[test]
    pub fn test_convert_time_back() {
        let time = SilkroadTime::from_u32(2709999169);
        assert_eq!(time.year(), 2001);
        assert_eq!(time.month(), 10);
        assert_eq!(time.day(), 20);
        assert_eq!(time.hour(), 14);
        assert_eq!(time.minute(), 24);
        assert_eq!(time.second(), 40);
    }
}
