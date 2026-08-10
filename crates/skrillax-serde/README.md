# skrillax-serde

[![Crates.io](https://img.shields.io/crates/v/skrillax-serde.svg)](https://crates.io/crates/skrillax-serde)
[![Docs.rs](https://docs.rs/skrillax-serde/badge.svg)](https://docs.rs/skrillax-serde)

Silkroad packets are not self-describing and use several field-specific framing
schemes. Although general-purpose [Serde](https://serde.rs/) can represent these
formats, doing so requires protocol-specific serializer hooks throughout packet
definitions. `skrillax-serde` instead provides focused `Serialize`,
`Deserialize`, and `ByteSize` traits plus optional derive macros whose
`#[silkroad(...)]` attributes describe the wire format directly.

The core crate implements the traits for primitives, time values, and generic
fixed-size arrays. Enable the `derive` feature to re-export the macros from
[`skrillax-serde-derive`](../skrillax-serde-derive/README.md).

## Wire format

Fields are encoded consecutively in declaration order, generally in
little-endian byte order. There are no implicit separators.

- Primitive integers and floating-point values use their fixed wire width.
- `[T; N]` has no prefix and concatenates exactly `N` elements.
- A `String` has a little-endian `u16` prefix. UTF-8 strings count payload bytes;
  UTF-16LE strings count UTF-16 code units, not Rust UTF-8 bytes.
- A counted `Vec<T>` prefixes its element count. `size = 1`, `2`, `4`, or `8`
  selects `u8`, `u16`, `u32`, or `u64`.
- Sentinel collections write a marker before each element and a terminal marker.
  `break` uses `1`/`2`, while `has-more` uses `1`/`0`. Markers honor the same
  configured widths.
- A calculated collection gets its count from another field or `SerdeContext`
  and writes no collection-local prefix.
- `Option<T>` normally uses a configurable-width `0`/`1` marker. Conditional
  options use `when` and no marker. A bare `size = 0` option is supported only
  for `Serialize` and `ByteSize`, because it cannot be decoded unambiguously.
- Enum discriminants support widths `1`, `2`, `4`, and `8`. Predicate-tagged
  enum fields alias that discriminant and are emitted and counted only once.
  A zero-width enum selects a variant from context and emits no discriminant.

See the derive crate's
[module documentation](https://docs.rs/skrillax-serde-derive/latest/skrillax_serde_derive/)
for the complete attribute rules, calculated fields, enum predicates, and
supported nesting.

## Time formats

Time support requires the default-enabled `chrono` feature. The crate supports
two distinct little-endian wire layouts:

| Rust type | Layout | Representability |
|---|---|---|
| `PackedSilkroadTime` | 4-byte packed calendar | Valid UTC dates in years `2000..=2063`, whole seconds only |
| `ExpandedSilkroadTime` | Six `u16` calendar fields plus one `u32` fraction (16 bytes) | UTC year must fit `u16`; fraction is nanoseconds within the second (`0..=999_999_999`) |

Both types are UTC-backed newtypes. `TryFrom<DateTime<Tz>>` converts the input
instant to UTC and validates wire representability before constructing either
wrapper. This means a successfully constructed value is ready to serialize:
packed construction rejects out-of-range years and subsecond precision, while
expanded construction rejects a UTC year that cannot fit its `u16` field.
Borrow the normalized value with `as_datetime()` or extract it with
`into_datetime()`.

Only the explicit wrappers implement `Serialize`, `Deserialize`, and
`ByteSize`; bare `chrono::DateTime` values do not select a Silkroad wire layout.
Expanded deserialization treats the calendar fields as UTC. The wire format
contains no timezone marker; UTC normalization during wrapper construction is
this crate's explicit API policy. See the
[expanded-time protocol evidence](../../docs/protocol/expanded-time.md) for the
nanosecond interpretation and its provenance.

A complete malformed wire value produces a typed `TimeError`, wrapped as
`SerializationError::Time` by the serialization traits. Direct time decoding
reports truncation as `SerializationError::IoError`; a derived packet field may
add its field context as `SerializationError::FieldIoError`. `ByteSize` reports
the wrapper's fixed width: 4 bytes for packed time and 16 bytes for expanded
time.

## Serialization contract

`Serialize::write_to` and `write_to_end` return
`Result<(), SerializationError>`. Derived serializers reject lengths that do
not fit configured prefixes and value/context combinations that would not round
trip. Nested serialization errors are propagated.

Validation occurs as fields are written. If a later field fails, bytes already
written remain in the `BytesMut`; serialization is deliberately not atomic. A
fresh packet buffer can simply be discarded. Callers reusing a shared buffer can
provide transactional behavior themselves:

```rust
use bytes::BytesMut;
use skrillax_serde::{SerdeContext, Serialize};

fn append<T: Serialize>(
    value: &T,
    output: &mut BytesMut,
    context: &SerdeContext,
) -> Result<(), skrillax_serde::SerializationError> {
    let original_len = output.len();
    if let Err(error) = value.write_to(output, context) {
        output.truncate(original_len);
        return Err(error);
    }
    Ok(())
}
```

`write_to_end` reserves `byte_size()` bytes before serialization. Reservation
can overallocate when an ill-formed value later fails; it is not validation.

## Collection deserialization limits

Collection decoding is unlimited by default, preserving the protocol's existing
count range. Applications accepting untrusted input can opt into a per-
collection element limit through `SerdeContext`:

```rust
use skrillax_serde::{DeserializationLimits, SerdeContext};

let context = SerdeContext::default();
context.set_deserialization_limits(
    DeserializationLimits::with_max_collection_elements(10_000),
);
```

Choose a maximum appropriate for the application's packet models; there is no
universal safe value. The high-level `skrillax-stream` network adapter applies
its own documented conservative default while direct serde use remains
unlimited. Counted and calculated collections are checked before
allocation and element decoding. Sentinel-framed collections are checked before
each announced element. Capacity reservation is fallible even when no policy is
configured, so capacity overflow and allocator failures reported by
`try_reserve` return `SerializationError::CollectionAllocationFailed` rather
than panicking through eager capacity creation.

The setting applies independently to each collection and is measured in
elements, not bytes. It is used during deserialization only: `Serialize` and
`ByteSize` ignore it. It is not a cumulative nested-value budget or a byte,
packet, frame, reassembly, connection, or stream limit. Context clones share the
setting; configure it before decoding and do not mutate it concurrently with a
decode. Call `clear_deserialization_limits()` to restore unlimited behavior.

## `ByteSize` contract

`ByteSize::byte_size()` is infallible and context-free. For every well-formed
value and matching context, it exactly equals the number of bytes emitted by
`Serialize`. It is an allocation estimate only: for an ill-formed value that
serialization would reject, the result is not guaranteed to be useful or
authoritative and callers must not treat it as validation.

## Migration from the infallible API

Serialization and packet construction are now fallible:

```rust
use bytes::{Bytes, BytesMut};
use skrillax_serde::{ByteSize, SerdeContext, Serialize};

# #[derive(ByteSize, Serialize)]
# struct MyPacket(u8);
# fn example(packet: MyPacket) -> Result<(), skrillax_serde::SerializationError> {
let bytes = Bytes::try_from(packet)?;

let mut output = BytesMut::new();
1u16.write_to_end(&mut output, &SerdeContext::default())?;
# Ok(())
# }
```

Replace `Bytes::from(value)` or conversions through `Into<Bytes>` with
`Bytes::try_from(value)`/`TryInto`. Manual `Serialize` implementations must
return `Result<(), SerializationError>` and propagate nested writes with `?`.
At the packet layer, `AsPacket::as_packet` also returns a `Result`; stream APIs
surface failures as `OutStreamError::PacketError` before sending frames.

### Packed-time migration

`SilkroadTime` has been replaced by `PackedSilkroadTime`; there is no deprecated
alias or compatibility layer. Construction and extraction do not discard
precision or wrap out-of-range values. `TryFrom<DateTime<Tz>>` first normalizes
the instant to UTC, then requires a whole-second value in years `2000..=2063`.
The raw `from_u32` and `as_u32` boundaries are also fallible:

```rust
use chrono::{DateTime, FixedOffset, Utc};
use skrillax_serde::{PackedSilkroadTime, TimeError};
use std::time::Duration;

fn from_datetime(value: DateTime<FixedOffset>) -> Result<u32, TimeError> {
    let packed = PackedSilkroadTime::try_from(value)?;
    packed.as_u32()
}

fn from_wire_integer(raw: u32) -> Result<PackedSilkroadTime, TimeError> {
    PackedSilkroadTime::from_u32(raw)
}

fn from_elapsed_since_epoch(
    elapsed: Duration,
) -> Result<PackedSilkroadTime, TimeError> {
    // Duration::ZERO is 2000-01-01 00:00:00 UTC.
    PackedSilkroadTime::try_from(elapsed)
}

fn extract(value: PackedSilkroadTime) -> DateTime<Utc> {
    value.into_datetime()
}
```

The old infallible `From<DateTime<Utc>>` and `From<Duration>` implementations
and `Default` remain removed. Use `as_datetime()` when only a borrowed UTC
`DateTime` is needed.

### Expanded-time migration

Bare `DateTime<Utc>` packet fields must become `ExpandedSilkroadTime` fields.
Bare `DateTime<Tz>` no longer implements this crate's serialization traits, so
the wire layout is explicit at each field. Construct the wrapper with `TryFrom`
at an application boundary; any timezone is normalized to UTC and the expanded
year is validated there. After decoding, use `as_datetime()` to borrow the UTC
value or `into_datetime()` to extract it.

The expanded format preserves nanoseconds rather than interpreting or emitting
the trailing field as an absolute timestamp:

```rust
use bytes::BytesMut;
use chrono::{DateTime, FixedOffset, Utc};
use skrillax_serde::{
    Deserialize, ExpandedSilkroadTime, SerdeContext, SerializationError, Serialize,
};

fn round_trip_expanded(
    value: DateTime<FixedOffset>,
) -> Result<DateTime<Utc>, SerializationError> {
    let value = ExpandedSilkroadTime::try_from(value)?;
    let context = SerdeContext::default();
    let mut bytes = BytesMut::new();
    value.write_to(&mut bytes, &context)?;

    let mut input = &bytes[..];
    let decoded = ExpandedSilkroadTime::read_from(&mut input, &context)?;
    Ok(decoded.into_datetime())
}
```

There is no compatibility implementation for bare `DateTime` and no alias for
the old `SilkroadTime` name.
