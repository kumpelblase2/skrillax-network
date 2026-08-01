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
