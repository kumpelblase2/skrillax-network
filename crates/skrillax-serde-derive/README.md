# skrillax-serde-derive

Derive macros for `Serialize`, `Deserialize`, and `ByteSize` from
[`skrillax-serde`](../skrillax-serde/README.md). See the
[module documentation](https://docs.rs/skrillax-serde-derive/latest/skrillax_serde_derive/)
for the complete `#[silkroad(...)]` attribute reference and examples. Runtime and
compile-fail coverage lives in [`skrillax-serde-derive-test`](../skrillax-serde-derive-test).

## Wire contract

For every well-formed value and matching `SerdeContext`, the three derives share
one wire description:

- `byte_size()` equals the number of serialized bytes;
- deserializing serialized data recreates the value;
- deserialization consumes exactly that value and leaves trailing data alone.

A synthetic scalar declared with `calculate` is the deliberate round-trip
exception: it occupies no wire bytes and deserialization recomputes it.

`Serialize` is fallible. Lengths and value-dependent invariants are checked when
the relevant field is reached and return `SerializationError`. A failure can
leave bytes from earlier fields in the destination buffer; use a fresh buffer or
truncate to a recorded starting length when atomic behavior is needed.

`ByteSize` remains infallible and does not validate values. It is exact for a
well-formed value, but its result is not authoritative when serialization would
reject that value.

Deriving `Serialize` generates `TryFrom<T> for bytes::Bytes` with
`SerializationError`; it does not generate an infallible `From` implementation.

## Attribute summary

- Integer widths use their actual wire-byte size: `1` → `u8`, `2` → `u16`,
  `4` → `u32`, and `8` → `u64`.
- Strings use a `u16` prefix. The default/`size = 1` codec is UTF-8 and counts
  bytes; `size = 2` is UTF-16LE and counts UTF-16 code units.
- `Vec<T>` supports counted (`length`), sentinel (`break` and `has-more`), and
  external-count (`calculated`) framing. Configured widths apply to counts and
  sentinel markers.
- `Option<T>` uses configurable `0`/`1` markers, a marker-free `when`
  condition, or write-only bare presence with `size = 0`.
- Arrays `[T; N]` have no prefix and work for any element implementing the
  relevant wire trait.
- Enum discriminants support widths `1`, `2`, `4`, and `8`; `size = 0` selects
  variants from context without writing a discriminant.

Invalid widths, conflicting attributes, ambiguous nesting, and unsupported
shapes fail during derive expansion rather than silently choosing a format.
