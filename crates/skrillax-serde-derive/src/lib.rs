//! Derive macros for the Silkroad wire traits in [`skrillax-serde`](https://docs.rs/skrillax-serde).
//!
//! Silkroad packets are not self-describing. The `#[silkroad(...)]` attribute
//! therefore supplies framing, presence, encoding, and enum-selection metadata
//! that cannot be inferred from a Rust type alone. Derive expansion rejects
//! unsupported placements and ambiguous combinations instead of guessing a
//! wire format.
//!
//! Most packet types derive all three traits:
//!
//! ```ignore
//! #[derive(Serialize, Deserialize, ByteSize)]
//! struct Position {
//!     region: u16,
//!     x: f32,
//!     y: f32,
//! }
//! ```
//!
//! Struct and variant fields are concatenated in declaration order with no
//! implicit separators. Unit structs and unit variant bodies occupy zero bytes.
//!
//! ## Serialization and sizing contract
//!
//! Derived [`Serialize`](https://docs.rs/skrillax-serde/latest/skrillax_serde/trait.Serialize.html)
//! is fallible. It checks representability and value-dependent invariants when
//! it reaches the relevant field, returning a typed `SerializationError`.
//! Writes are not atomic: bytes already written to the destination remain when
//! a later field fails. Use a fresh buffer, or record its original length and
//! truncate it yourself if transactional behavior is required.
//!
//! `ByteSize::byte_size()` is infallible and exactly matches serialized output
//! for a well-formed value. It is an allocation estimate, not validation: its
//! result is not authoritative for a value that `Serialize` would reject, and
//! reserving that amount of space does not guarantee serialization will
//! succeed.
//!
//! Deriving `Serialize` also generates `TryFrom<T> for bytes::Bytes`, using a
//! default `SerdeContext`. It does not generate the old infallible
//! `From<T> for bytes::Bytes`. Call `write_to` directly when a non-default
//! context is needed.
//!
//! ## Strings
//!
//! A `String` has a little-endian `u16` length prefix. With no `size` or with
//! `size = 1`, the payload is UTF-8 and the prefix counts bytes. With
//! `size = 2`, the payload is UTF-16LE and the prefix counts UTF-16 code units,
//! including both units of a surrogate pair. Other string sizes are rejected.
//!
//! ```ignore
//! #[derive(Serialize, Deserialize, ByteSize)]
//! struct Greeting {
//!     normal: String,
//!     #[silkroad(size = 2)]
//!     wide: String,
//! }
//! ```
//!
//! Strings directly inside `Vec` and `Option` use the default UTF-8 codec.
//! Use a wrapper struct when a nested string needs UTF-16.
//!
//! ## Collections
//!
//! A `Vec<T>` defaults to `list_type = "length"` and `size = 1`: an unsigned
//! count followed by the elements. Sizes `1`, `2`, `4`, and `8` select `u8`,
//! `u16`, `u32`, and `u64` counts respectively.
//!
//! ```ignore
//! #[derive(Serialize, Deserialize, ByteSize)]
//! struct Inventory {
//!     #[silkroad(size = 2)]
//!     items: Vec<Item>,
//! }
//! ```
//!
//! Sentinel framing is selected with `list_type = "break"` or
//! `list_type = "has-more"`. A marker precedes every element and a terminal
//! marker follows the collection. `break` uses `1`/`2`; `has-more` uses
//! `1`/`0`. Marker width is selected by `size` with the same `1`, `2`, `4`, and
//! `8` mapping and defaults to one byte.
//!
//! A calculated collection has no collection-local count or marker. Its
//! `calculate` expression determines the element count from earlier fields or
//! `ctx`. Serialization requires that count to equal the vector length.
//!
//! ```ignore
//! #[derive(Serialize, Deserialize, ByteSize)]
//! struct Inventory {
//!     count: u16,
//!     #[silkroad(list_type = "calculated", calculate = "count")]
//!     items: Vec<Item>,
//! }
//! ```
//!
//! Directly nested collections and optional values are rejected because their
//! framing would be implicit; use a wrapper struct to supply field metadata.
//!
//! Collection deserialization observes the optional `DeserializationLimits`
//! stored in `SerdeContext`. The limit is unlimited by default, measured in
//! elements, and applied independently to each collection. Known counts are
//! checked before allocation and item reads; sentinel collections are checked
//! before each announced item. Vector reservation failures are returned as a
//! typed `SerializationError`.
//!
//! This receiver policy affects deserialization only. `Serialize` and
//! `ByteSize` do not consult it, so the round-trip guarantee is conditional on
//! the receiving context accepting the serialized collection lengths. It is
//! not a byte, packet, frame, reassembly, or stream limit.
//!
//! ## Optional fields
//!
//! An `Option<T>` normally has an unsigned `0`/`1` presence marker. The marker
//! defaults to one byte; `size = 1`, `2`, `4`, or `8` selects its width.
//! Deserialization rejects any marker other than `0` or `1`.
//!
//! `when` creates a marker-free conditional option. The condition may refer to
//! earlier fields and `ctx`. During serialization, its boolean result must
//! equal `Option::is_some()` or serialization returns
//! `ConditionalPresenceMismatch`.
//!
//! Expressions follow Rust's lexical binding scopes. Closure parameters,
//! block locals, match and loop patterns, and `if let`/`while let` bindings
//! shadow packet field names; bindings in a let chain are visible to the rest
//! of the chain and its guarded body, but not to an `else` branch.
//!
//! ```ignore
//! #[derive(Serialize, Deserialize, ByteSize)]
//! struct Greeting {
//!     enabled: bool,
//!     #[silkroad(when = "enabled")]
//!     text: Option<String>,
//! }
//! ```
//!
//! `#[silkroad(size = 0)]` without `when` is a bare write-only option: `Some`
//! emits the inner value and `None` emits nothing. It is supported by
//! `Serialize` and `ByteSize`, but a `Deserialize` derive rejects it because
//! absence cannot be distinguished from truncated input. `size = 0` may be
//! combined with `when` to state explicitly that the condition controls
//! presence.
//!
//! ## Calculated scalar fields
//!
//! `calculate` on a non-collection field makes that field synthetic. It emits
//! and counts zero bytes. Deserialization computes it from earlier fields or
//! `ctx`; serialization deliberately does not compare the stored value with
//! the expression. A noncanonical stored value therefore serializes, but a
//! round trip replaces it with the calculated value.
//!
//! ```ignore
//! #[derive(Serialize, Deserialize, ByteSize)]
//! struct Item {
//!     raw_kind: u8,
//!     #[silkroad(calculate = "ItemKind::from(raw_kind)")]
//!     kind: ItemKind,
//! }
//! ```
//!
//! ## Arrays and tuples
//!
//! `[T; N]` has no prefix and supports any `T` implementing the relevant wire
//! trait; its size is the sum of its elements. Tuple fields similarly
//! concatenate supported elements. Direct `String`, `Vec`, or `Option` tuple
//! elements are rejected in this version; use wrapper structs for metadata-
//! sensitive nested values.
//!
//! ## Enums
//!
//! Enum discriminants default to one byte. Container `size = 1`, `2`, `4`, or
//! `8` selects `u8`, `u16`, `u32`, or `u64`. Fixed selectors use a unique
//! `value` that must fit that width:
//!
//! ```ignore
//! #[derive(Serialize, Deserialize, ByteSize)]
//! #[silkroad(size = 2)]
//! enum Hello {
//!     #[silkroad(value = 0x400d)]
//!     Client(String),
//!     #[silkroad(value = 0x400e)]
//!     Server(String),
//! }
//! ```
//!
//! A nonzero-width enum may instead select every variant with an ordered
//! `when` predicate over `tag`. Every variant must contain exactly one
//! `#[silkroad(tag)]` field whose type exactly matches the selected unsigned
//! discriminant type. That field aliases the discriminant: it is written,
//! read, and counted once rather than also appearing in the variant body.
//! Serialization verifies that the Rust variant is the first matching
//! predicate, preserving round trips when predicates overlap.
//!
//! ```ignore
//! #[derive(Serialize, Deserialize, ByteSize)]
//! #[silkroad(size = 2)]
//! enum Tagged {
//!     #[silkroad(when = "tag < 100")]
//!     Small { #[silkroad(tag)] tag: u16 },
//!     #[silkroad(when = "tag >= 100")]
//!     Large { #[silkroad(tag)] tag: u16 },
//! }
//! ```
//!
//! `#[silkroad(size = 0)]` creates a context-selected enum with no
//! discriminant. Every variant must use an ordered `when` expression based on
//! `ctx` or external paths; `value`, `tag`, and variant-field references are
//! unavailable. Serialization again requires the selected Rust variant to be
//! the first matching predicate, and deserialization errors if none match.

use crate::deserialize::deserialize;
use crate::model::{DeriveOperation, normalize};
use crate::serialize::serialize;
use crate::size::size;
use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use proc_macro2_diagnostics::Diagnostic;
use quote::quote;
use syn::DeriveInput;

mod deserialize;
mod model;
mod serialize;
mod size;

#[proc_macro_derive(Serialize, attributes(silkroad))]
pub fn derive_serialize(input: TokenStream) -> TokenStream {
    expand_serialize(input.into())
        .unwrap_or_else(Diagnostic::emit_as_item_tokens)
        .into()
}

fn expand_serialize(input: TokenStream2) -> Result<TokenStream2, Diagnostic> {
    let input: DeriveInput = syn::parse2(input)?;
    let model = normalize(&input, DeriveOperation::Serialize)?;
    let ident = model.ident;
    let output = serialize(&model)?;

    Ok(quote! {
        impl skrillax_serde::Serialize for #ident {
            fn write_to(
                &self,
                writer: &mut ::skrillax_serde::__internal::bytes::BytesMut,
                ctx: &skrillax_serde::SerdeContext,
            ) -> Result<(), skrillax_serde::SerializationError> {
                #output
                Ok(())
            }
        }

        impl TryFrom<#ident> for ::skrillax_serde::__internal::bytes::Bytes {
            type Error = skrillax_serde::SerializationError;

            fn try_from(packet: #ident) -> Result<Self, Self::Error> {
                let mut buffer = ::skrillax_serde::__internal::bytes::BytesMut::with_capacity(packet.byte_size());
                packet.write_to(&mut buffer, &skrillax_serde::SerdeContext::default())?;
                Ok(buffer.freeze())
            }
        }
    })
}

#[proc_macro_derive(Deserialize, attributes(silkroad))]
pub fn derive_deserialize(input: TokenStream) -> TokenStream {
    expand_deserialize(input.into())
        .unwrap_or_else(Diagnostic::emit_as_item_tokens)
        .into()
}

fn expand_deserialize(input: TokenStream2) -> Result<TokenStream2, Diagnostic> {
    let input: DeriveInput = syn::parse2(input)?;
    let model = normalize(&input, DeriveOperation::Deserialize)?;
    let ident = model.ident;
    let output = deserialize(&model)?;

    Ok(quote! {
        impl skrillax_serde::Deserialize for #ident {
            fn read_from<T: std::io::Read + ::skrillax_serde::__internal::byteorder::ReadBytesExt>(mut reader: &mut T, ctx: &skrillax_serde::SerdeContext) -> Result<Self, skrillax_serde::SerializationError> {
                #output
            }
        }

        impl TryFrom<::skrillax_serde::__internal::bytes::Bytes> for #ident {
            type Error = skrillax_serde::SerializationError;

            fn try_from(data: ::skrillax_serde::__internal::bytes::Bytes) -> Result<Self, Self::Error> {
                use ::skrillax_serde::__internal::bytes::Buf;
                let mut data_reader = data.reader();
                #ident::read_from(&mut data_reader, &skrillax_serde::SerdeContext::default())
            }
        }
    })
}

#[proc_macro_derive(ByteSize, attributes(silkroad))]
pub fn derive_size(input: TokenStream) -> TokenStream {
    expand_size(input.into())
        .unwrap_or_else(Diagnostic::emit_as_item_tokens)
        .into()
}

fn expand_size(input: TokenStream2) -> Result<TokenStream2, Diagnostic> {
    let input: DeriveInput = syn::parse2(input)?;
    let model = normalize(&input, DeriveOperation::ByteSize)?;
    let ident = model.ident;
    let output = size(&model)?;

    Ok(quote! {
        impl skrillax_serde::ByteSize for #ident {
            fn byte_size(&self) -> usize {
                #output
            }
        }
    })
}
