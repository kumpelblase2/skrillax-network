//! Generally it should be enough to simply `#[derive(Deserialize)]` or
//! whichever trait you need. Just like the more general `serde` crate, this
//! will handle most common things, like fields of different types, including
//! references to other structures. However, there are a few things to
//! keep in mind. Silkroad Online packets are not self-specifying, and thus we
//! often need to provide just a little bit of help to serialize/deserialize
//! some kinds of data. In general, you can provide additional options through
//! the `#[silkroad]` tag. Which options are available for which elements will
//! be explained in the following section.
//!
//! ## Enums
//!
//! Enums are generally serialized as one byte discriminant, followed by the
//! content of that variant without further details. Currently, we don't
//! automatically map the index of the enum variant to the discriminant. As
//! such, you need to define a value manually. This can be done using
//! `#[silkroad(value = 1)]` to set the variants byte value to `1`:
//! ```ignore
//! #[derive(Serialize, Deserialize)]
//! enum Hello {
//!     #[silkroad(value = 1)]
//!     ClientHello(String),
//!     #[silkroad(value = 2)]
//!     ServerHello(String),
//! }
//! ```
//! In some cases it may be necessary for the discriminant to be two bytes wide,
//! which you can specify using `#[silkroad(size = 2)]` on the enum itself:
//! ```ignore
//! #[derive(Serialize, Deserialize)]
//! #[silkroad(size = 2)]
//! enum Hello {
//!     #[silkroad(value = 0x400D)]
//!     ClientHello(String),
//! }
//! ```
//!
//! ## Structs
//!
//! Structs are always serialized/deserialized by serializing/deserializing
//! their fields. A unit struct therefor has length zero. There are also no
//! options currently to alter the behavior for structs themselves, only their
//! fields.
//!
//! ```ignore
//! #[derive(Serialize, Deserialize)]
//! struct Hello(String);
//! ```
//!
//! ## Fields
//!
//! The serialization/deserialization of fields is identical between structs and
//! enums. Each field is serialized one after another without any separators.
//! Therefor, it is necessary to match the size exactly to the consumed bytes.
//! Fields are serialized and deserialized in the order they are defined.
//!
//! ```ignore
//! #[derive(Serialize, Deserialize)]
//! struct Hello {
//!     one_byte: u8,
//!     two_bytes: u16,
//! }
//! ```
//!
//! ## Collections
//!
//! Collections (i.e. vectors) are encoded using one byte length followed by the
//! elements of the collection without a separator. If the size is larger, this
//! needs to be denoted using the `#[silkroad(size = 2)]` attribute.
//! ```ignore
//! #[derive(Serialize, Deserialize)]
//! struct Hello {
//!     #[silkroad(size = 2)]
//!     greetings: Vec<String>,
//! }
//! ```
//! The default size is 1 with a size of up to 4 being supported.
//! Additionally, you may change the type of encoding for a collection using the
//! `list_type` attribute. This accepts one of three options: `length`
//! (default), `break`, and `has-more`. `break` and `has-more` specify before
//! each element if another element will follow using different values. `break`
//! uses `1` for 'has more values' and `2` for finished, while `has-more`
//! uses `1` for more elements and `0` for being finished.
//! ```ignore
//! #[derive(Serialize, Deserialize)]
//! struct Hello {
//!     #[silkroad(list_type = "break")]
//!     greetings: Vec<String>,
//! }
//! ```
//!
//! ## Strings
//!
//! Generally a string is encoded using two bytes length and then the UTF-8
//! representation of that string. In some cases, Silkroad however uses two byte
//! wide characters (UTF-16) in strings. This can be configured by using a
//! `size` of 2.
//! ```ignore
//! #[derive(Serialize, Deserialize)]
//! struct Hello {
//!     #[silkroad(size = 2)]
//!     greeting: String,
//! }
//! ```
//!
//! ## Optional
//!
//! Optional values will be encoded using a byte denoting the presence (1) or
//! absence (0), following the underlying value if it is present. In some cases,
//! due to previous knowledge, optional values may just appear (or be missing)
//! without the presence indicator. This makes them impossible to deserialize
//! (currently), but this is unfortunately current necessary. To achieve this,
//! you can set the size of the field to 0.
//! ```ignore
//! #[derive(Serialize)]
//! struct Hello {
//!     #[silkroad(size = 0)]
//!     greeting: Option<String>,
//! }
//! ```
//!
//! Alternatively, if there is an indication in the data whether the value will
//! be present or not, you can use the `when` attribute to specify a condition.
//! In that case the presence byte will be omitted as well, but makes it
//! possible to be deserialized. This does not make any checks for serialization
//! and will always append a present value, ignoring the condition. The
//! condition in `when` should denote an expression which returns a boolean,
//! showing if the values is present in the packet or not. It is possible to
//! access any previous values, but is currently limited to expressions without
//! imports.
//! ```ignore
//! #[derive(Deserialize, Serialize)]
//! struct Hello {
//!     condition: u8
//!     #[silkroad(when = "condition == 1")]
//!     greeting: Option<String>
//! }
//! ```
//!
//! ## Conditional Tag Evaluation for Enums
//!
//! For enums, you can use the `when` attribute to conditionally evaluate which
//! variant to use based on the tag value. The tag value is available as `tag`
//! in the condition expression.
//!
//! ```ignore
//! #[derive(Serialize, ByteSize, Deserialize)]
//! #[silkroad(size = 2)]
//! enum TaggedEnum {
//!     #[silkroad(when = "tag < 100")]
//!     A {
//!         #[silkroad(tag)]
//!         value: u16,
//!     },
//!     #[silkroad(when = "tag >= 100")]
//!     B {
//!         #[silkroad(tag)]
//!         value: u16,
//!     },
//! }
//! ```
//!
//! When deserializing, the tag value is read first, and then the condition is
//! evaluated to determine which variant to use. The tag value is also available
//! for use in the variant's fields, so you can use it to fill in the value of
//! the variant.

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
