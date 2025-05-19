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

use crate::deserialize::deserialize;
use crate::serialize::serialize;
use crate::size::size;
use darling::{FromAttributes, FromDeriveInput};
use proc_macro::TokenStream;
use proc_macro_error::{abort, proc_macro_error};
use quote::{quote, ToTokens};
use syn::spanned::Spanned;
use syn::{parse_macro_input, DeriveInput, Expr, GenericArgument, PathArguments, Type};

mod deserialize;
mod serialize;
mod size;

pub(crate) const DEFAULT_LIST_TYPE: &str = "length";

#[derive(FromAttributes)]
#[darling(attributes(silkroad))]
pub(crate) struct FieldArgs {
    list_type: Option<String>,
    size: Option<usize>,
    value: Option<usize>,
    when: Option<String>,
}

#[derive(FromDeriveInput)]
#[darling(attributes(silkroad))]
pub(crate) struct SilkroadArgs {
    size: Option<usize>,
}

#[proc_macro_error]
#[proc_macro_derive(Serialize, attributes(silkroad))]
pub fn derive_serialize(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input);
    let args = SilkroadArgs::from_derive_input(&input).unwrap();
    let DeriveInput { ident, data, .. } = input;

    let output = serialize(&ident, &data, args);

    let output = quote! {
        impl skrillax_serde::Serialize for #ident {
            fn write_to(&self, mut writer: &mut ::skrillax_serde::__internal::bytes::BytesMut) {
                #output
            }
        }

        impl From<#ident> for ::skrillax_serde::__internal::bytes::Bytes {
            fn from(packet: #ident) -> ::skrillax_serde::__internal::bytes::Bytes {
                let mut buffer = ::skrillax_serde::__internal::bytes::BytesMut::with_capacity(packet.byte_size());
                packet.write_to(&mut buffer);
                buffer.freeze()
            }
        }
    };
    output.into()
}

#[proc_macro_error]
#[proc_macro_derive(Deserialize, attributes(silkroad))]
pub fn derive_deserialize(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input);
    let args = SilkroadArgs::from_derive_input(&input).unwrap();
    let DeriveInput { ident, data, .. } = input;
    let output = deserialize(&ident, &data, args);
    let output = quote! {
        impl skrillax_serde::Deserialize for #ident {
            fn read_from<T: std::io::Read + ::skrillax_serde::__internal::byteorder::ReadBytesExt>(mut reader: &mut T) -> Result<Self, skrillax_serde::SerializationError> {
                #output
            }
        }

        impl TryFrom<::skrillax_serde::__internal::bytes::Bytes> for #ident {
            type Error = skrillax_serde::SerializationError;

            fn try_from(data: ::skrillax_serde::__internal::bytes::Bytes) -> Result<Self, Self::Error> {
                use ::skrillax_serde::__internal::bytes::Buf;
                let mut data_reader = data.reader();
                #ident::read_from(&mut data_reader)
            }
        }
    };
    output.into()
}

#[proc_macro_error]
#[proc_macro_derive(ByteSize, attributes(silkroad))]
pub fn derive_size(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input);
    let args = SilkroadArgs::from_derive_input(&input).unwrap();
    let DeriveInput { ident, data, .. } = input;
    let output = size(&ident, &data, args);
    let output = quote! {
        impl skrillax_serde::ByteSize for #ident {
            fn byte_size(&self) -> usize {
                #output
            }
        }
    };
    output.into()
}

#[derive(Debug)]
pub(crate) enum UsedType<'a> {
    Primitive,
    String,
    Array(&'a Expr),
    Collection(&'a Type),
    Option(&'a Type),
    Tuple(Vec<&'a Type>),
}

pub(crate) fn get_type_of(ty: &Type) -> UsedType {
    match ty {
        Type::Array(arr) => UsedType::Array(&arr.len),
        Type::Reference(_) => abort!(ty, "References are not supported for (de)serialization."),
        Type::Tuple(tuple) => UsedType::Tuple(tuple.elems.iter().collect()),
        Type::Path(path) => {
            let full_name = path
                .path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect::<Vec<String>>()
                .join("::");

            if full_name == "String"
                || full_name == "string::String"
                || full_name == "std::string::String"
            {
                return UsedType::String;
            } else if full_name == "Vec" {
                match path.path.segments.last().unwrap().arguments {
                    PathArguments::None => {
                        abort!(ty, "Missing generic parameters for collection type.")
                    },
                    PathArguments::Parenthesized(_) => {
                        abort!(ty, "Cannot use parenthesized types.")
                    },
                    PathArguments::AngleBracketed(ref args) => {
                        let ty = args
                            .args
                            .iter()
                            .find_map(|arg| match arg {
                                GenericArgument::Type(ty) => Some(ty),
                                _ => None,
                            })
                            .unwrap();
                        return UsedType::Collection(ty);
                    },
                }
            } else if full_name == "Option" {
                match path.path.segments.last().unwrap().arguments {
                    PathArguments::None => {
                        abort!(ty, "Missing generic parameters for option type.")
                    },
                    PathArguments::Parenthesized(_) => {
                        abort!(ty, "Cannot use parenthesized types.")
                    },
                    PathArguments::AngleBracketed(ref args) => {
                        let ty = args
                            .args
                            .iter()
                            .find_map(|arg| match arg {
                                GenericArgument::Type(ty) => Some(ty),
                                _ => None,
                            })
                            .unwrap();
                        return UsedType::Option(ty);
                    },
                }
            }

            UsedType::Primitive
        },
        _ => abort!(ty, "Encountered unknown syn type."),
    }
}

fn get_variant_value<T: Spanned + ToTokens>(source: &T, value: usize, size: usize) -> Expr {
    let ty = match size {
        1 => "u8",
        2 => "u16",
        4 => "u32",
        8 => "u64",
        _ => abort!(source, "Unknown size"),
    };
    syn::parse_str(&format!("{}{}", value, ty)).unwrap()
}
