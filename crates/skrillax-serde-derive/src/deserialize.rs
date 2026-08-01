use crate::model::{
    DataModel, FieldModel, FieldRole, IntegerWidth, Presence, SequenceFraming, StringEncoding,
    VariantModel, VariantSelector, WireModel, WireType,
};
use proc_macro2::{Ident, Span, TokenStream};
use proc_macro2_diagnostics::{Diagnostic, SpanDiagnosticExt};
use quote::{format_ident, quote, quote_spanned};
use syn::spanned::Spanned;
use syn::{Fields, Type};

pub(crate) fn deserialize(model: &WireModel<'_>) -> Result<TokenStream, Diagnostic> {
    let ident = model.ident;
    match &model.data {
        DataModel::Struct(struct_model) => {
            let names = struct_model
                .fields
                .iter()
                .enumerate()
                .map(|(index, field)| field_name(field, index))
                .collect::<Vec<_>>();
            let content = struct_model
                .fields
                .iter()
                .enumerate()
                .map(|(index, field)| generate_reader_for(field, &names[index]))
                .collect::<Result<Vec<_>, _>>()?;
            match &struct_model.data.fields {
                Fields::Named(_) => Ok(quote_spanned! {model.ident.span() =>
                    #(#content)*
                    Ok(#ident { #(#names),* })
                }),
                Fields::Unnamed(_) => Ok(quote_spanned! {model.ident.span() =>
                    #(#content)*
                    Ok(#ident(#(#names),*))
                }),
                Fields::Unit => Ok(quote_spanned! {model.ident.span() => Ok(#ident)}),
            }
        },
        DataModel::Enum(enum_model) => {
            let arms = enum_model
                .variants
                .iter()
                .map(|variant| generate_variant_reader(model.ident, variant, enum_model.width))
                .collect::<Result<Vec<_>, _>>()?;
            if let Some(width) = enum_model.width {
                let reader = read_integer(width, model.ident, "enum discriminant");
                Ok(quote_spanned! {model.ident.span() =>
                    let tag = #reader;
                    match tag {
                        #(#arms),*,
                        unknown => Err(skrillax_serde::SerializationError::UnknownVariation(unknown as u64, stringify!(#ident))),
                    }
                })
            } else {
                Ok(quote_spanned! {model.ident.span() =>
                    #(#arms)*
                    Err(skrillax_serde::SerializationError::UnknownVariation(0, stringify!(#ident)))
                })
            }
        },
    }
}

fn field_name(field: &FieldModel<'_>, index: usize) -> Ident {
    field
        .field
        .ident
        .clone()
        .unwrap_or_else(|| format_ident!("t{index}"))
}

fn generate_reader_for(field: &FieldModel<'_>, ident: &Ident) -> Result<TokenStream, Diagnostic> {
    let span = field.field.span();
    match &field.role {
        FieldRole::EnumTag => Ok(quote_spanned! {span => let #ident = tag; }),
        FieldRole::Synthetic { expression } => {
            Ok(quote_spanned! {span => let #ident = #expression; })
        },
        FieldRole::Wire => match &field.kind {
            WireType::Delegated(type_name) => Ok(read_delegated(type_name, ident, span)),
            WireType::String => read_string(field, ident),
            WireType::Array { .. } => read_value(&field.kind, ident, span),
            WireType::Collection { element } => read_collection(field, element, ident),
            WireType::Optional { inner } => read_option(field, inner, ident),
            WireType::Tuple(items) => read_tuple(items, ident, span),
        },
    }
}

fn read_delegated(type_name: &Type, ident: &Ident, span: Span) -> TokenStream {
    let name = ident.to_string();
    quote_spanned! {span =>
        let #ident = <#type_name as skrillax_serde::Deserialize>::read_from(reader, ctx)
            .map_err(|e| skrillax_serde::SerializationError::field_io_error(#name, e))?;
    }
}

fn read_string(field: &FieldModel<'_>, ident: &Ident) -> Result<TokenStream, Diagnostic> {
    let span = field.field.span();
    let name = ident.to_string();
    let body = match field.string_encoding.expect("strings have an encoding") {
        StringEncoding::Utf8 => quote! {
            let mut bytes = Vec::with_capacity(length.into());
            for _ in 0..length {
                bytes.push(u8::read_from(reader, ctx)
                    .map_err(|e| skrillax_serde::SerializationError::field_io_error(#name, e))?);
            }
            let #ident = String::from_utf8(bytes)?;
        },
        StringEncoding::Utf16 => quote! {
            let mut units = Vec::with_capacity(length.into());
            for _ in 0..length {
                units.push(u16::read_from(reader, ctx)
                    .map_err(|e| skrillax_serde::SerializationError::field_io_error(#name, e))?);
            }
            let #ident = String::from_utf16(&units)?;
        },
    };
    Ok(quote_spanned! {span =>
        let length = u16::read_from(reader, ctx)
            .map_err(|e| skrillax_serde::SerializationError::field_io_error(#name, e))?;
        #body
    })
}

fn read_collection(
    field: &FieldModel<'_>,
    element: &WireType<'_>,
    ident: &Ident,
) -> Result<TokenStream, Diagnostic> {
    let span = field.field.span();
    let item = format_ident!("{}_item", ident);
    let item_read = read_value(element, &item, span)?;
    let framing = field.framing.as_ref().expect("collections have framing");
    let output = match framing {
        SequenceFraming::Break { marker_width } => {
            let marker = read_integer(*marker_width, ident, "sequence marker");
            quote! {
                let mut items = Vec::new();
                loop {
                    let marker = #marker;
                    if marker == 2 {
                        break;
                    }
                    #item_read
                    items.push(#item);
                }
                let #ident = items;
            }
        },
        SequenceFraming::HasMore { marker_width } => {
            let marker = read_integer(*marker_width, ident, "sequence marker");
            quote! {
                let mut items = Vec::new();
                loop {
                    let marker = #marker;
                    if marker == 0 {
                        break;
                    }
                    #item_read
                    items.push(#item);
                }
                let #ident = items;
            }
        },
        SequenceFraming::Counted { width } => {
            let count = read_integer(*width, ident, "collection length");
            quote! {
                let count = #count;
                let mut items = Vec::with_capacity(count as usize);
                for _ in 0..count {
                    #item_read
                    items.push(#item);
                }
                let #ident = items;
            }
        },
        SequenceFraming::Calculated { expression } => quote! {
            let count = (#expression) as usize;
            let mut items = Vec::with_capacity(count);
            for _ in 0..count {
                #item_read
                items.push(#item);
            }
            let #ident = items;
        },
    };
    Ok(quote_spanned! {span => #output})
}

fn read_option(
    field: &FieldModel<'_>,
    inner: &WireType<'_>,
    ident: &Ident,
) -> Result<TokenStream, Diagnostic> {
    let span = field.field.span();
    let item = format_ident!("{}_inner", ident);
    let inner_read = read_value(inner, &item, span)?;
    let output = match field.presence.as_ref().expect("options have presence") {
        Presence::Conditional { expression } => quote! {
            let #ident = if #expression {
                #inner_read
                Some(#item)
            } else {
                None
            };
        },
        Presence::Bare => quote! {
            let #ident = None;
        },
        Presence::Explicit { width } => {
            let marker = read_integer(*width, ident, "option presence");
            quote! {
                let marker = #marker;
                let #ident = if marker == 1 {
                    #inner_read
                    Some(#item)
                } else {
                    None
                };
            }
        },
    };
    Ok(quote_spanned! {span => #output})
}

fn read_tuple(
    items: &[WireType<'_>],
    ident: &Ident,
    span: Span,
) -> Result<TokenStream, Diagnostic> {
    let bindings = (0..items.len())
        .map(|index| format_ident!("{}_t{index}", ident))
        .collect::<Vec<_>>();
    let content = items
        .iter()
        .zip(&bindings)
        .map(|(kind, binding)| read_value(kind, binding, span))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(quote_spanned! {span =>
        #(#content)*
        let #ident = (#(#bindings),*);
    })
}

fn read_value(kind: &WireType<'_>, ident: &Ident, span: Span) -> Result<TokenStream, Diagnostic> {
    match kind {
        WireType::Delegated(type_name) => Ok(read_delegated(type_name, ident, span)),
        WireType::String => Ok(quote_spanned! {span =>
            let length = u16::read_from(reader, ctx)?;
            let mut bytes = Vec::with_capacity(length.into());
            for _ in 0..length {
                bytes.push(u8::read_from(reader, ctx)?);
            }
            let #ident = String::from_utf8(bytes)?;
        }),
        WireType::Array {
            element_type,
            element,
            length,
        } => {
            let item = format_ident!("{}_item", ident);
            let item_read = read_value(element, &item, span)?;
            Ok(quote_spanned! {span =>
                let mut values = Vec::with_capacity((#length) as usize);
                for _ in 0..#length {
                    #item_read
                    values.push(#item);
                }
                let #ident: [#element_type; #length] = values.try_into()
                    .expect("normalized array length must match its type");
            })
        },
        WireType::Collection { .. } | WireType::Optional { .. } => Err(span.error(
            "Nested collections and options require a wrapper struct with explicit framing.",
        )),
        WireType::Tuple(_) => Err(span.error("Nested tuple values are not supported.")),
    }
}

fn generate_variant_reader(
    enum_ident: &Ident,
    variant: &VariantModel<'_>,
    width: Option<IntegerWidth>,
) -> Result<TokenStream, Diagnostic> {
    let name = &variant.variant.ident;
    let bindings = match &variant.variant.fields {
        Fields::Named(fields) => fields
            .named
            .iter()
            .filter_map(|field| field.ident.clone())
            .collect::<Vec<_>>(),
        Fields::Unnamed(fields) => (0..fields.unnamed.len())
            .map(|index| format_ident!("t{index}"))
            .collect::<Vec<_>>(),
        Fields::Unit => Vec::new(),
    };
    let content = variant
        .fields
        .iter()
        .enumerate()
        .map(|(index, field)| generate_reader_for(field, &bindings[index]))
        .collect::<Result<Vec<_>, _>>()?;
    let result = match &variant.variant.fields {
        Fields::Named(_) => quote!(Ok(#enum_ident::#name { #(#bindings),* })),
        Fields::Unnamed(_) => quote!(Ok(#enum_ident::#name(#(#bindings),*))),
        Fields::Unit => quote!(Ok(#enum_ident::#name)),
    };
    let body = quote! { #(#content)* #result };

    match &variant.selector {
        VariantSelector::Fixed(value) => {
            let width = width.expect("fixed selector has width");
            let value = width_literal(width, *value);
            Ok(quote_spanned! {name.span() => #value => { #body }})
        },
        VariantSelector::Predicate(expression) => {
            if width.is_some() {
                Ok(quote_spanned! {name.span() => tag if #expression => { #body }})
            } else {
                Ok(quote_spanned! {name.span() =>
                    if #expression {
                        #(#content)*
                        return #result;
                    }
                })
            }
        },
    }
}

fn read_integer(width: IntegerWidth, ident: &Ident, _kind: &str) -> TokenStream {
    let rust_type = syn::Ident::new(width.rust_type(), ident.span());
    let name = ident.to_string();
    quote!(<#rust_type as skrillax_serde::Deserialize>::read_from(reader, ctx)
        .map_err(|e| skrillax_serde::SerializationError::field_io_error(#name, e))?)
}

fn width_literal(width: IntegerWidth, value: u64) -> TokenStream {
    let literal = syn::LitInt::new(
        &format!("{value}{}", width.rust_type()),
        proc_macro2::Span::call_site(),
    );
    quote!(#literal)
}
