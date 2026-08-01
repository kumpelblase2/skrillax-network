use crate::model::{
    DataModel, FieldModel, FieldRole, Presence, SequenceFraming, StringEncoding, VariantModel,
    WireModel, WireType,
};
use proc_macro2::{Ident, TokenStream};
use proc_macro2_diagnostics::{Diagnostic, SpanDiagnosticExt};
use quote::{format_ident, quote, quote_spanned};
use syn::spanned::Spanned;
use syn::{Fields, Index};

pub(crate) fn size(model: &WireModel<'_>) -> Result<TokenStream, Diagnostic> {
    match &model.data {
        DataModel::Struct(struct_model) => {
            let terms = struct_model
                .fields
                .iter()
                .enumerate()
                .map(|(index, field)| generate_size_for(field, field_access(field, index)))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(sum(terms))
        },
        DataModel::Enum(enum_model) => {
            let arms = enum_model
                .variants
                .iter()
                .map(|variant| generate_variant_size(model.ident, variant))
                .collect::<Result<Vec<_>, _>>()?;
            let discriminant: usize = enum_model.width.map_or(0, |width| width.bytes());
            Ok(quote_spanned! {model.ident.span() =>
                #discriminant + match &self { #(#arms),* }
            })
        },
    }
}

fn field_access(field: &FieldModel<'_>, index: usize) -> TokenStream {
    match &field.field.ident {
        Some(ident) => quote!(self.#ident),
        None => {
            let index = Index::from(index);
            quote!(self.#index)
        },
    }
}

fn generate_size_for(
    field: &FieldModel<'_>,
    ident: TokenStream,
) -> Result<TokenStream, Diagnostic> {
    if !matches!(field.role, FieldRole::Wire) {
        return Ok(quote!(0));
    }

    match &field.kind {
        WireType::Delegated(_) => Ok(quote_spanned!(field.field.span() => #ident.byte_size())),
        WireType::String => {
            let multiplier: usize = match field.string_encoding.expect("strings have an encoding") {
                StringEncoding::Utf8 => 1,
                StringEncoding::Utf16 => 2,
            };
            Ok(quote_spanned! {field.field.span() => 2 + #ident.len() * #multiplier})
        },
        WireType::Array { .. } => generate_size_value(&field.kind, ident, field.field.span()),
        WireType::Collection { element } => {
            let inner = generate_size_value(element, quote!(elem), field.field.span())?;
            let body = quote!(#ident.iter().map(|elem| #inner).sum::<usize>());
            let prefix = match field.framing.as_ref().expect("collections have framing") {
                SequenceFraming::Counted { width } => {
                    let bytes = width.bytes();
                    quote!(#bytes)
                },
                SequenceFraming::Break { marker_width }
                | SequenceFraming::HasMore { marker_width } => {
                    let width = marker_width.bytes();
                    quote!((#ident.len() + 1) * #width)
                },
                SequenceFraming::Calculated { .. } => quote!(0usize),
            };
            Ok(quote_spanned! {field.field.span() => #prefix + #body})
        },
        WireType::Optional { inner } => {
            let inner_size = generate_size_value(inner, quote!(elem), field.field.span())?;
            let marker = match field.presence.as_ref().expect("options have presence") {
                Presence::Explicit { width } => width.bytes(),
                Presence::Conditional { .. } | Presence::Bare => 0,
            };
            Ok(quote_spanned! {field.field.span() =>
                #marker + #ident.as_ref().map(|elem| #inner_size).unwrap_or(0)
            })
        },
        WireType::Tuple(items) => {
            let terms = items
                .iter()
                .enumerate()
                .map(|(index, kind)| {
                    let index = Index::from(index);
                    generate_size_value(kind, quote!(#ident.#index), field.field.span())
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(sum(terms))
        },
    }
}

fn generate_size_value(
    kind: &WireType<'_>,
    ident: TokenStream,
    span: proc_macro2::Span,
) -> Result<TokenStream, Diagnostic> {
    match kind {
        WireType::Delegated(_) => Ok(quote!(#ident.byte_size())),
        WireType::String => Ok(quote!(2 + #ident.len())),
        WireType::Array { .. } => Ok(quote!(#ident.iter().map(ByteSize::byte_size).sum::<usize>())),
        WireType::Collection { .. } | WireType::Optional { .. } => Err(span.error(
            "Nested collections and options require a wrapper struct with explicit framing.",
        )),
        WireType::Tuple(_) => Err(span.error("Nested tuple values are not supported.")),
    }
}

fn generate_variant_size(
    ident: &Ident,
    variant: &VariantModel<'_>,
) -> Result<TokenStream, Diagnostic> {
    let bindings = match &variant.variant.fields {
        Fields::Named(fields) => fields
            .named
            .iter()
            .filter_map(|field| field.ident.as_ref())
            .cloned()
            .collect::<Vec<_>>(),
        Fields::Unnamed(fields) => (0..fields.unnamed.len())
            .map(|index| format_ident!("t{index}"))
            .collect::<Vec<_>>(),
        Fields::Unit => Vec::new(),
    };
    let patterns = match &variant.variant.fields {
        Fields::Named(fields) => fields
            .named
            .iter()
            .zip(&bindings)
            .enumerate()
            .map(|(index, (field, binding))| {
                let source = field.ident.as_ref().expect("named field has an ident");
                if matches!(variant.fields[index].role, FieldRole::EnumTag) {
                    let binding = format_ident!("_{binding}");
                    quote!(#source: #binding)
                } else {
                    quote!(#source)
                }
            })
            .collect::<Vec<_>>(),
        Fields::Unnamed(_) => bindings
            .iter()
            .enumerate()
            .map(|(index, binding)| {
                if matches!(variant.fields[index].role, FieldRole::EnumTag) {
                    let binding = format_ident!("_{binding}");
                    quote!(#binding)
                } else {
                    quote!(#binding)
                }
            })
            .collect(),
        Fields::Unit => Vec::new(),
    };
    let terms = variant
        .fields
        .iter()
        .enumerate()
        .map(|(index, field)| {
            if !matches!(field.role, FieldRole::Wire) {
                Ok(quote!(0))
            } else {
                let binding = &bindings[index];
                generate_size_for(field, quote!(#binding))
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    let body = sum(terms);

    let name = &variant.variant.ident;
    match &variant.variant.fields {
        Fields::Named(_) => Ok(quote_spanned! {name.span() =>
            #ident::#name { #(#patterns),* } => #body
        }),
        Fields::Unnamed(_) => Ok(quote_spanned! {name.span() =>
            #ident::#name(#(#patterns),*) => #body
        }),
        Fields::Unit => Ok(quote_spanned! {name.span() =>
            #ident::#name => #body
        }),
    }
}

fn sum(terms: Vec<TokenStream>) -> TokenStream {
    if terms.is_empty() {
        quote!(0usize)
    } else {
        quote!(#(#terms)+*)
    }
}
