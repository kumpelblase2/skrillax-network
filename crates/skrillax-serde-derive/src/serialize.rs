use crate::model::{
    DataModel, FieldModel, FieldRole, IntegerWidth, Presence, SequenceFraming, VariantModel,
    VariantSelector, WireModel, WireType,
};
use proc_macro2::{Ident, TokenStream};
use proc_macro2_diagnostics::{Diagnostic, SpanDiagnosticExt};
use quote::{format_ident, quote, quote_spanned};
use syn::spanned::Spanned;
use syn::{Fields, Index};

pub(crate) fn serialize(model: &WireModel<'_>) -> Result<TokenStream, Diagnostic> {
    match &model.data {
        DataModel::Struct(struct_model) => {
            let content = struct_model
                .fields
                .iter()
                .enumerate()
                .map(|(index, field)| {
                    let access = field_access(field, index);
                    generate_for_field(field, access)
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(quote_spanned! { model.ident.span() => #(#content)* })
        },
        DataModel::Enum(enum_model) => {
            let content = enum_model
                .variants
                .iter()
                .map(|variant| generate_for_variant(model.ident, variant, enum_model.width))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(quote_spanned! { model.ident.span() => match &self { #(#content),* } })
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

fn binding(index: usize) -> Ident {
    format_ident!("t{index}")
}

fn generate_for_field(
    field: &FieldModel<'_>,
    ident: TokenStream,
) -> Result<TokenStream, Diagnostic> {
    if !matches!(field.role, FieldRole::Wire) {
        return Ok(quote!());
    }

    match &field.kind {
        WireType::Delegated(_) => Ok(quote_spanned! {field.field.span() =>
            #ident.write_to(writer, ctx)?;
        }),
        WireType::String => {
            let content = match field.string_encoding.expect("strings have an encoding") {
                crate::model::StringEncoding::Utf8 => quote! {
                    for byte in #ident.as_bytes() {
                        byte.write_to(writer, ctx)?;
                    }
                },
                crate::model::StringEncoding::Utf16 => quote! {
                    for unit in #ident.encode_utf16() {
                        unit.write_to(writer, ctx)?;
                    }
                },
            };
            Ok(quote_spanned! {field.field.span() =>
                (#ident.len() as u16).write_to(writer, ctx)?;
                #content
            })
        },
        WireType::Array { .. } => generate_value(&field.kind, ident, field.field.span()),
        WireType::Collection { element } => {
            let inner = quote!(skrillax_serde_inner);
            let body = generate_value(element, inner, field.field.span())?;
            let framing = field.framing.as_ref().expect("collections have framing");
            let framing_output = match framing {
                SequenceFraming::Break { marker_width } => {
                    let continue_value = width_literal(*marker_width, 1);
                    let end_value = width_literal(*marker_width, 2);
                    quote! {
                        for skrillax_serde_inner in #ident.iter() {
                            #continue_value.write_to(writer, ctx)?;
                            #body
                        }
                        #end_value.write_to(writer, ctx)?;
                    }
                },
                SequenceFraming::HasMore { marker_width } => {
                    let continue_value = width_literal(*marker_width, 1);
                    let end_value = width_literal(*marker_width, 0);
                    quote! {
                        for skrillax_serde_inner in #ident.iter() {
                            #continue_value.write_to(writer, ctx)?;
                            #body
                        }
                        #end_value.write_to(writer, ctx)?;
                    }
                },
                SequenceFraming::Counted { width } => {
                    let rust_type = syn::Ident::new(width.rust_type(), field.field.span());
                    quote! {
                        (#ident.len() as #rust_type).write_to(writer, ctx)?;
                        for skrillax_serde_inner in #ident.iter() {
                            #body
                        }
                    }
                },
                SequenceFraming::Calculated { .. } => quote! {
                    for skrillax_serde_inner in #ident.iter() {
                        #body
                    }
                },
            };
            Ok(quote_spanned! {field.field.span() => #framing_output })
        },
        WireType::Optional { inner } => {
            let inner_body =
                generate_value(inner, quote!(skrillax_serde_inner), field.field.span())?;
            let presence = field.presence.as_ref().expect("options have presence");
            let output = match presence {
                Presence::Explicit { width } => {
                    let some = width_literal(*width, 1);
                    let none = width_literal(*width, 0);
                    quote! {
                        match &#ident {
                            Some(skrillax_serde_inner) => {
                                #some.write_to(writer, ctx)?;
                                #inner_body
                            },
                            None => #none.write_to(writer, ctx)?,
                        }
                    }
                },
                Presence::Conditional { .. } | Presence::Bare => quote! {
                    if let Some(skrillax_serde_inner) = &#ident {
                        #inner_body
                    }
                },
            };
            Ok(quote_spanned! {field.field.span() => #output })
        },
        WireType::Tuple(items) => {
            let defs = (0..items.len()).map(binding).collect::<Vec<_>>();
            let content = items
                .iter()
                .zip(&defs)
                .map(|(kind, ident)| generate_value(kind, quote!(#ident), field.field.span()))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(quote_spanned! {field.field.span() =>
                let (#(#defs),*) = &#ident;
                #(#content)*
            })
        },
    }
}

fn generate_value(
    kind: &WireType<'_>,
    ident: TokenStream,
    span: proc_macro2::Span,
) -> Result<TokenStream, Diagnostic> {
    match kind {
        WireType::Delegated(_) => Ok(quote_spanned! {span => #ident.write_to(writer, ctx)?; }),
        WireType::String => Ok(quote_spanned! {span =>
            (#ident.len() as u16).write_to(writer, ctx)?;
            for byte in #ident.as_bytes() {
                byte.write_to(writer, ctx)?;
            }
        }),
        WireType::Array { .. } => Ok(quote_spanned! {span =>
            for element in #ident {
                element.write_to(writer, ctx)?;
            }
        }),
        WireType::Collection { .. } | WireType::Optional { .. } => Err(span.error(
            "Nested collections and options require a wrapper struct with explicit framing.",
        )),
        WireType::Tuple(_) => Err(span.error(
            "Tuple elements cannot directly contain tuple values; use a wrapper struct instead.",
        )),
    }
}

fn generate_for_variant(
    ident: &Ident,
    variant: &VariantModel<'_>,
    width: Option<IntegerWidth>,
) -> Result<TokenStream, Diagnostic> {
    let variant_name = &variant.variant.ident;
    let source_fields = match &variant.variant.fields {
        Fields::Named(fields) => fields
            .named
            .iter()
            .filter_map(|field| field.ident.as_ref())
            .cloned()
            .collect::<Vec<_>>(),
        Fields::Unnamed(fields) => (0..fields.unnamed.len()).map(binding).collect::<Vec<_>>(),
        Fields::Unit => Vec::new(),
    };
    let fields = source_fields
        .iter()
        .enumerate()
        .map(|(index, field)| {
            if matches!(variant.fields[index].role, FieldRole::EnumTag) {
                format_ident!("_{field}")
            } else {
                field.clone()
            }
        })
        .collect::<Vec<_>>();
    let named_patterns = source_fields
        .iter()
        .zip(&fields)
        .enumerate()
        .map(|(index, (source, binding))| {
            if matches!(variant.fields[index].role, FieldRole::EnumTag) {
                quote!(#source: #binding)
            } else {
                quote!(#source)
            }
        })
        .collect::<Vec<_>>();

    let selector = match &variant.selector {
        VariantSelector::Fixed(value) => {
            let width = width.ok_or_else(|| {
                variant
                    .variant
                    .span()
                    .error("Fixed selector on a zero-width enum.")
            })?;
            let literal = width_literal(width, *value);
            quote_spanned! {variant_name.span() => #literal.write_to(writer, ctx)?;}
        },
        VariantSelector::Predicate(_) if width.is_none() => quote!(),
        VariantSelector::Predicate(_) => {
            let index = variant.tag_index.ok_or_else(|| {
                variant
                    .variant
                    .span()
                    .error("Predicate-tagged variants require a tag field.")
            })?;
            let tag = fields[index].clone();
            quote_spanned! {variant_name.span() => #tag.write_to(writer, ctx)?;}
        },
    };

    let body = variant
        .fields
        .iter()
        .enumerate()
        .filter(|(_, field)| matches!(field.role, FieldRole::Wire))
        .map(|(index, field)| {
            let access = fields[index].clone();
            generate_for_field(field, quote!(#access))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let selector_and_body = quote! { #selector #(#body)* };
    match &variant.variant.fields {
        Fields::Named(_) => Ok(quote_spanned! {variant_name.span() =>
            #ident::#variant_name { #(#named_patterns),* } => { #selector_and_body }
        }),
        Fields::Unnamed(_) => Ok(quote_spanned! {variant_name.span() =>
            #ident::#variant_name(#(#fields),*) => { #selector_and_body }
        }),
        Fields::Unit => Ok(quote_spanned! {variant_name.span() =>
            #ident::#variant_name => { #selector_and_body }
        }),
    }
}

fn width_literal(width: IntegerWidth, value: u64) -> TokenStream {
    let suffix = width.rust_type();
    let literal = syn::LitInt::new(&format!("{value}{suffix}"), proc_macro2::Span::call_site());
    quote!(#literal)
}
