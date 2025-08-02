use crate::{get_type_of, get_variant_value, FieldArgs, SilkroadArgs, UsedType, DEFAULT_LIST_TYPE};
use darling::FromAttributes;
use proc_macro2::{Ident, TokenStream};
use proc_macro_error::abort;
use quote::{format_ident, quote, quote_spanned};
use syn::spanned::Spanned;
use syn::{Data, Field, Fields, Index, Variant};

pub(crate) fn serialize(ident: &Ident, data: &Data, args: SilkroadArgs) -> TokenStream {
    match *data {
        Data::Struct(ref data) => match data.fields {
            Fields::Named(ref fields) => {
                let content = fields.named.iter().map(|field| {
                    let ident = field
                        .ident
                        .as_ref()
                        .expect("Field of named struct should have a name");
                    generate_for_field(field, quote!(self.#ident))
                });
                quote_spanned! { ident.span() =>
                    #(#content)*
                }
            },
            Fields::Unnamed(ref fields) => {
                let content = fields.unnamed.iter().enumerate().map(|(i, field)| {
                    let index = Index::from(i);
                    generate_for_field(field, quote!(self.#index))
                });
                quote_spanned! { ident.span() =>
                    #(#content)*
                }
            },
            Fields::Unit => {
                quote!()
            },
        },
        Data::Enum(ref data) => {
            let size = args.size.unwrap_or(1);
            let variant_content = data
                .variants
                .iter()
                .map(|variant| generate_for_variant(ident, variant, size));
            quote_spanned! { ident.span() =>
                match &self {
                    #(#variant_content),*
                }
            }
        },
        _ => abort!(ident, "Unions are not supported."),
    }
}

fn generate_for_field(field: &Field, ident: TokenStream) -> TokenStream {
    let ty = get_type_of(&field.ty);
    let Ok(args) = FieldArgs::from_attributes(&field.attrs) else {
        abort!(field, "Could not parse field attributes.");
    };
    match ty {
        UsedType::Primitive => {
            quote_spanned! {field.span() =>
                #ident.write_to(writer, ctx);
            }
        },
        UsedType::String => {
            let content = match args.size.unwrap_or(1) {
                1 => quote! {
                    for skrillax_serde_byte in #ident.as_bytes() {
                        skrillax_serde_byte.write_to(writer, ctx);
                    }
                },
                2 => quote! {
                    for skrillax_serde_utf_char in #ident.encode_utf16() {
                        skrillax_serde_utf_char.write_to(writer, ctx);
                    }
                },
                _ => abort!(field, "Unknown String length"),
            };
            quote_spanned! {field.span() =>
                (#ident.len() as u16).write_to(writer, ctx);
                #content
            }
        },
        UsedType::Array(_) => {
            quote_spanned! {field.span() =>
                for skrillax_serde_inner in #ident {
                    skrillax_serde_inner.write_to(writer, ctx);
                }
            }
        },
        UsedType::Collection(inner) => {
            let length_type = args.list_type.as_deref().unwrap_or(DEFAULT_LIST_TYPE);
            // TODO: this does not handle double length strings.
            let inner_ty = match get_type_of(inner) {
                UsedType::Primitive => quote!(skrillax_serde_inner.write_to(writer, ctx)),
                UsedType::String => quote! {
                    (skrillax_serde_inner.len() as u16).write_to(writer, ctx);
                    for skrillax_serde_byte in skrillax_serde_inner.as_bytes() {
                        skrillax_serde_byte.write_to(writer, ctx);
                    }
                },
                _ => abort!(field, "Cannot nest collection-like types"),
            };

            let size = args.size.unwrap_or(1);
            if length_type == "break" {
                let continue_lit = get_variant_value(&ident, 1, size);
                let break_lit = get_variant_value(&ident, 2, size);
                quote_spanned! {field.span() =>
                    for skrillax_serde_inner in #ident.iter() {
                        #continue_lit.write_to(writer, ctx);
                        #inner_ty;
                    }
                    #break_lit.write_to(writer, ctx);
                }
            } else if length_type == "has-more" {
                let continue_lit = get_variant_value(&ident, 1, size);
                let break_lit = get_variant_value(&ident, 0, size);
                quote_spanned! {field.span() =>
                    for skrillax_serde_inner in #ident.iter() {
                        #continue_lit.write_to(writer, ctx);
                        #inner_ty;
                    }
                    #break_lit.write_to(writer, ctx);
                }
            } else if length_type == "length" {
                let size_type = match size {
                    1 => quote!(u8),
                    2 => quote!(u16),
                    3 => quote!(u32),
                    4 => quote!(u64),
                    _ => abort!(ident, "Could not determine size for list."),
                };
                quote_spanned! {field.span() =>
                    (#ident.len() as #size_type).write_to(writer, ctx);
                    for skrillax_serde_inner in #ident.iter() {
                        #inner_ty;
                    }
                }
            } else {
                quote_spanned! {field.span() =>
                    for skrillax_serde_inner in #ident.iter() {
                        #inner_ty;
                    }
                }
            }
        },
        UsedType::Option(inner) => {
            // TODO: this does not handle double length strings.
            let inner_ty = match get_type_of(inner) {
                UsedType::Primitive => quote!(skrillax_serde_inner.write_to(writer, ctx)),
                UsedType::String => quote! {
                    (skrillax_serde_inner.len() as u16).write_to(writer, ctx);
                    for skrillax_serde_byte in skrillax_serde_inner.as_bytes() {
                        skrillax_serde_byte.write_to(writer, ctx);
                    }
                },
                _ => abort!(field, "Cannot nest collection-like types"),
            };
            if args.when.is_some() || args.size.unwrap_or(1) == 0 {
                quote_spanned! {field.span() =>
                    match &#ident {
                        Some(skrillax_serde_inner) => {
                            #inner_ty;
                        },
                        None => {},
                    }
                }
            } else {
                quote_spanned! {field.span() =>
                    match &#ident {
                        Some(skrillax_serde_inner) => {
                            1u8.write_to(writer, ctx);
                            #inner_ty;
                        },
                        None => 0u8.write_to(writer, ctx),
                    }
                }
            }
        },
        UsedType::Tuple(items) => {
            let def = (0..items.len())
                .map(|index| format_ident!("t{}", index))
                .collect::<Vec<Ident>>();

            quote_spanned! {field.span() =>
                let (#(#def),*) = &#ident;
                #(#def.write_to(writer, ctx);)*
            }
        },
    }
}

fn generate_for_variant(ident: &Ident, variant: &Variant, size: usize) -> TokenStream {
    let Ok(attributes) = FieldArgs::from_attributes(&variant.attrs) else {
        abort!(variant, "Could not parse variant attributes.");
    };
    let variant_name = &variant.ident;
    let value_output = if size > 0 {
        if attributes.value.is_none() && attributes.when.is_none() {
            abort!(
                variant,
                "When size is not zero, either value or when should be set."
            );
        }

        // For variants with a when attribute, we need to determine the value at runtime
        // For serialization, we'll just use the first field's value as the tag
        if let Some(_) = attributes.when {
            match &variant.fields {
                Fields::Named(fields) if !fields.named.is_empty() => {
                    let relevant_field = fields
                        .named
                        .iter()
                        .map(|field| {
                            (
                                field,
                                FieldArgs::from_attributes(&field.attrs).unwrap_or_default(),
                            )
                        })
                        .find(|(_, args)| args.tag)
                        .map(|(f, _)| f)
                        .unwrap_or(fields.named.first().unwrap());

                    let first_field_ident = relevant_field.ident.as_ref().unwrap();
                    quote_spanned! { variant_name.span() =>
                        #first_field_ident.write_to(writer, ctx);
                    }
                },
                Fields::Unnamed(fields) if !fields.unnamed.is_empty() => {
                    let relevant_field_index = fields
                        .unnamed
                        .iter()
                        .enumerate()
                        .map(|(index, field)| {
                            (
                                index,
                                FieldArgs::from_attributes(&field.attrs).unwrap_or_default(),
                            )
                        })
                        .find(|(_, args)| args.tag)
                        .map(|(f, _)| f)
                        .unwrap_or(0);

                    let first_field_ident = format_ident!("t{relevant_field_index}");

                    quote_spanned! { variant_name.span() =>
                        #first_field_ident.write_to(writer, ctx);
                    }
                },
                _ => {
                    abort!(
                        variant,
                        "When using 'when' attribute, the variant must have at least one field to \
                         use as the tag value."
                    );
                },
            }
        } else {
            let value = attributes.value.unwrap();
            let value = get_variant_value(variant_name, value, size);
            quote_spanned! { variant_name.span() =>
                #value.write_to(writer, ctx);
            }
        }
    } else {
        quote!()
    };
    match &variant.fields {
        Fields::Named(fields) => {
            let idents = fields
                .named
                .iter()
                .map(|field| {
                    field
                        .ident
                        .as_ref()
                        .expect("Field of named struct should have a name")
                })
                .collect::<Vec<&Ident>>();

            let content = fields
                .named
                .iter()
                .zip(&idents)
                .filter(|(f, _)| !FieldArgs::from_attributes(&f.attrs).unwrap_or_default().tag)
                .map(|(field, ident)| generate_for_field(field, quote!(#ident)));

            quote_spanned! {variant_name.span()=>
                #ident::#variant_name { #(#idents),* } => {
                    #value_output
                    #(#content)*
                }
            }
        },
        Fields::Unnamed(fields) => {
            let idents = (0..fields.unnamed.len())
                .map(|i| format_ident!("t{}", i))
                .collect::<Vec<Ident>>();
            let content = fields
                .unnamed
                .iter()
                .zip(&idents)
                .filter(|(f, _)| !FieldArgs::from_attributes(&f.attrs).unwrap_or_default().tag)
                .map(|(field, ident)| generate_for_field(field, quote!(#ident)));

            quote_spanned! {variant_name.span()=>
                #ident::#variant_name(#(#idents),*) => {
                    #value_output
                    #(#content)*
                }
            }
        },
        Fields::Unit => {
            quote_spanned! {variant_name.span()=>
                #ident::#variant_name => {
                    #value_output
                }
            }
        },
    }
}
