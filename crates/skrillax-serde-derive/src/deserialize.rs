use crate::{get_type_of, get_variant_value, FieldArgs, SilkroadArgs, UsedType};
use darling::FromAttributes;
use proc_macro2::{Ident, TokenStream};
use proc_macro_error::abort;
use quote::{format_ident, quote, quote_spanned};
use syn::spanned::Spanned;
use syn::{Data, Expr, Field, Fields, Type};

pub(crate) fn deserialize(ident: &Ident, data: &Data, args: SilkroadArgs) -> TokenStream {
    match *data {
        Data::Struct(ref struct_data) => match &struct_data.fields {
            Fields::Named(named) => {
                let idents = named
                    .named
                    .iter()
                    .map(|field| {
                        field
                            .ident
                            .as_ref()
                            .expect("Field of named struct should have a name")
                    })
                    .collect::<Vec<&Ident>>();
                let content = named.named.iter().map(|field| {
                    generate_reader_for(
                        field,
                        field
                            .ident
                            .as_ref()
                            .expect("Field of named struct should have a name"),
                    )
                });
                quote_spanned! {ident.span()=>
                    #(#content)*
                    Ok(#ident { #(#idents),* })
                }
            },
            Fields::Unnamed(unnamed) => {
                let idents = (0..unnamed.unnamed.len())
                    .map(|i| format_ident!("t{}", i))
                    .collect::<Vec<Ident>>();
                let content = unnamed
                    .unnamed
                    .iter()
                    .zip(&idents)
                    .map(|(field, ident)| generate_reader_for(field, ident));
                quote_spanned! { ident.span() =>
                    #(#content)*
                    Ok(#ident(#(#idents),*))
                }
            },
            Fields::Unit => {
                quote_spanned! { ident.span() =>
                    Ok(#ident)
                }
            },
        },
        Data::Enum(ref enum_data) => {
            let enum_size = args.size.unwrap_or(1);
            let arms = enum_data.variants.iter().map(|variant| {
                let field_args = FieldArgs::from_attributes(&variant.attrs).unwrap();
                let value = get_variant_value(
                    &variant.ident,
                    field_args.value.expect("Missing value for variant."),
                    enum_size,
                );
                let variant_ident = &variant.ident;

                match &variant.fields {
                    Fields::Named(named) => {
                        let idents = named
                            .named
                            .iter()
                            .map(|field| field.ident.as_ref().unwrap())
                            .collect::<Vec<&Ident>>();
                        let content = named
                            .named
                            .iter()
                            .map(|field| generate_reader_for(field, field.ident.as_ref().unwrap()));
                        quote_spanned! { variant_ident.span() =>
                            #value => {
                                #(#content)*
                                Ok(#ident::#variant_ident { #(#idents),* })
                            }
                        }
                    },
                    Fields::Unnamed(unnamed) => {
                        let idents = (0..unnamed.unnamed.len())
                            .map(|i| format_ident!("t{}", i))
                            .collect::<Vec<Ident>>();
                        let content = unnamed
                            .unnamed
                            .iter()
                            .zip(&idents)
                            .map(|(field, ident)| generate_reader_for(field, ident));
                        quote_spanned! { variant_ident.span() =>
                            #value => {
                                #(#content)*
                                Ok(#ident::#variant_ident(#(#idents),*))
                            }
                        }
                    },
                    Fields::Unit => {
                        quote_spanned! { variant_ident.span() =>
                            #value => Ok(#ident::#variant_ident)
                        }
                    },
                }
            });

            let variant_string = format!("{}", ident);
            let size = args.size.unwrap_or(1);
            let reader = match size {
                1 => quote_spanned!(ident.span() => u8::read_from(reader)?),
                2 => quote_spanned!(ident.span() => u16::read_from(reader)?),
                4 => quote_spanned!(ident.span() => u32::read_from(reader)?),
                8 => quote_spanned!(ident.span() => u64::read_from(reader)?),
                _ => abort!(ident, "Invalid size"),
            };
            quote_spanned! { ident.span() =>
                match #reader {
                    #(#arms),*,
                    unknown => Err(skrillax_serde::SerializationError::UnknownVariation(unknown as usize, #variant_string)),
                }
            }
        },
        _ => abort!(ident, "Unions are not supported."),
    }
}

fn generate_reader_for(field: &Field, ident: &Ident) -> TokenStream {
    let ty = get_type_of(&field.ty);
    let type_name = &field.ty;
    let Ok(args) = FieldArgs::from_attributes(&field.attrs) else {
        abort!(field, "Could not parse attrs for field.");
    };
    match ty {
        UsedType::Primitive => {
            quote_spanned! { field.span() =>
                let #ident = #type_name::read_from(reader)?;
            }
        },
        UsedType::String => {
            let content = match args.size.unwrap_or(1) {
                1 => quote! {
                    for _ in 0..skrillax_serde_len {
                        skrillax_serde_bytes.push(u8::read_from(reader)?);
                    }
                    let #ident = String::from_utf8(skrillax_serde_bytes)?;
                },
                2 => quote! {
                    for _ in 0..skrillax_serde_len {
                        skrillax_serde_bytes.push(u16::read_from(reader)?);
                    }
                    let #ident = String::from_utf16(&skrillax_serde_bytes)?;
                },
                _ => abort!(field, "Unknown String size"),
            };

            quote_spanned! { field.span() =>
                let skrillax_serde_len = u16::read_from(reader)?;
                let mut skrillax_serde_bytes = Vec::with_capacity(skrillax_serde_len.into());
                #content
            }
        },
        UsedType::Array(len) => {
            quote_spanned! { field.span() =>
                let mut skrillax_serde_bytes = [0u8; #len];
                reader.read_exact(&mut skrillax_serde_bytes)?;
                let #ident = skrillax_serde_bytes;
            }
        },
        UsedType::Collection(inner) => {
            let inner_ty = get_type_of(inner);
            let inner = generate_reader_for_inner(ident, inner, &inner_ty);
            let list_type = args.list_type.as_deref().unwrap_or("length");
            match list_type {
                "has-more" | "break" => {
                    let break_value = if list_type == "has-more" { 0u8 } else { 2u8 };
                    quote_spanned! { field.span() =>
                        let mut skrillax_serde_items = Vec::new();
                        loop {
                            let skrillax_serde_more = u8::read_from(reader)?;
                            if skrillax_serde_more == #break_value {
                                break;
                            }

                            #inner
                            skrillax_serde_items.push(#ident);
                        }
                        let #ident = skrillax_serde_items;
                    }
                },
                _ => {
                    quote_spanned! { field.span() =>
                        let skrillax_serde_size = u8::read_from(reader)?;
                        let mut skrillax_serde_items = Vec::with_capacity(skrillax_serde_size.into());
                        for _ in 0..skrillax_serde_size {
                            #inner
                            skrillax_serde_items.push(#ident);
                        }
                        let #ident = skrillax_serde_items;
                    }
                },
            }
        },
        UsedType::Option(inner) => {
            let inner_ty = get_type_of(inner);
            let inner_ts = generate_reader_for_inner(ident, inner, &inner_ty);
            match args.when {
                Some(condition) => {
                    if let Ok(condition) = syn::parse_str::<Expr>(&condition) {
                        quote_spanned! { field.span() =>
                            let #ident = if #condition {
                                #inner_ts
                                Some(#ident)
                            } else {
                                None
                            };
                        }
                    } else {
                        abort!(field, "Condition could not be parsed");
                    }
                },
                None => {
                    quote_spanned! { field.span() =>
                        let skrillax_serde_some = u8::read_from(reader)?;
                        let #ident = if skrillax_serde_some == 1 {
                            #inner_ts
                            Some(#ident)
                        } else {
                            None
                        };
                    }
                },
            }
        },
        UsedType::Tuple(inner) => {
            let idents = (0..inner.len())
                .map(|i| format_ident!("t{}", i))
                .collect::<Vec<Ident>>();
            let content = inner.iter().zip(&idents).map(|(ty, ident)| {
                let inner_ty = get_type_of(ty);
                generate_reader_for_inner(ident, ty, &inner_ty)
            });
            quote_spanned! { field.span() =>
                #(#content)*
                let #ident = (#(#idents),*);
            }
        },
    }
}

fn generate_reader_for_inner(ident: &Ident, type_name: &Type, ty: &UsedType) -> TokenStream {
    match ty {
        UsedType::Primitive => {
            quote_spanned! { ident.span() =>
                let #ident = #type_name::read_from(reader)?;
            }
        },
        UsedType::String => {
            quote_spanned! { ident.span() =>
                let skrillax_serde_len = u16::read_from(reader)?;
                let mut skrillax_serde_bytes = Vec::with_capacity(skrillax_serde_len.into());
                for _ in 0..skrillax_serde_len {
                    skrillax_serde_bytes.push(u8::read_from(reader)?);
                }
                let #ident = String::from_utf8(skrillax_serde_bytes)?;
            }
        },
        UsedType::Array(len) => {
            quote_spanned! { ident.span() =>
                let mut skrillax_serde_bytes = [0u8; #len];
                reader.read_exact(skrillax_serde_bytes)?;
                let #ident = skrillax_serde_bytes;
            }
        },
        UsedType::Collection(inner) => {
            quote_spanned! { ident.span() =>
                let skrillax_serde_size = u8::read_from(reader)?;
                let mut skrillax_serde_items = Vec::with_capacity(skrillax_serde_size.into());
                for _ in 0..size {
                    skrillax_serde_items.push(#inner::read_from(reader)?);
                }
                let #ident = skrillax_serde_items;
            }
        },
        UsedType::Option(inner) => {
            quote_spanned! { ident.span() =>
                let skrillax_serde_some = u8::read_from(reader)?;
                let #ident = if skrillax_serde_some == 1 {
                    Some(#inner::read_from(reader)?)
                } else {
                    None
                };
            }
        },
        UsedType::Tuple(inner) => {
            let content = inner.iter().map(|ty| quote!(#ty::read_from(reader)?));
            quote_spanned! { ident.span() =>
                let #ident = (#(#content),*);
            }
        },
    }
}
