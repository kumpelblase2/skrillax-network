use crate::{FieldArgs, SilkroadArgs, UsedType, get_type_of, get_variant_value};
use darling::FromAttributes;
use proc_macro2::{Ident, TokenStream};
use proc_macro2_diagnostics::{Diagnostic, SpanDiagnosticExt};
use quote::{ToTokens, format_ident, quote, quote_spanned};
use syn::spanned::Spanned;
use syn::{Data, Expr, Field, Fields, Type};

pub(crate) fn deserialize(
    ident: &Ident,
    data: &Data,
    args: SilkroadArgs,
) -> Result<TokenStream, Diagnostic> {
    match data {
        Data::Struct(struct_data) => match &struct_data.fields {
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
                let content = named
                    .named
                    .iter()
                    .map(|field| {
                        generate_reader_for(
                            field,
                            field
                                .ident
                                .as_ref()
                                .expect("Field of named struct should have a name"),
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(quote_spanned! {ident.span()=>
                    #(#content)*
                    Ok(#ident { #(#idents),* })
                })
            },
            Fields::Unnamed(unnamed) => {
                let idents = (0..unnamed.unnamed.len())
                    .map(|i| format_ident!("t{}", i))
                    .collect::<Vec<Ident>>();
                let content = unnamed
                    .unnamed
                    .iter()
                    .zip(&idents)
                    .map(|(field, ident)| generate_reader_for(field, ident))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(quote_spanned! { ident.span() =>
                    #(#content)*
                    Ok(#ident(#(#idents),*))
                })
            },
            Fields::Unit => Ok(quote_spanned! { ident.span() =>
                Ok(#ident)
            }),
        },
        Data::Enum(enum_data) => {
            let enum_size = args.size.unwrap_or(1);
            if enum_size == 0 {
                let arms = enum_data
                    .variants
                    .iter()
                    .map(|variant| -> Result<TokenStream, Diagnostic> {
                        let field_args =
                            FieldArgs::from_attributes(&variant.attrs).map_err(|_| {
                                variant.span().error("Could not parse attrs for variant.")
                            })?;
                        let when = field_args.when.ok_or_else(|| {
                            variant.span().error("Missing condition for enum variant.")
                        })?;
                        let when = syn::parse_str::<Expr>(&when)
                            .map_err(|_| variant.span().error("Condition could not be parsed"))?;

                        let variant_ident = &variant.ident;
                        let variable_name = Ident::new(
                            &variant_ident.to_string().to_lowercase(),
                            variant_ident.span(),
                        );
                        let content = match &variant.fields {
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
                                let content = named
                                    .named
                                    .iter()
                                    .map(|field| {
                                        generate_reader_for(
                                            field,
                                            field
                                                .ident
                                                .as_ref()
                                                .expect("Field of named struct should have a name"),
                                        )
                                    })
                                    .collect::<Result<Vec<_>, _>>()?;
                                quote! {
                                    #(#content)*
                                    let #variable_name = #ident::#variant_ident { #(#idents),* };
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
                                    .map(|(field, ident)| generate_reader_for(field, ident))
                                    .collect::<Result<Vec<_>, _>>()?;
                                quote! {
                                    #(#content)*
                                    let #variable_name = #ident::#variant_ident(#(#idents),*);
                                }
                            },
                            Fields::Unit => quote! {
                                let #variable_name = #ident::#variant_ident
                            },
                        };
                        Ok(quote_spanned! { variant_ident.span() =>
                            if #when {
                                #content
                                return Ok(#variable_name);
                            }
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                Ok(quote_spanned! { ident.span() =>
                    #(#arms)*
                    Err(skrillax_serde::SerializationError::UnknownVariation(0, "No arm matched the conditions."))
                })
            } else {
                let arms = enum_data
                    .variants
                    .iter()
                    .enumerate()
                    .map(|(i, variant)| -> Result<TokenStream, Diagnostic> {
                        let field_args =
                            FieldArgs::from_attributes(&variant.attrs).map_err(|_| {
                                variant.span().error("Could not parse attrs for variant.")
                            })?;

                        if field_args.value.is_none() && field_args.when.is_none() {
                            return Err(variant.span().error(
                                "When size is not zero, either value or when should be set.",
                            ));
                        }

                        let variant_check = if let Some(cond) = field_args.when {
                            let cond_str = cond.replace("tag", "variant");
                            let cond = syn::parse_str::<Expr>(&cond_str).map_err(|_| {
                                variant.span().error("Condition could not be parsed")
                            })?;
                            quote! { variant if #cond }
                        } else {
                            get_variant_value(
                                &variant.ident,
                                field_args.value.unwrap_or(i),
                                enum_size,
                            )?
                            .to_token_stream()
                        };
                        let variant_ident = &variant.ident;

                        let output = match &variant.fields {
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
                                let content = named
                                    .named
                                    .iter()
                                    .map(|field| {
                                        generate_reader_for(
                                            field,
                                            field
                                                .ident
                                                .as_ref()
                                                .expect("Field of named struct should have a name"),
                                        )
                                    })
                                    .collect::<Result<Vec<_>, _>>()?;
                                quote_spanned! { variant_ident.span() =>
                                    #variant_check => {
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
                                    .map(|(field, ident)| generate_reader_for(field, ident))
                                    .collect::<Result<Vec<_>, _>>()?;
                                quote_spanned! { variant_ident.span() =>
                                    #variant_check => {
                                        #(#content)*
                                        Ok(#ident::#variant_ident(#(#idents),*))
                                    }
                                }
                            },
                            Fields::Unit => quote_spanned! { variant_ident.span() =>
                                #variant_check => {
                                    Ok(#ident::#variant_ident)
                                }
                            },
                        };
                        Ok(output)
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                let variant_string = format!("{ident}");
                let size = args.size.unwrap_or(1);
                let reader = match size {
                    1 => {
                        quote_spanned!(ident.span() => u8::read_from(reader, ctx).map_err(|e| skrillax_serde::SerializationError::field_io_error(#variant_string, e))?)
                    },
                    2 => {
                        quote_spanned!(ident.span() => u16::read_from(reader, ctx).map_err(|e| skrillax_serde::SerializationError::field_io_error(#variant_string, e))?)
                    },
                    4 => {
                        quote_spanned!(ident.span() => u32::read_from(reader, ctx).map_err(|e| skrillax_serde::SerializationError::field_io_error(#variant_string, e))?)
                    },
                    8 => {
                        quote_spanned!(ident.span() => u64::read_from(reader, ctx).map_err(|e| skrillax_serde::SerializationError::field_io_error(#variant_string, e))?)
                    },
                    _ => return Err(ident.span().error("Invalid size")),
                };
                Ok(quote_spanned! { ident.span() =>
                    match #reader {
                        #(#arms),*,
                        unknown => Err(skrillax_serde::SerializationError::UnknownVariation(unknown as usize, #variant_string)),
                    }
                })
            }
        },
        _ => Err(ident.span().error("Unions are not supported.")),
    }
}

fn generate_reader_for(field: &Field, ident: &Ident) -> Result<TokenStream, Diagnostic> {
    let ty = get_type_of(&field.ty)?;
    let type_name = &field.ty;
    let args = FieldArgs::from_attributes(&field.attrs)
        .map_err(|_| field.span().error("Could not parse attrs for field."))?;
    let ident_string = format!("\"{ident}\"");

    if args.tag {
        return Ok(quote_spanned! { field.span() =>
            let #ident = variant;
        });
    }

    if !matches!(ty, UsedType::Collection(_))
        && let Some(calculate) = args.calculate
    {
        return Ok(quote_spanned! { field.span() =>
            let #ident = #calculate;
        });
    }

    match ty {
        UsedType::Primitive => Ok(quote_spanned! { field.span() =>
            let #ident = #type_name::read_from(reader, ctx).map_err(|e| skrillax_serde::SerializationError::field_io_error(#ident_string, e))?;
        }),
        UsedType::String => {
            let content = match args.size.unwrap_or(1) {
                1 => quote! {
                    for _ in 0..skrillax_serde_len {
                        skrillax_serde_bytes.push(u8::read_from(reader, ctx).map_err(|e| skrillax_serde::SerializationError::field_io_error(#ident_string, e))?);
                    }
                    let #ident = String::from_utf8(skrillax_serde_bytes)?;
                },
                2 => quote! {
                    for _ in 0..skrillax_serde_len {
                        skrillax_serde_bytes.push(u16::read_from(reader, ctx).map_err(|e| skrillax_serde::SerializationError::field_io_error(#ident_string, e))?);
                    }
                    let #ident = String::from_utf16(&skrillax_serde_bytes)?;
                },
                _ => return Err(field.span().error("Unknown String size")),
            };

            Ok(quote_spanned! { field.span() =>
                let skrillax_serde_len = u16::read_from(reader, ctx).map_err(|e| skrillax_serde::SerializationError::field_io_error(#ident_string, e))?;
                let mut skrillax_serde_bytes = Vec::with_capacity(skrillax_serde_len.into());
                #content
            })
        },
        UsedType::Array(len) => Ok(quote_spanned! { field.span() =>
            let mut skrillax_serde_bytes = [0u8; #len];
            reader.read_exact(&mut skrillax_serde_bytes)?;
            let #ident = skrillax_serde_bytes;
        }),
        UsedType::Collection(inner) => {
            let inner_ty = get_type_of(inner)?;
            let inner = generate_reader_for_inner(ident, inner, &inner_ty)?;
            let list_type = args.list_type.as_deref().unwrap_or("length");
            match list_type {
                "has-more" | "break" => {
                    let break_value = if list_type == "has-more" { 0u8 } else { 2u8 };
                    Ok(quote_spanned! { field.span() =>
                        let mut skrillax_serde_items = Vec::new();
                        loop {
                            let skrillax_serde_more = u8::read_from(reader, ctx).map_err(|e| skrillax_serde::SerializationError::field_io_error(#ident_string, e))?;
                            if skrillax_serde_more == #break_value {
                                break;
                            }

                            #inner
                            skrillax_serde_items.push(#ident);
                        }
                        let #ident = skrillax_serde_items;
                    })
                },
                "calculated" => {
                    let calculation = args.calculate.as_ref().ok_or_else(|| {
                        field.span().error(
                            "Missing `calculate` attribute for collection of size `calculated`.",
                        )
                    })?;
                    let calculation = syn::parse_str::<Expr>(calculation)
                        .map_err(|_| field.span().error("Calculation could not be parsed"))?;

                    Ok(quote_spanned! { field.span() =>
                        let skrillax_serde_size = #calculation;
                        let mut skrillax_serde_items = Vec::with_capacity(skrillax_serde_size.into());
                        for _ in 0..skrillax_serde_size {
                            #inner
                            skrillax_serde_items.push(#ident);
                        }
                        let #ident = skrillax_serde_items;
                    })
                },
                _ => Ok(quote_spanned! { field.span() =>
                    let skrillax_serde_size = u8::read_from(reader, ctx).map_err(|e| skrillax_serde::SerializationError::field_io_error(#ident_string, e))?;
                    let mut skrillax_serde_items = Vec::with_capacity(skrillax_serde_size.into());
                    for _ in 0..skrillax_serde_size {
                        #inner
                        skrillax_serde_items.push(#ident);
                    }
                    let #ident = skrillax_serde_items;
                }),
            }
        },
        UsedType::Option(inner) => {
            let inner_ty = get_type_of(inner)?;
            let inner_ts = generate_reader_for_inner(ident, inner, &inner_ty)?;
            match args.when {
                Some(condition) => {
                    let condition = syn::parse_str::<Expr>(&condition)
                        .map_err(|_| field.span().error("Condition could not be parsed"))?;
                    Ok(quote_spanned! { field.span() =>
                        let #ident = if #condition {
                            #inner_ts
                            Some(#ident)
                        } else {
                            None
                        };
                    })
                },
                None => Ok(quote_spanned! { field.span() =>
                    let skrillax_serde_some = u8::read_from(reader, ctx).map_err(|e| skrillax_serde::SerializationError::field_io_error(#ident_string, e))?;
                    let #ident = if skrillax_serde_some == 1 {
                        #inner_ts
                        Some(#ident)
                    } else {
                        None
                    };
                }),
            }
        },
        UsedType::Tuple(inner) => {
            let idents = (0..inner.len())
                .map(|i| format_ident!("t{}", i))
                .collect::<Vec<Ident>>();
            let content = inner
                .iter()
                .zip(&idents)
                .map(|(ty, ident)| {
                    let inner_ty = get_type_of(ty)?;
                    generate_reader_for_inner(ident, ty, &inner_ty)
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(quote_spanned! { field.span() =>
                #(#content)*
                let #ident = (#(#idents),*);
            })
        },
    }
}

fn generate_reader_for_inner(
    ident: &Ident,
    type_name: &Type,
    ty: &UsedType,
) -> Result<TokenStream, Diagnostic> {
    let ident_string = format!("{ident}");
    Ok(match ty {
        UsedType::Primitive => quote_spanned! { ident.span() =>
            let #ident = #type_name::read_from(reader, ctx).map_err(|e| skrillax_serde::SerializationError::field_io_error(#ident_string, e))?;
        },
        UsedType::String => quote_spanned! { ident.span() =>
            let skrillax_serde_len = u16::read_from(reader, ctx).map_err(|e| skrillax_serde::SerializationError::field_io_error(#ident_string, e))?;
            let mut skrillax_serde_bytes = Vec::with_capacity(skrillax_serde_len.into());
            for _ in 0..skrillax_serde_len {
                skrillax_serde_bytes.push(u8::read_from(reader, ctx).map_err(|e| skrillax_serde::SerializationError::field_io_error(#ident_string, e))?);
            }
            let #ident = String::from_utf8(skrillax_serde_bytes)?;
        },
        UsedType::Array(len) => quote_spanned! { ident.span() =>
            let mut skrillax_serde_bytes = [0u8; #len];
            reader.read_exact(skrillax_serde_bytes)?;
            let #ident = skrillax_serde_bytes;
        },
        UsedType::Collection(inner) => quote_spanned! { ident.span() =>
            let skrillax_serde_size = u8::read_from(reader, ctx).map_err(|e| skrillax_serde::SerializationError::field_io_error(#ident_string, e))?;
            let mut skrillax_serde_items = Vec::with_capacity(skrillax_serde_size.into());
            for _ in 0..skrillax_serde_size {
                skrillax_serde_items.push(#inner::read_from(reader, ctx).map_err(|e| skrillax_serde::SerializationError::field_io_error(#ident_string, e))?);
            }
            let #ident = skrillax_serde_items;
        },
        UsedType::Option(inner) => quote_spanned! { ident.span() =>
            let skrillax_serde_some = u8::read_from(reader,ctx).map_err(|e| skrillax_serde::SerializationError::field_io_error(#ident_string, e))?;
            let #ident = if skrillax_serde_some == 1 {
                Some(#inner::read_from(reader, ctx).map_err(|e| skrillax_serde::SerializationError::field_io_error(#ident_string, e))?)
            } else {
                None
            };
        },
        UsedType::Tuple(inner) => {
            let content = inner.iter().map(|ty| quote!(#ty::read_from(reader, ctx)?));
            quote_spanned! { ident.span() =>
                let #ident = (#(#content),*);
            }
        },
    })
}
