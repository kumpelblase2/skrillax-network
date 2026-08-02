use crate::model::{
    DataModel, FieldModel, FieldRole, IntegerWidth, Presence, SequenceFraming, StringEncoding,
    VariantModel, VariantSelector, WireModel, WireType,
};
use proc_macro2::{Ident, Span, TokenStream};
use proc_macro2_diagnostics::{Diagnostic, SpanDiagnosticExt};
use quote::{format_ident, quote, quote_spanned};
use std::collections::HashSet;
use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::visit_mut::VisitMut;
use syn::{Expr, Fields, Type};

pub(crate) fn deserialize(model: &WireModel<'_>) -> Result<TokenStream, Diagnostic> {
    let ident = model.ident;
    match &model.data {
        DataModel::Struct(struct_model) => {
            let bindings = struct_model
                .fields
                .iter()
                .enumerate()
                .map(|(index, _)| format_ident!("skrillax_serde_field_{index}"))
                .collect::<Vec<_>>();
            let expression_fields = struct_model
                .fields
                .iter()
                .zip(&bindings)
                .filter_map(|(field, binding)| {
                    field
                        .field
                        .ident
                        .clone()
                        .map(|source| (source, binding.clone()))
                })
                .collect::<Vec<_>>();
            let content = struct_model
                .fields
                .iter()
                .enumerate()
                .map(|(index, field)| {
                    generate_reader_for(
                        field,
                        &bindings[index],
                        &expression_fields,
                        &field_name(field, index).to_string(),
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            match &struct_model.data.fields {
                Fields::Named(fields) => {
                    let construction =
                        fields.named.iter().zip(&bindings).map(|(field, binding)| {
                            let source =
                                field.ident.as_ref().expect("named field has an identifier");
                            quote!(#source: #binding)
                        });
                    Ok(quote_spanned! {model.ident.span() =>
                        #(#content)*
                        Ok(#ident { #(#construction),* })
                    })
                },
                Fields::Unnamed(_) => Ok(quote_spanned! {model.ident.span() =>
                    #(#content)*
                    Ok(#ident(#(#bindings),*))
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
                let enum_name = model.ident.to_string();
                let reader = read_integer(width, model.ident, &enum_name);
                let predicate = enum_model.variants.first().is_some_and(|variant| {
                    matches!(variant.selector, VariantSelector::Predicate(_))
                });
                let fallback = if predicate {
                    quote!(_unknown => Err(skrillax_serde::SerializationError::NoMatchingVariant {
                        enum_name: stringify!(#ident),
                    }))
                } else {
                    quote!(unknown => Err(skrillax_serde::SerializationError::UnknownVariation(
                        u64::from(unknown),
                        stringify!(#ident),
                    )))
                };
                Ok(quote_spanned! {model.ident.span() =>
                    let tag = #reader;
                    match tag {
                        #(#arms),*,
                        #fallback,
                    }
                })
            } else {
                Ok(quote_spanned! {model.ident.span() =>
                    #(#arms)*
                    Err(skrillax_serde::SerializationError::NoMatchingVariant {
                        enum_name: stringify!(#ident),
                    })
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

fn generate_reader_for(
    field: &FieldModel<'_>,
    ident: &Ident,
    expression_fields: &[(Ident, Ident)],
    name: &str,
) -> Result<TokenStream, Diagnostic> {
    let span = field.field.span();
    match &field.role {
        FieldRole::EnumTag => Ok(quote_spanned! {span => let #ident = tag; }),
        FieldRole::Synthetic { expression } => {
            let expression = rewrite_expression(expression, expression_fields);
            Ok(quote_spanned! {span => let #ident = #expression; })
        },
        FieldRole::Wire => match &field.kind {
            WireType::Delegated(type_name) => Ok(read_delegated(type_name, ident, span, name)),
            WireType::String => read_string(field, ident, name),
            WireType::Array { .. } => read_value(&field.kind, ident, span, name),
            WireType::Collection { element } => {
                read_collection(field, element, ident, expression_fields, name)
            },
            WireType::Optional { inner } => {
                read_option(field, inner, ident, expression_fields, name)
            },
            WireType::Tuple(items) => read_tuple(items, ident, span, name),
        },
    }
}

fn read_delegated(type_name: &Type, ident: &Ident, span: Span, name: &str) -> TokenStream {
    quote_spanned! {span =>
        let #ident = <#type_name as skrillax_serde::Deserialize>::read_from(reader, ctx)
            .map_err(|e| skrillax_serde::SerializationError::field_io_error(#name, e))?;
    }
}

fn read_string(
    field: &FieldModel<'_>,
    ident: &Ident,
    name: &str,
) -> Result<TokenStream, Diagnostic> {
    let span = field.field.span();
    let body = match field.string_encoding.expect("strings have an encoding") {
        StringEncoding::Utf8 => quote! {
            let mut values = Vec::with_capacity(length.into());
            for _ in 0..length {
                values.push(u8::read_from(reader, ctx)
                    .map_err(|e| skrillax_serde::SerializationError::field_io_error(#name, e))?);
            }
            String::from_utf8(values)?
        },
        StringEncoding::Utf16 => quote! {
            let mut values = Vec::with_capacity(length.into());
            for _ in 0..length {
                values.push(u16::read_from(reader, ctx)
                    .map_err(|e| skrillax_serde::SerializationError::field_io_error(#name, e))?);
            }
            String::from_utf16(&values)?
        },
    };
    Ok(quote_spanned! {span =>
        let #ident = {
            let length = u16::read_from(reader, ctx)
                .map_err(|e| skrillax_serde::SerializationError::field_io_error(#name, e))?;
            #body
        };
    })
}

fn read_collection(
    field: &FieldModel<'_>,
    element: &WireType<'_>,
    ident: &Ident,
    expression_fields: &[(Ident, Ident)],
    name: &str,
) -> Result<TokenStream, Diagnostic> {
    let span = field.field.span();
    let item = format_ident!("skrillax_serde_{}_item", ident);
    let item_read = read_value(element, &item, span, name)?;
    let framing = field.framing.as_ref().expect("collections have framing");
    let output = match framing {
        SequenceFraming::Break { marker_width } => {
            let marker = read_integer(*marker_width, ident, name);
            let item_marker = width_literal(*marker_width, 1);
            let end_marker = width_literal(*marker_width, 2);
            quote! {
                let #ident = {
                    let mut items = Vec::new();
                    loop {
                        let marker = #marker;
                        match marker {
                            #end_marker => break,
                            #item_marker => {
                                let current_count = u64::try_from(items.len()).unwrap_or(u64::MAX);
                                let attempted_count = current_count.checked_add(1).unwrap_or(u64::MAX);
                                ctx.check_collection_length(#name, attempted_count)?;
                                if items.len() == items.capacity() {
                                    items.try_reserve(1).map_err(|source| {
                                        skrillax_serde::SerializationError::CollectionAllocationFailed {
                                            field: #name,
                                            elements: attempted_count,
                                            source,
                                        }
                                    })?;
                                }
                                #item_read
                                items.push(#item);
                            },
                            invalid => return Err(skrillax_serde::SerializationError::InvalidSequenceMarker {
                                field: #name,
                                value: u64::from(invalid),
                            }),
                        }
                    }
                    items
                };
            }
        },
        SequenceFraming::HasMore { marker_width } => {
            let marker = read_integer(*marker_width, ident, name);
            let item_marker = width_literal(*marker_width, 1);
            let end_marker = width_literal(*marker_width, 0);
            quote! {
                let #ident = {
                    let mut items = Vec::new();
                    loop {
                        let marker = #marker;
                        match marker {
                            #end_marker => break,
                            #item_marker => {
                                let current_count = u64::try_from(items.len()).unwrap_or(u64::MAX);
                                let attempted_count = current_count.checked_add(1).unwrap_or(u64::MAX);
                                ctx.check_collection_length(#name, attempted_count)?;
                                if items.len() == items.capacity() {
                                    items.try_reserve(1).map_err(|source| {
                                        skrillax_serde::SerializationError::CollectionAllocationFailed {
                                            field: #name,
                                            elements: attempted_count,
                                            source,
                                        }
                                    })?;
                                }
                                #item_read
                                items.push(#item);
                            },
                            invalid => return Err(skrillax_serde::SerializationError::InvalidSequenceMarker {
                                field: #name,
                                value: u64::from(invalid),
                            }),
                        }
                    }
                    items
                };
            }
        },
        SequenceFraming::Counted { width } => {
            let count = read_integer(*width, ident, name);
            quote! {
                let #ident = {
                    let decoded_count = #count;
                    let decoded_count_u64 = u64::from(decoded_count);
                    ctx.check_collection_length(#name, decoded_count_u64)?;
                    let count = usize::try_from(decoded_count).map_err(|_| {
                        skrillax_serde::SerializationError::DecodedLengthOutOfRange {
                            field: #name,
                            value: decoded_count_u64,
                        }
                    })?;
                    let mut items = Vec::new();
                    items.try_reserve_exact(count).map_err(|source| {
                        skrillax_serde::SerializationError::CollectionAllocationFailed {
                            field: #name,
                            elements: decoded_count_u64,
                            source,
                        }
                    })?;
                    for _ in 0..count {
                        #item_read
                        items.push(#item);
                    }
                    items
                };
            }
        },
        SequenceFraming::Calculated { expression } => {
            let expression = rewrite_expression(expression, expression_fields);
            quote! {
                let #ident = {
                    let calculated_count = #expression;
                    let count = usize::try_from(calculated_count).map_err(|_| {
                        skrillax_serde::SerializationError::CalculatedLengthOutOfRange {
                            field: #name,
                        }
                    })?;
                    let count_u64 = u64::try_from(count).map_err(|_| {
                        skrillax_serde::SerializationError::CalculatedLengthOutOfRange {
                            field: #name,
                        }
                    })?;
                    ctx.check_collection_length(#name, count_u64)?;
                    let mut items = Vec::new();
                    items.try_reserve_exact(count).map_err(|source| {
                        skrillax_serde::SerializationError::CollectionAllocationFailed {
                            field: #name,
                            elements: count_u64,
                            source,
                        }
                    })?;
                    for _ in 0..count {
                        #item_read
                        items.push(#item);
                    }
                    items
                };
            }
        },
    };
    Ok(quote_spanned! {span => #output})
}

fn read_option(
    field: &FieldModel<'_>,
    inner: &WireType<'_>,
    ident: &Ident,
    expression_fields: &[(Ident, Ident)],
    name: &str,
) -> Result<TokenStream, Diagnostic> {
    let span = field.field.span();
    let item = format_ident!("skrillax_serde_{}_inner", ident);
    let inner_read = read_value(inner, &item, span, name)?;
    let output = match field.presence.as_ref().expect("options have presence") {
        Presence::Conditional { expression } => {
            let expression = rewrite_expression(expression, expression_fields);
            quote! {
                let #ident = if #expression {
                    #inner_read
                    Some(#item)
                } else {
                    None
                };
            }
        },
        Presence::Bare => quote! {
            let #ident = None;
        },
        Presence::Explicit { width } => {
            let marker = read_integer(*width, ident, name);
            let some_marker = width_literal(*width, 1);
            let none_marker = width_literal(*width, 0);
            quote! {
                let #ident = {
                    let marker = #marker;
                    match marker {
                        #some_marker => {
                            #inner_read
                            Some(#item)
                        },
                        #none_marker => None,
                        invalid => return Err(skrillax_serde::SerializationError::InvalidPresenceMarker {
                            field: #name,
                            value: u64::from(invalid),
                        }),
                    }
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
    name: &str,
) -> Result<TokenStream, Diagnostic> {
    let bindings = (0..items.len())
        .map(|index| format_ident!("{}_t{index}", ident))
        .collect::<Vec<_>>();
    let content = items
        .iter()
        .zip(&bindings)
        .map(|(kind, binding)| read_value(kind, binding, span, name))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(quote_spanned! {span =>
        #(#content)*
        let #ident = (#(#bindings,)*);
    })
}

fn read_value(
    kind: &WireType<'_>,
    ident: &Ident,
    span: Span,
    name: &str,
) -> Result<TokenStream, Diagnostic> {
    match kind {
        WireType::Delegated(type_name) => Ok(read_delegated(type_name, ident, span, name)),
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
            length,
            ..
        } => Ok(quote_spanned! {span =>
            let #ident = <[#element_type; #length] as skrillax_serde::Deserialize>::read_from(reader, ctx)
                .map_err(|e| skrillax_serde::SerializationError::field_io_error(#name, e))?;
        }),
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
    let bindings = variant
        .fields
        .iter()
        .enumerate()
        .map(|(index, _)| format_ident!("skrillax_serde_variant_field_{index}"))
        .collect::<Vec<_>>();
    let named_sources = match &variant.variant.fields {
        Fields::Named(fields) => fields
            .named
            .iter()
            .filter_map(|field| field.ident.clone())
            .collect::<Vec<_>>(),
        Fields::Unnamed(_) | Fields::Unit => Vec::new(),
    };
    let expression_fields = named_sources
        .iter()
        .zip(&bindings)
        .map(|(source, binding)| (source.clone(), binding.clone()))
        .collect::<Vec<_>>();
    let content = variant
        .fields
        .iter()
        .enumerate()
        .map(|(index, field)| {
            generate_reader_for(
                field,
                &bindings[index],
                &expression_fields,
                &field_name(field, index).to_string(),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let result = match &variant.variant.fields {
        Fields::Named(_) => {
            let construction = named_sources
                .iter()
                .zip(&bindings)
                .map(|(source, binding)| quote!(#source: #binding));
            quote!(Ok(#enum_ident::#name { #(#construction),* }))
        },
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

#[derive(Default)]
struct PatternBindings(HashSet<String>);

impl<'ast> Visit<'ast> for PatternBindings {
    fn visit_pat_ident(&mut self, pattern: &'ast syn::PatIdent) {
        self.0.insert(pattern.ident.to_string());
        syn::visit::visit_pat_ident(self, pattern);
    }
}

fn pattern_bindings(pattern: &syn::Pat) -> HashSet<String> {
    let mut bindings = PatternBindings::default();
    bindings.visit_pat(pattern);
    bindings.0
}

struct ExpressionRewriter<'a> {
    fields: &'a [(Ident, Ident)],
    scopes: Vec<HashSet<String>>,
}

impl ExpressionRewriter<'_> {
    fn is_bound(&self, ident: &Ident) -> bool {
        let name = ident.to_string();
        self.scopes.iter().rev().any(|scope| scope.contains(&name))
    }
}

impl VisitMut for ExpressionRewriter<'_> {
    fn visit_expr_mut(&mut self, expression: &mut Expr) {
        if let Expr::Path(path) = expression
            && path.qself.is_none()
            && path.path.leading_colon.is_none()
            && path.path.segments.len() == 1
        {
            let source = &path.path.segments[0].ident;
            if !self.is_bound(source)
                && let Some((_, binding)) = self.fields.iter().find(|(field, _)| field == source)
            {
                let span = source.span();
                *expression = syn::parse_quote_spanned!(span=> #binding);
                return;
            }
        }
        syn::visit_mut::visit_expr_mut(self, expression);
    }

    fn visit_expr_closure_mut(&mut self, closure: &mut syn::ExprClosure) {
        let bindings = closure
            .inputs
            .iter()
            .flat_map(pattern_bindings)
            .collect::<HashSet<_>>();
        self.scopes.push(bindings);
        self.visit_expr_mut(&mut closure.body);
        self.scopes.pop();
    }

    fn visit_block_mut(&mut self, block: &mut syn::Block) {
        self.scopes.push(HashSet::new());
        for statement in &mut block.stmts {
            match statement {
                syn::Stmt::Local(local) => {
                    if let Some(initializer) = &mut local.init {
                        self.visit_expr_mut(&mut initializer.expr);
                        if let Some((_, diverge)) = &mut initializer.diverge {
                            self.visit_expr_mut(diverge);
                        }
                    }
                    let bindings = pattern_bindings(&local.pat);
                    self.scopes
                        .last_mut()
                        .expect("block scope exists")
                        .extend(bindings);
                },
                syn::Stmt::Expr(expression, _) => self.visit_expr_mut(expression),
                syn::Stmt::Item(_) | syn::Stmt::Macro(_) => {},
            }
        }
        self.scopes.pop();
    }

    fn visit_expr_match_mut(&mut self, expression: &mut syn::ExprMatch) {
        self.visit_expr_mut(&mut expression.expr);
        for arm in &mut expression.arms {
            self.scopes.push(pattern_bindings(&arm.pat));
            if let Some((_, guard)) = &mut arm.guard {
                self.visit_expr_mut(guard);
            }
            self.visit_expr_mut(&mut arm.body);
            self.scopes.pop();
        }
    }

    fn visit_expr_for_loop_mut(&mut self, expression: &mut syn::ExprForLoop) {
        self.visit_expr_mut(&mut expression.expr);
        self.scopes.push(pattern_bindings(&expression.pat));
        self.visit_block_mut(&mut expression.body);
        self.scopes.pop();
    }
}

fn rewrite_expression(expression: &Expr, fields: &[(Ident, Ident)]) -> Expr {
    let mut expression = expression.clone();
    ExpressionRewriter {
        fields,
        scopes: Vec::new(),
    }
    .visit_expr_mut(&mut expression);
    expression
}

fn read_integer(width: IntegerWidth, ident: &Ident, name: &str) -> TokenStream {
    let rust_type = syn::Ident::new(width.rust_type(), ident.span());
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
