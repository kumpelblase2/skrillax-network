use crate::expression::MatchesMacro;
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
use syn::{Expr, Fields, Index};

pub(crate) fn serialize(model: &WireModel<'_>) -> Result<TokenStream, Diagnostic> {
    match &model.data {
        DataModel::Struct(struct_model) => {
            let expression_fields = struct_model
                .fields
                .iter()
                .filter_map(|field| field.field.ident.clone())
                .map(|ident| (ident.clone(), ExpressionAccess::SelfField(ident)))
                .collect::<Vec<_>>();
            let content = struct_model
                .fields
                .iter()
                .enumerate()
                .map(|(index, field)| {
                    let access = field_access(field, index);
                    generate_for_field(field, access, &expression_fields)
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(quote_spanned! { model.ident.span() => #(#content)* })
        },
        DataModel::Enum(enum_model) => {
            let content = enum_model
                .variants
                .iter()
                .enumerate()
                .map(|(index, variant)| {
                    generate_for_variant(
                        model.ident,
                        variant,
                        index,
                        &enum_model.variants,
                        enum_model.width,
                    )
                })
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

fn field_name(field: &FieldModel<'_>) -> String {
    field
        .field
        .ident
        .as_ref()
        .map(ToString::to_string)
        .unwrap_or_else(|| "unnamed field".to_owned())
}

fn generate_for_field(
    field: &FieldModel<'_>,
    ident: TokenStream,
    expression_fields: &[(Ident, ExpressionAccess)],
) -> Result<TokenStream, Diagnostic> {
    if !matches!(field.role, FieldRole::Wire) {
        return Ok(quote!());
    }

    let name = field_name(field);
    match &field.kind {
        WireType::Delegated(_) => Ok(quote_spanned! {field.field.span() =>
            #ident.write_to(writer, ctx)?;
        }),
        WireType::String => {
            let output = serialize_string(
                ident,
                field.string_encoding.expect("strings have an encoding"),
                &name,
            );
            Ok(quote_spanned! {field.field.span() => { #output }})
        },
        WireType::Array { .. } => Ok(quote_spanned! {field.field.span() =>
            #ident.write_to(writer, ctx)?;
        }),
        WireType::Collection { element } => {
            let inner = quote!(skrillax_serde_inner);
            let body = generate_value(element, inner, field.field.span(), &name)?;
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
                    let maximum = width.max_value();
                    let width_bytes = width.bytes();
                    quote! {
                        let skrillax_serde_actual = #ident.len();
                        let skrillax_serde_count = <#rust_type>::try_from(skrillax_serde_actual)
                            .map_err(|_| skrillax_serde::SerializationError::LengthOutOfRange {
                                field: #name,
                                actual: skrillax_serde_actual,
                                maximum: #maximum,
                                width: #width_bytes,
                            })?;
                        skrillax_serde_count.write_to(writer, ctx)?;
                        for skrillax_serde_inner in #ident.iter() {
                            #body
                        }
                    }
                },
                SequenceFraming::Calculated { expression } => {
                    let expression = rewrite_expression(expression, expression_fields);
                    quote! {
                        let skrillax_serde_expected = usize::try_from(#expression)
                            .map_err(|_| skrillax_serde::SerializationError::CalculatedLengthOutOfRange {
                                field: #name,
                            })?;
                        let skrillax_serde_actual = #ident.len();
                        if skrillax_serde_expected != skrillax_serde_actual {
                            return Err(skrillax_serde::SerializationError::CalculatedLengthMismatch {
                                field: #name,
                                expected: skrillax_serde_expected,
                                actual: skrillax_serde_actual,
                            });
                        }
                        for skrillax_serde_inner in #ident.iter() {
                            #body
                        }
                    }
                },
            };
            Ok(quote_spanned! {field.field.span() => { #framing_output } })
        },
        WireType::Optional { inner } => {
            let inner_body = generate_value(
                inner,
                quote!(skrillax_serde_inner),
                field.field.span(),
                &name,
            )?;
            let presence = field.presence.as_ref().expect("options have presence");
            let output = match presence {
                Presence::Explicit { width } => {
                    let some = width_literal(*width, 1);
                    let none = width_literal(*width, 0);
                    quote! {
                        match (#ident).as_ref() {
                            Some(skrillax_serde_inner) => {
                                #some.write_to(writer, ctx)?;
                                #inner_body
                            },
                            None => #none.write_to(writer, ctx)?,
                        }
                    }
                },
                Presence::Conditional { expression } => {
                    let expression = rewrite_expression(expression, expression_fields);
                    quote! {
                        let skrillax_serde_condition: bool = #expression;
                        let skrillax_serde_present = #ident.is_some();
                        if skrillax_serde_condition != skrillax_serde_present {
                            return Err(skrillax_serde::SerializationError::ConditionalPresenceMismatch {
                                field: #name,
                                condition: skrillax_serde_condition,
                                present: skrillax_serde_present,
                            });
                        }
                        if let Some(skrillax_serde_inner) = (#ident).as_ref() {
                            #inner_body
                        }
                    }
                },
                Presence::Bare => quote! {
                    if let Some(skrillax_serde_inner) = (#ident).as_ref() {
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
                .map(|(kind, ident)| {
                    generate_value(kind, quote!(#ident), field.field.span(), &name)
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(quote_spanned! {field.field.span() =>
                let (#(#defs,)*) = &#ident;
                #(#content)*
            })
        },
    }
}

fn serialize_string(ident: TokenStream, encoding: StringEncoding, field_name: &str) -> TokenStream {
    match encoding {
        StringEncoding::Utf8 => quote! {
            let skrillax_serde_actual = #ident.as_bytes().len();
            let skrillax_serde_length = u16::try_from(skrillax_serde_actual)
                .map_err(|_| skrillax_serde::SerializationError::LengthOutOfRange {
                    field: #field_name,
                    actual: skrillax_serde_actual,
                    maximum: u64::from(u16::MAX),
                    width: 2,
                })?;
            skrillax_serde_length.write_to(writer, ctx)?;
            for byte in #ident.as_bytes() {
                byte.write_to(writer, ctx)?;
            }
        },
        StringEncoding::Utf16 => quote! {
            let skrillax_serde_units = #ident.encode_utf16().collect::<Vec<_>>();
            let skrillax_serde_actual = skrillax_serde_units.len();
            let skrillax_serde_length = u16::try_from(skrillax_serde_actual)
                .map_err(|_| skrillax_serde::SerializationError::LengthOutOfRange {
                    field: #field_name,
                    actual: skrillax_serde_actual,
                    maximum: u64::from(u16::MAX),
                    width: 2,
                })?;
            skrillax_serde_length.write_to(writer, ctx)?;
            for unit in skrillax_serde_units {
                unit.write_to(writer, ctx)?;
            }
        },
    }
}

fn generate_value(
    kind: &WireType<'_>,
    ident: TokenStream,
    span: Span,
    field_name: &str,
) -> Result<TokenStream, Diagnostic> {
    match kind {
        WireType::Delegated(_) | WireType::Array { .. } => {
            Ok(quote_spanned! {span => #ident.write_to(writer, ctx)?; })
        },
        WireType::String => Ok(serialize_string(ident, StringEncoding::Utf8, field_name)),
        WireType::Collection { .. } | WireType::Optional { .. } | WireType::Tuple(_) => {
            Err(span
                .error("Unsupported nested wire shape reached serialization after normalization."))
        },
    }
}

fn generate_for_variant(
    ident: &Ident,
    variant: &VariantModel<'_>,
    variant_index: usize,
    variants: &[VariantModel<'_>],
    width: Option<IntegerWidth>,
) -> Result<TokenStream, Diagnostic> {
    let variant_name = &variant.variant.ident;
    let fields = variant
        .fields
        .iter()
        .enumerate()
        .map(|(index, _)| format_ident!("skrillax_serde_variant_field_{index}"))
        .collect::<Vec<_>>();
    let named_sources = match &variant.variant.fields {
        Fields::Named(fields) => fields
            .named
            .iter()
            .filter_map(|field| field.ident.as_ref())
            .cloned()
            .collect::<Vec<_>>(),
        Fields::Unnamed(_) | Fields::Unit => Vec::new(),
    };
    let named_patterns = named_sources
        .iter()
        .zip(&fields)
        .map(|(source, binding)| quote!(#source: #binding))
        .collect::<Vec<_>>();
    let expression_fields = named_sources
        .iter()
        .zip(&fields)
        .map(|(source, binding)| {
            (
                source.clone(),
                ExpressionAccess::VariantBinding(binding.clone()),
            )
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
        VariantSelector::Predicate(_) => {
            let selector_check =
                predicate_selector_check(ident, variant_name, variant_index, variants);
            if width.is_none() {
                selector_check
            } else {
                let index = variant.tag_index.ok_or_else(|| {
                    variant
                        .variant
                        .span()
                        .error("Predicate-tagged variants require a tag field.")
                })?;
                let tag_field = fields[index].clone();
                quote_spanned! {variant_name.span() =>
                    let tag = *#tag_field;
                    #selector_check
                    tag.write_to(writer, ctx)?;
                }
            }
        },
    };

    let body = variant
        .fields
        .iter()
        .enumerate()
        .filter(|(_, field)| matches!(field.role, FieldRole::Wire))
        .map(|(index, field)| {
            let access = fields[index].clone();
            generate_for_field(field, quote!(#access), &expression_fields)
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

fn predicate_selector_check(
    enum_ident: &Ident,
    variant_ident: &Ident,
    expected_index: usize,
    variants: &[VariantModel<'_>],
) -> TokenStream {
    let checks = variants
        .iter()
        .enumerate()
        .map(|(index, variant)| {
            let VariantSelector::Predicate(expression) = &variant.selector else {
                return quote!();
            };
            quote! {
                if skrillax_serde_selected.is_none() && (#expression) {
                    skrillax_serde_selected = Some(#index);
                }
            }
        })
        .collect::<Vec<_>>();
    quote! {
        let mut skrillax_serde_selected = None;
        #(#checks)*
        if skrillax_serde_selected != Some(#expected_index) {
            return Err(skrillax_serde::SerializationError::VariantConditionMismatch {
                enum_name: stringify!(#enum_ident),
                variant: stringify!(#variant_ident),
            });
        }
    }
}

#[derive(Clone)]
enum ExpressionAccess {
    SelfField(Ident),
    VariantBinding(Ident),
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
    fields: &'a [(Ident, ExpressionAccess)],
    scopes: Vec<HashSet<String>>,
}

impl ExpressionRewriter<'_> {
    fn is_bound(&self, ident: &Ident) -> bool {
        let name = ident.to_string();
        self.scopes.iter().rev().any(|scope| scope.contains(&name))
    }

    fn rewrite_condition(&mut self, condition: &mut Expr) -> HashSet<String> {
        match condition {
            Expr::Let(binding) => {
                self.visit_expr_mut(&mut binding.expr);
                pattern_bindings(&binding.pat)
            },
            Expr::Binary(binary) if matches!(&binary.op, syn::BinOp::And(_)) => {
                let mut bindings = self.rewrite_condition(&mut binary.left);
                self.scopes.push(bindings.clone());
                bindings.extend(self.rewrite_condition(&mut binary.right));
                self.scopes.pop();
                bindings
            },
            Expr::Paren(parenthesized) => self.rewrite_condition(&mut parenthesized.expr),
            Expr::Group(grouped) => self.rewrite_condition(&mut grouped.expr),
            _ => {
                self.visit_expr_mut(condition);
                HashSet::new()
            },
        }
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
                && let Some((_, access)) = self.fields.iter().find(|(field, _)| field == source)
            {
                let span = source.span();
                *expression = match access {
                    ExpressionAccess::SelfField(field) => {
                        syn::parse_quote_spanned!(span=> self.#field)
                    },
                    ExpressionAccess::VariantBinding(binding) => {
                        syn::parse_quote_spanned!(span=> *#binding)
                    },
                };
                return;
            }
        }
        syn::visit_mut::visit_expr_mut(self, expression);
    }

    fn visit_expr_macro_mut(&mut self, expression: &mut syn::ExprMacro) {
        let Some(mut matches) = MatchesMacro::parse(expression) else {
            syn::visit_mut::visit_expr_macro_mut(self, expression);
            return;
        };

        self.visit_expr_mut(&mut matches.value);
        if let Some((_, guard)) = &mut matches.guard {
            self.scopes.push(pattern_bindings(&matches.pattern));
            self.visit_expr_mut(guard);
            self.scopes.pop();
        }
        expression.mac.tokens = quote!(#matches);
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

    fn visit_expr_if_mut(&mut self, expression: &mut syn::ExprIf) {
        let bindings = self.rewrite_condition(&mut expression.cond);
        self.scopes.push(bindings);
        self.visit_block_mut(&mut expression.then_branch);
        self.scopes.pop();
        if let Some((_, else_branch)) = &mut expression.else_branch {
            self.visit_expr_mut(else_branch);
        }
    }

    fn visit_expr_while_mut(&mut self, expression: &mut syn::ExprWhile) {
        let bindings = self.rewrite_condition(&mut expression.cond);
        self.scopes.push(bindings);
        self.visit_block_mut(&mut expression.body);
        self.scopes.pop();
    }
}

fn rewrite_expression(expression: &Expr, fields: &[(Ident, ExpressionAccess)]) -> Expr {
    let mut expression = expression.clone();
    ExpressionRewriter {
        fields,
        scopes: Vec::new(),
    }
    .visit_expr_mut(&mut expression);
    expression
}

fn width_literal(width: IntegerWidth, value: u64) -> TokenStream {
    let suffix = width.rust_type();
    let literal = syn::LitInt::new(&format!("{value}{suffix}"), proc_macro2::Span::call_site());
    quote!(#literal)
}
