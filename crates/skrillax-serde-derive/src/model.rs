use crate::expression::MatchesMacro;
use darling::{FromAttributes, FromDeriveInput};
use proc_macro2::{Ident, Span};
use proc_macro2_diagnostics::{Diagnostic, SpanDiagnosticExt};
use std::collections::HashSet;
use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{
    Data, DataEnum, DataStruct, DeriveInput, Expr, Field, GenericArgument, PathArguments, Type,
    Variant,
};

/// The derive operation using the normalized wire description.
#[derive(Clone, Copy, Debug)]
pub(crate) enum DeriveOperation {
    Serialize,
    Deserialize,
    ByteSize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IntegerWidth {
    U8,
    U16,
    U32,
    U64,
}

impl IntegerWidth {
    pub(crate) fn bytes(self) -> usize {
        match self {
            Self::U8 => 1,
            Self::U16 => 2,
            Self::U32 => 4,
            Self::U64 => 8,
        }
    }

    pub(crate) fn max_value(self) -> u64 {
        match self {
            Self::U8 => u8::MAX.into(),
            Self::U16 => u16::MAX.into(),
            Self::U32 => u32::MAX.into(),
            Self::U64 => u64::MAX,
        }
    }

    pub(crate) fn rust_type(self) -> &'static str {
        match self {
            Self::U8 => "u8",
            Self::U16 => "u16",
            Self::U32 => "u32",
            Self::U64 => "u64",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum StringEncoding {
    Utf8,
    Utf16,
}

#[derive(Clone, Debug)]
pub(crate) enum SequenceFraming {
    Counted { width: IntegerWidth },
    Break { marker_width: IntegerWidth },
    HasMore { marker_width: IntegerWidth },
    Calculated { expression: Expr },
}

#[derive(Clone, Debug)]
pub(crate) enum Presence {
    Explicit { width: IntegerWidth },
    Conditional { expression: Expr },
    Bare,
}

#[derive(Clone, Debug)]
pub(crate) enum FieldRole {
    Wire,
    Synthetic { expression: Expr },
    EnumTag,
}

/// A field's direct wire kind. Framing and presence live on the field model,
/// rather than on this recursive type, because they are supplied by field
/// attributes and cannot be inferred for arbitrary nested values.
#[derive(Clone, Debug)]
pub(crate) enum WireType<'a> {
    Delegated(&'a Type),
    String,
    Array {
        element_type: &'a Type,
        length: &'a Expr,
    },
    Collection {
        element: Box<WireType<'a>>,
    },
    Optional {
        inner: Box<WireType<'a>>,
    },
    Tuple(Vec<WireType<'a>>),
}

pub(crate) struct FieldModel<'a> {
    pub(crate) field: &'a Field,
    pub(crate) kind: WireType<'a>,
    pub(crate) role: FieldRole,
    pub(crate) string_encoding: Option<StringEncoding>,
    pub(crate) framing: Option<SequenceFraming>,
    pub(crate) presence: Option<Presence>,
    pub(crate) is_tag: bool,
}

pub(crate) struct StructModel<'a> {
    pub(crate) data: &'a DataStruct,
    pub(crate) fields: Vec<FieldModel<'a>>,
}

#[derive(Clone, Debug)]
pub(crate) enum VariantSelector {
    Fixed(u64),
    Predicate(Expr),
}

pub(crate) struct VariantModel<'a> {
    pub(crate) variant: &'a Variant,
    pub(crate) fields: Vec<FieldModel<'a>>,
    pub(crate) selector: VariantSelector,
    pub(crate) tag_index: Option<usize>,
}

pub(crate) struct EnumModel<'a> {
    pub(crate) width: Option<IntegerWidth>,
    pub(crate) variants: Vec<VariantModel<'a>>,
}

pub(crate) enum DataModel<'a> {
    Struct(StructModel<'a>),
    Enum(EnumModel<'a>),
}

#[derive(Default)]
pub(crate) struct Hooks {
    pub(crate) before_serialize: Option<syn::ExprPath>,
    pub(crate) after_serialize: Option<syn::ExprPath>,
    pub(crate) before_deserialize: Option<syn::ExprPath>,
    pub(crate) after_deserialize: Option<syn::ExprPath>,
}

pub(crate) struct WireModel<'a> {
    pub(crate) ident: &'a Ident,
    pub(crate) data: DataModel<'a>,
    pub(crate) hooks: Hooks,
}

#[derive(FromAttributes, Default)]
#[darling(attributes(silkroad))]
pub(crate) struct FieldArgs {
    pub(crate) list_type: Option<String>,
    pub(crate) size: Option<usize>,
    pub(crate) value: Option<u64>,
    pub(crate) when: Option<String>,
    pub(crate) calculate: Option<String>,
    #[darling(default)]
    pub(crate) tag: bool,
}

#[derive(FromDeriveInput)]
#[darling(attributes(silkroad))]
pub(crate) struct SilkroadArgs {
    pub(crate) size: Option<usize>,
    pub(crate) before_serialize: Option<String>,
    pub(crate) after_serialize: Option<String>,
    pub(crate) before_deserialize: Option<String>,
    pub(crate) after_deserialize: Option<String>,
}

pub(crate) fn normalize(
    input: &DeriveInput,
    operation: DeriveOperation,
) -> Result<WireModel<'_>, Diagnostic> {
    let args = SilkroadArgs::from_derive_input(input)
        .map_err(|_| input.span().error("Failed to parse silkroad arguments."))?;
    let ident = &input.ident;
    let hooks = Hooks {
        before_serialize: parse_hook(args.before_serialize, ident.span(), "before_serialize")?,
        after_serialize: parse_hook(args.after_serialize, ident.span(), "after_serialize")?,
        before_deserialize: parse_hook(
            args.before_deserialize,
            ident.span(),
            "before_deserialize",
        )?,
        after_deserialize: parse_hook(args.after_deserialize, ident.span(), "after_deserialize")?,
    };

    let data = match &input.data {
        Data::Struct(data) => {
            if args.size.is_some() {
                return Err(ident
                    .span()
                    .error("Container `size` is only valid on enums."));
            }
            let fields = data
                .fields
                .iter()
                .map(|field| normalize_field(field, operation, false, None))
                .collect::<Result<Vec<_>, _>>()?;
            validate_field_expression_order(&fields, operation)?;
            DataModel::Struct(StructModel { data, fields })
        },
        Data::Enum(data) => DataModel::Enum(normalize_enum(data, args.size, operation)?),
        Data::Union(data) => {
            return Err(data.union_token.span().error("Unions are not supported."));
        },
    };

    Ok(WireModel { ident, data, hooks })
}

fn parse_hook(
    value: Option<String>,
    span: Span,
    attribute: &'static str,
) -> Result<Option<syn::ExprPath>, Diagnostic> {
    value
        .map(|value| {
            syn::parse_str(&value).map_err(|_| {
                span.error(format!(
                    "`{attribute}` must contain a valid Rust function path."
                ))
            })
        })
        .transpose()
}

fn normalize_enum(
    data: &DataEnum,
    size: Option<usize>,
    operation: DeriveOperation,
) -> Result<EnumModel<'_>, Diagnostic> {
    let width = match size.unwrap_or(1) {
        0 => None,
        value => Some(integer_width(
            value,
            data.enum_token.span(),
            "enum discriminant",
        )?),
    };

    let mut variants = Vec::with_capacity(data.variants.len());
    for variant in &data.variants {
        let args = parse_attrs(&variant.attrs, variant.span(), "variant")?;
        if args.size.is_some() || args.list_type.is_some() || args.calculate.is_some() || args.tag {
            return Err(variant
                .span()
                .error("Variant attributes may use only `value` or `when` as an enum selector."));
        }
        let selector = match width {
            None => {
                if args.value.is_some() {
                    return Err(variant.span().error(
                        "Zero-width enum variants cannot use `value`; use `when` instead.",
                    ));
                }
                VariantSelector::Predicate(parse_expr(
                    args.when.ok_or_else(|| {
                        variant.span().error("Missing condition for enum variant.")
                    })?,
                    variant.span(),
                    "Condition",
                )?)
            },
            Some(width) => match (args.value, args.when) {
                (Some(value), None) => {
                    if value > width.max_value() {
                        return Err(variant.span().error(format!(
                            "Variant value {value} does not fit in a {}-byte discriminant.",
                            width.bytes()
                        )));
                    }
                    VariantSelector::Fixed(value)
                },
                (None, Some(condition)) => {
                    VariantSelector::Predicate(parse_expr(condition, variant.span(), "Condition")?)
                },
                (Some(_), Some(_)) => {
                    return Err(variant
                        .span()
                        .error("A variant cannot use both `value` and `when`."));
                },
                (None, None) => {
                    return Err(variant
                        .span()
                        .error("When size is not zero, either value or when should be set."));
                },
            },
        };

        let predicate = matches!(selector, VariantSelector::Predicate(_));
        let fields = variant
            .fields
            .iter()
            .map(|field| normalize_field(field, operation, predicate, width))
            .collect::<Result<Vec<_>, _>>()?;
        let tag_indices = fields
            .iter()
            .enumerate()
            .filter_map(|(index, field)| field.is_tag.then_some(index))
            .collect::<Vec<_>>();

        if predicate && width.is_some() && tag_indices.len() != 1 {
            return Err(variant
                .span()
                .error("Predicate-tagged variants require exactly one field marked with `tag`."));
        }
        if predicate && width.is_none() && !tag_indices.is_empty() {
            return Err(variant
                .span()
                .error("Zero-width enum variants cannot use field-level `tag`."));
        }
        if !predicate && !tag_indices.is_empty() {
            return Err(variant
                .span()
                .error("`tag` fields are only valid on predicate-tagged variants."));
        }
        if let Some(index) = tag_indices.first().copied() {
            let expected = width.expect("tagged variants have a nonzero width");
            let tag_field = variant
                .fields
                .iter()
                .nth(index)
                .expect("tag index must refer to a variant field");
            if !is_unsigned_primitive(&tag_field.ty, expected) {
                return Err(tag_field.span().error(format!(
                    "Tag field must have type {} for a {}-byte enum discriminant.",
                    expected.rust_type(),
                    expected.bytes()
                )));
            }
        }

        validate_field_expression_order(&fields, operation)?;
        if let VariantSelector::Predicate(expression) = &selector {
            validate_enum_predicate(expression, &fields, variant, width)?;
        }

        variants.push(VariantModel {
            variant,
            fields,
            selector,
            tag_index: tag_indices.first().copied(),
        });
    }

    let predicate_count = variants
        .iter()
        .filter(|variant| matches!(variant.selector, VariantSelector::Predicate(_)))
        .count();
    if predicate_count != 0 && predicate_count != variants.len() {
        return Err(data.enum_token.span().error(
            "An enum must use fixed `value` selectors or predicate `when` selectors consistently.",
        ));
    }

    let mut fixed_values = Vec::new();
    for variant in &variants {
        if let VariantSelector::Fixed(value) = variant.selector {
            if fixed_values.contains(&value) {
                return Err(variant
                    .variant
                    .span()
                    .error(format!("Duplicate fixed variant value {value}.")));
            }
            fixed_values.push(value);
        }
    }

    Ok(EnumModel { width, variants })
}

fn normalize_field(
    field: &Field,
    operation: DeriveOperation,
    allow_tag: bool,
    enum_width: Option<IntegerWidth>,
) -> Result<FieldModel<'_>, Diagnostic> {
    let args = parse_attrs(&field.attrs, field.span(), "field")?;
    let kind = classify_type(&field.ty)?;
    let is_collection = matches!(kind, WireType::Collection { .. });
    let is_option = matches!(kind, WireType::Optional { .. });

    if args.tag && !allow_tag {
        return Err(field
            .span()
            .error("Tagged fields are not supported for structs or fixed enum variants."));
    }

    if args.value.is_some() {
        return Err(field
            .span()
            .error("`value` is only valid on enum variants."));
    }
    if args.when.is_some() && !is_option {
        return Err(field.span().error("`when` is only valid on Option fields."));
    }
    if args.list_type.is_some() && !is_collection {
        return Err(field
            .span()
            .error("`list_type` is only valid on collection fields."));
    }
    if args.calculate.is_some() && is_option {
        return Err(field.span().error(
            "`calculate` is not valid on Option fields; use `when` for conditional presence.",
        ));
    }
    if args.calculate.is_some() && is_collection && args.list_type.as_deref() != Some("calculated")
    {
        return Err(field
            .span()
            .error("A collection `calculate` expression requires `list_type = \"calculated\"`."));
    }
    if args.calculate.is_some() && !is_collection && args.when.is_some() {
        return Err(field
            .span()
            .error("A calculated scalar field cannot also use `when`."));
    }
    if args.calculate.is_some()
        && !is_collection
        && (args.tag || args.list_type.is_some() || args.size.is_some())
    {
        return Err(field
            .span()
            .error("A calculated scalar field cannot use `tag`, `list_type`, or `size`."));
    }
    if args.calculate.is_some() && is_collection && args.size.is_some() {
        return Err(field
            .span()
            .error("A calculated collection cannot use `size`; it has no local prefix."));
    }

    let condition = args
        .when
        .map(|value| parse_expr(value, field.span(), "Condition"))
        .transpose()?;
    let calculation = args
        .calculate
        .clone()
        .map(|value| parse_expr(value, field.span(), "Calculation"))
        .transpose()?;

    let (string_encoding, framing, presence, role) = match &kind {
        WireType::String => {
            let encoding = match args.size.unwrap_or(1) {
                1 => StringEncoding::Utf8,
                2 => StringEncoding::Utf16,
                invalid => {
                    return Err(field.span().error(format!(
                        "Invalid String size {invalid}; expected 1 for UTF-8 or 2 for UTF-16."
                    )));
                },
            };
            (
                Some(encoding),
                None,
                None,
                calculation
                    .clone()
                    .map(|expression| FieldRole::Synthetic { expression })
                    .unwrap_or(FieldRole::Wire),
            )
        },
        WireType::Collection { .. } => {
            let framing_name = args.list_type.as_deref().unwrap_or("length");
            let framing = match framing_name {
                "length" => SequenceFraming::Counted {
                    width: integer_width(args.size.unwrap_or(1), field.span(), "collection")?,
                },
                "break" => SequenceFraming::Break {
                    marker_width: integer_width(
                        args.size.unwrap_or(1),
                        field.span(),
                        "collection marker",
                    )?,
                },
                "has-more" => SequenceFraming::HasMore {
                    marker_width: integer_width(
                        args.size.unwrap_or(1),
                        field.span(),
                        "collection marker",
                    )?,
                },
                "calculated" => SequenceFraming::Calculated {
                    expression: calculation.clone().ok_or_else(|| {
                        field.span().error(
                            "Missing `calculate` attribute for collection of size `calculated`.",
                        )
                    })?,
                },
                _ => {
                    return Err(field.span().error(format!(
                        "Unknown list_type `{framing_name}`; expected `length`, `break`, \
                         `has-more`, or `calculated`."
                    )));
                },
            };
            (None, Some(framing), None, FieldRole::Wire)
        },
        WireType::Optional { .. } => {
            let presence = match condition.clone() {
                Some(expression) => {
                    if let Some(size) = args.size
                        && size != 0
                    {
                        return Err(field.span().error(
                            "Conditional options cannot use a nonzero presence-marker size.",
                        ));
                    }
                    Presence::Conditional { expression }
                },
                None => match args.size.unwrap_or(1) {
                    0 => {
                        if matches!(operation, DeriveOperation::Deserialize) {
                            return Err(field.span().error(
                                "Bare Option fields with `size = 0` require a `when` condition \
                                 for Deserialize.",
                            ));
                        }
                        Presence::Bare
                    },
                    size => Presence::Explicit {
                        width: integer_width(size, field.span(), "option presence")?,
                    },
                },
            };
            (None, None, Some(presence), FieldRole::Wire)
        },
        _ => {
            if args.size.is_some() {
                return Err(field
                    .span()
                    .error("`size` is only valid on String, collection, or Option fields."));
            }
            (
                None,
                None,
                None,
                calculation
                    .map(|expression| FieldRole::Synthetic { expression })
                    .unwrap_or(FieldRole::Wire),
            )
        },
    };

    // A tag aliases the enum discriminant and therefore occupies no body
    // bytes. It is represented explicitly in the model so every emitter can
    // make the same decision.
    let role = if args.tag {
        let _ = enum_width;
        FieldRole::EnumTag
    } else {
        role
    };

    Ok(FieldModel {
        field,
        kind,
        role,
        string_encoding,
        framing,
        presence,
        is_tag: args.tag,
    })
}

fn classify_type(ty: &Type) -> Result<WireType<'_>, Diagnostic> {
    match ty {
        Type::Array(array) => Ok(WireType::Array {
            element_type: &array.elem,
            length: &array.len,
        }),
        Type::Tuple(tuple) => {
            let items = tuple
                .elems
                .iter()
                .map(classify_type)
                .collect::<Result<Vec<_>, _>>()?;
            for item in &items {
                if matches!(
                    item,
                    WireType::String
                        | WireType::Collection { .. }
                        | WireType::Optional { .. }
                        | WireType::Tuple(_)
                ) {
                    return Err(tuple.span().error(
                        "Tuple fields cannot directly contain String, collection, or Option \
                         values; use a wrapper struct instead.",
                    ));
                }
            }
            Ok(WireType::Tuple(items))
        },
        Type::Reference(reference) => Err(reference
            .span()
            .error("References are not supported for (de)serialization.")),
        Type::Path(path) => {
            let name = path
                .path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect::<Vec<_>>()
                .join("::");
            if matches!(
                name.as_str(),
                "String" | "string::String" | "std::string::String"
            ) {
                Ok(WireType::String)
            } else if matches!(
                name.as_str(),
                "Vec" | "vec::Vec" | "std::vec::Vec" | "alloc::vec::Vec"
            ) {
                let element = classify_generic(path, "collection")?;
                validate_container_inner(&element, path.span(), "collection")?;
                Ok(WireType::Collection {
                    element: Box::new(element),
                })
            } else if matches!(
                name.as_str(),
                "Option" | "option::Option" | "std::option::Option" | "core::option::Option"
            ) {
                let inner = classify_generic(path, "option")?;
                validate_container_inner(&inner, path.span(), "option")?;
                Ok(WireType::Optional {
                    inner: Box::new(inner),
                })
            } else {
                Ok(WireType::Delegated(ty))
            }
        },
        _ => Err(ty.span().error("Encountered unknown syn type.")),
    }
}

fn classify_generic<'a>(path: &'a syn::TypePath, kind: &str) -> Result<WireType<'a>, Diagnostic> {
    let arguments = &path
        .path
        .segments
        .last()
        .expect("a non-empty path has a last segment")
        .arguments;
    let argument = match arguments {
        PathArguments::None => {
            return Err(path
                .span()
                .error(format!("Missing generic parameters for {kind} type.")));
        },
        PathArguments::Parenthesized(_) => {
            return Err(path.span().error("Cannot use parenthesized types."));
        },
        PathArguments::AngleBracketed(arguments) => arguments.args.iter().find_map(|argument| {
            if let GenericArgument::Type(ty) = argument {
                Some(ty)
            } else {
                None
            }
        }),
    }
    .ok_or_else(|| {
        path.span()
            .error(format!("Missing generic parameters for {kind} type."))
    })?;
    classify_type(argument)
}

fn validate_container_inner(
    kind: &WireType<'_>,
    span: Span,
    outer: &str,
) -> Result<(), Diagnostic> {
    if matches!(
        kind,
        WireType::Collection { .. } | WireType::Optional { .. } | WireType::Tuple(_)
    ) {
        let article = if outer == "option" { "An" } else { "A" };
        return Err(span.error(format!(
            "{article} {outer} cannot directly contain a collection, Option, or tuple; use a \
             wrapper struct with explicit wire attributes instead."
        )));
    }
    Ok(())
}

fn validate_field_expression_order(
    fields: &[FieldModel<'_>],
    operation: DeriveOperation,
) -> Result<(), Diagnostic> {
    if !matches!(operation, DeriveOperation::Deserialize) {
        return Ok(());
    }

    let positions = fields
        .iter()
        .enumerate()
        .filter_map(|(index, field)| {
            field
                .field
                .ident
                .as_ref()
                .map(|ident| (ident.to_string(), index))
        })
        .collect::<Vec<_>>();

    for (index, field) in fields.iter().enumerate() {
        for expression in field_expressions(field) {
            let paths = free_single_segment_paths(expression);
            if let Some((name, _)) = positions
                .iter()
                .find(|(name, position)| *position >= index && paths.contains(name))
            {
                return Err(field.field.span().error(format!(
                    "Expression for this field references `{name}`, which is not available until \
                     this or a later field is decoded."
                )));
            }
        }
    }
    Ok(())
}

fn validate_enum_predicate(
    expression: &Expr,
    fields: &[FieldModel<'_>],
    variant: &Variant,
    width: Option<IntegerWidth>,
) -> Result<(), Diagnostic> {
    let paths = free_single_segment_paths(expression);
    if width.is_none() && paths.contains("tag") {
        return Err(variant.span().error(
            "Zero-width enum predicates cannot reference `tag`; only `ctx` and external paths are \
             available.",
        ));
    }
    if let Some(name) = fields
        .iter()
        .filter_map(|field| field.field.ident.as_ref())
        .map(ToString::to_string)
        .find(|name| name.as_str() != "tag" && paths.contains(name))
    {
        return Err(variant.span().error(format!(
            "Enum predicate cannot reference variant body field `{name}`; only `tag`, `ctx`, and \
             external paths are available."
        )));
    }
    Ok(())
}

fn field_expressions<'a>(field: &'a FieldModel<'_>) -> Vec<&'a Expr> {
    let mut expressions = Vec::new();
    if let FieldRole::Synthetic { expression } = &field.role {
        expressions.push(expression);
    }
    if let Some(SequenceFraming::Calculated { expression }) = &field.framing {
        expressions.push(expression);
    }
    if let Some(Presence::Conditional { expression }) = &field.presence {
        expressions.push(expression);
    }
    expressions
}

#[derive(Default)]
struct PatternIdentifiers(HashSet<String>);

impl<'ast> Visit<'ast> for PatternIdentifiers {
    fn visit_pat_ident(&mut self, pattern: &'ast syn::PatIdent) {
        self.0.insert(pattern.ident.to_string());
        syn::visit::visit_pat_ident(self, pattern);
    }
}

fn pattern_identifiers(pattern: &syn::Pat) -> HashSet<String> {
    let mut identifiers = PatternIdentifiers::default();
    identifiers.visit_pat(pattern);
    identifiers.0
}

#[derive(Default)]
struct FreePaths {
    paths: HashSet<String>,
    scopes: Vec<HashSet<String>>,
}

impl FreePaths {
    fn is_bound(&self, ident: &Ident) -> bool {
        let name = ident.to_string();
        self.scopes.iter().rev().any(|scope| scope.contains(&name))
    }

    fn visit_condition(&mut self, condition: &Expr) -> HashSet<String> {
        match condition {
            Expr::Let(binding) => {
                self.visit_expr(&binding.expr);
                pattern_identifiers(&binding.pat)
            },
            Expr::Binary(binary) if matches!(&binary.op, syn::BinOp::And(_)) => {
                let mut bindings = self.visit_condition(&binary.left);
                self.scopes.push(bindings.clone());
                bindings.extend(self.visit_condition(&binary.right));
                self.scopes.pop();
                bindings
            },
            Expr::Paren(parenthesized) => self.visit_condition(&parenthesized.expr),
            Expr::Group(grouped) => self.visit_condition(&grouped.expr),
            _ => {
                self.visit_expr(condition);
                HashSet::new()
            },
        }
    }
}

impl<'ast> Visit<'ast> for FreePaths {
    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        if path.qself.is_none()
            && path.path.leading_colon.is_none()
            && path.path.segments.len() == 1
            && !self.is_bound(&path.path.segments[0].ident)
        {
            self.paths.insert(path.path.segments[0].ident.to_string());
        }
        syn::visit::visit_expr_path(self, path);
    }

    fn visit_expr_macro(&mut self, expression: &'ast syn::ExprMacro) {
        let Some(matches) = MatchesMacro::parse(expression) else {
            syn::visit::visit_expr_macro(self, expression);
            return;
        };

        let mut paths = FreePaths {
            paths: HashSet::new(),
            scopes: self.scopes.clone(),
        };
        paths.visit_expr(&matches.value);
        if let Some((_, guard)) = &matches.guard {
            paths.scopes.push(pattern_identifiers(&matches.pattern));
            paths.visit_expr(guard);
        }
        self.paths.extend(paths.paths);
    }

    fn visit_expr_closure(&mut self, closure: &'ast syn::ExprClosure) {
        let bindings = closure
            .inputs
            .iter()
            .flat_map(pattern_identifiers)
            .collect::<HashSet<_>>();
        self.scopes.push(bindings);
        self.visit_expr(&closure.body);
        self.scopes.pop();
    }

    fn visit_block(&mut self, block: &'ast syn::Block) {
        self.scopes.push(HashSet::new());
        for statement in &block.stmts {
            match statement {
                syn::Stmt::Local(local) => {
                    if let Some(initializer) = &local.init {
                        self.visit_expr(&initializer.expr);
                        if let Some((_, diverge)) = &initializer.diverge {
                            self.visit_expr(diverge);
                        }
                    }
                    let bindings = pattern_identifiers(&local.pat);
                    self.scopes
                        .last_mut()
                        .expect("block scope exists")
                        .extend(bindings);
                },
                syn::Stmt::Expr(expression, _) => self.visit_expr(expression),
                syn::Stmt::Item(_) | syn::Stmt::Macro(_) => {},
            }
        }
        self.scopes.pop();
    }

    fn visit_expr_match(&mut self, expression: &'ast syn::ExprMatch) {
        self.visit_expr(&expression.expr);
        for arm in &expression.arms {
            self.scopes.push(pattern_identifiers(&arm.pat));
            if let Some((_, guard)) = &arm.guard {
                self.visit_expr(guard);
            }
            self.visit_expr(&arm.body);
            self.scopes.pop();
        }
    }

    fn visit_expr_for_loop(&mut self, expression: &'ast syn::ExprForLoop) {
        self.visit_expr(&expression.expr);
        self.scopes.push(pattern_identifiers(&expression.pat));
        self.visit_block(&expression.body);
        self.scopes.pop();
    }

    fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
        let bindings = self.visit_condition(&expression.cond);
        self.scopes.push(bindings);
        self.visit_block(&expression.then_branch);
        self.scopes.pop();
        if let Some((_, else_branch)) = &expression.else_branch {
            self.visit_expr(else_branch);
        }
    }

    fn visit_expr_while(&mut self, expression: &'ast syn::ExprWhile) {
        let bindings = self.visit_condition(&expression.cond);
        self.scopes.push(bindings);
        self.visit_block(&expression.body);
        self.scopes.pop();
    }
}

fn free_single_segment_paths(expression: &Expr) -> HashSet<String> {
    let mut paths = FreePaths::default();
    paths.visit_expr(expression);
    paths.paths
}

fn parse_attrs(attrs: &[syn::Attribute], span: Span, kind: &str) -> Result<FieldArgs, Diagnostic> {
    FieldArgs::from_attributes(attrs)
        .map_err(|_| span.error(format!("Could not parse {kind} attributes.")))
}

fn parse_expr(value: String, span: Span, label: &str) -> Result<Expr, Diagnostic> {
    syn::parse_str(&value).map_err(|_| span.error(format!("{label} could not be parsed")))
}

fn integer_width(size: usize, span: Span, kind: &str) -> Result<IntegerWidth, Diagnostic> {
    match size {
        1 => Ok(IntegerWidth::U8),
        2 => Ok(IntegerWidth::U16),
        4 => Ok(IntegerWidth::U32),
        8 => Ok(IntegerWidth::U64),
        _ => Err(span.error(format!(
            "Invalid {kind} width {size}; expected 1, 2, 4, or 8."
        ))),
    }
}

fn is_unsigned_primitive(ty: &Type, expected: IntegerWidth) -> bool {
    let Type::Path(path) = ty else { return false };
    if path.qself.is_some()
        || path
            .path
            .segments
            .iter()
            .any(|segment| !matches!(segment.arguments, PathArguments::None))
    {
        return false;
    }

    let segments = path
        .path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>();
    let primitive = expected.rust_type();
    (path.path.leading_colon.is_none()
        && matches!(segments.as_slice(), [name] if name == primitive))
        || matches!(segments.as_slice(), [root, kind, name]
            if matches!(root.as_str(), "core" | "std")
                && kind == "primitive"
                && name == primitive)
}
