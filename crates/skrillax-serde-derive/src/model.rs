use darling::{FromAttributes, FromDeriveInput};
use proc_macro2::{Ident, Span};
use proc_macro2_diagnostics::{Diagnostic, SpanDiagnosticExt};
use syn::spanned::Spanned;
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
        element: Box<WireType<'a>>,
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

pub(crate) struct WireModel<'a> {
    pub(crate) ident: &'a Ident,
    pub(crate) data: DataModel<'a>,
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
}

pub(crate) fn normalize(
    input: &DeriveInput,
    operation: DeriveOperation,
) -> Result<WireModel<'_>, Diagnostic> {
    let args = SilkroadArgs::from_derive_input(input)
        .map_err(|_| input.span().error("Failed to parse silkroad arguments."))?;
    let ident = &input.ident;

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
            DataModel::Struct(StructModel { data, fields })
        },
        Data::Enum(data) => DataModel::Enum(normalize_enum(data, args.size, operation)?),
        Data::Union(data) => {
            return Err(data.union_token.span().error("Unions are not supported."));
        },
    };

    Ok(WireModel { ident, data })
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
                _ => return Err(field.span().error("Unknown String length")),
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
            element: Box::new(classify_type(&array.elem)?),
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
            } else if name == "Vec" {
                Ok(WireType::Collection {
                    element: Box::new(classify_generic(path, "collection")?),
                })
            } else if name == "Option" {
                Ok(WireType::Optional {
                    inner: Box::new(classify_generic(path, "option")?),
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
    path.path.segments.last().is_some_and(|segment| {
        segment.ident == expected.rust_type() && matches!(segment.arguments, PathArguments::None)
    })
}
