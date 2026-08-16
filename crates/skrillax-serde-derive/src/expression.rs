use proc_macro2::TokenStream;
use quote::{ToTokens, quote};
use syn::parse::{Parse, ParseStream};
use syn::{Expr, ExprMacro, Pat, Result, Token};

pub(crate) struct MatchesMacro {
    pub(crate) value: Expr,
    comma: Token![,],
    pub(crate) pattern: Pat,
    pub(crate) guard: Option<(Token![if], Expr)>,
    trailing_comma: Option<Token![,]>,
}

impl MatchesMacro {
    pub(crate) fn parse(expression: &ExprMacro) -> Option<Self> {
        let is_matches = expression
            .mac
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "matches");
        is_matches
            .then(|| syn::parse2(expression.mac.tokens.clone()).ok())
            .flatten()
    }
}

impl Parse for MatchesMacro {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        Ok(Self {
            value: input.parse()?,
            comma: input.parse()?,
            pattern: input.call(Pat::parse_multi_with_leading_vert)?,
            guard: if input.peek(Token![if]) {
                Some((input.parse()?, input.parse()?))
            } else {
                None
            },
            trailing_comma: input.parse()?,
        })
    }
}

impl ToTokens for MatchesMacro {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let Self {
            value,
            comma,
            pattern,
            guard,
            trailing_comma,
        } = self;
        let guard = guard
            .as_ref()
            .map(|(if_token, expression)| quote!(#if_token #expression));
        tokens.extend(quote!(#value #comma #pattern #guard #trailing_comma));
    }
}
