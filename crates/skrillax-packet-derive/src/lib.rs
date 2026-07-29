use darling::FromDeriveInput;
use proc_macro::TokenStream;
use proc_macro2_diagnostics::{Diagnostic, SpanDiagnosticExt};
use quote::quote;
use syn::DeriveInput;
use syn::spanned::Spanned;

#[derive(FromDeriveInput)]
#[darling(attributes(packet))]
pub(crate) struct PacketArgs {
    opcode: u16,
    encrypted: Option<bool>,
    massive: Option<bool>,
}

#[proc_macro_derive(Packet, attributes(packet))]
pub fn derive_deserialize(input: TokenStream) -> TokenStream {
    expand_packet(input.into())
        .unwrap_or_else(Diagnostic::emit_as_item_tokens)
        .into()
}

fn expand_packet(input: proc_macro2::TokenStream) -> Result<proc_macro2::TokenStream, Diagnostic> {
    let input: DeriveInput = syn::parse2(input)?;
    let args = PacketArgs::from_derive_input(&input)
        .map_err(|_| input.span().error("Failed to parse packet arguments."))?;

    if args.massive.unwrap_or(false) && args.encrypted.unwrap_or(false) {
        return Err(input
            .span()
            .error("Packet can't be both encrypted and massive."));
    }

    let DeriveInput { ident, .. } = input;

    let opcode = args.opcode;
    let name = format!("{ident}");
    let massive = args.massive.unwrap_or(false);
    let encrypted = args.encrypted.unwrap_or(false);

    Ok(quote! {
        impl ::skrillax_packet::Packet for #ident {
            const ID: u16 = #opcode;
            const NAME: &'static str = #name;
            const MASSIVE: bool = #massive;
            const ENCRYPTED: bool = #encrypted;
        }
    })
}
