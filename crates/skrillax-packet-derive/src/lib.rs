use darling::FromDeriveInput;
use proc_macro::TokenStream;
use proc_macro_error::{abort, proc_macro_error};
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

#[derive(FromDeriveInput)]
#[darling(attributes(packet))]
pub(crate) struct PacketArgs {
    opcode: u16,
    encrypted: Option<bool>,
    massive: Option<bool>,
}

#[proc_macro_error]
#[proc_macro_derive(Packet, attributes(packet))]
pub fn derive_deserialize(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input);
    let args = PacketArgs::from_derive_input(&input).unwrap();
    if args.massive.unwrap_or(false) && args.encrypted.unwrap_or(false) {
        abort!(input, "Packet can't be both encrypted and massive.");
    }

    let DeriveInput { ident, .. } = input;

    let opcode = args.opcode;
    let name = format!("{}", ident);
    let massive = args.massive.unwrap_or(false);
    let encrypted = args.encrypted.unwrap_or(false);

    let output = quote! {
        impl ::skrillax_packet::Packet for #ident {
            const ID: u16 = #opcode;
            const NAME: &'static str = #name;
            const MASSIVE: bool = #massive;
            const ENCRYPTED: bool = #encrypted;
        }
    };

    output.into()
}
