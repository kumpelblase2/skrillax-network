# skrillax-security

[![Crates.io](https://img.shields.io/crates/v/skrillax-security.svg)](https://crates.io/crates/skrillax-security)
[![Docs.rs](https://docs.rs/skrillax-security/badge.svg)](https://docs.rs/skrillax-security)

`skrillax-security` is part of the [`skrillax-network`](https://git.eternalwings.de/tim/skrillax-network) family of
crates for handling the network part of communication between a Silkroad Online client and/or server. This crate
specifically deals with the security aspects of a Silkroad Online connection. In particular, the encryption used,
the handshake as well as other security measures like checksum generation.

Malformed peer handshake parameters are rejected with typed `SilkroadSecurityError` values. In particular,
handshake moduli below 2 are rejected rather than reaching modular arithmetic, and full-range `u32` public values
are handled without multiplication overflow.

## Documentation

For documentation, please see the [docs.rs page](https://docs.rs/skrillax-security).

## License

Like the rest of the `skrillax-network` crates, this crate is licensed under the [MIT license](../../LICENSE).