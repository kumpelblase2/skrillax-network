# skrillax-stream

[![Crates.io](https://img.shields.io/crates/v/skrillax-stream.svg)](https://crates.io/crates/skrillax-stream)
[![Docs.rs](https://docs.rs/skrillax-stream/badge.svg)](https://docs.rs/skrillax-stream)

This is the high-level (tcp) stream implementation for working with Silkroad Online connections. It is built on top
of the other crates (`skrillax-packet`, `skrillax-codec`, `skrillax-serde`, `skrillax-security`) from the
[`skrillax-network`](https://git.eternalwings.de/tim/skrillax-network) family of creates.
Additionally, it provides the initialization handshake for both the server and client party, whichever applies.