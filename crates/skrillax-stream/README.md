# skrillax-stream

[![Crates.io](https://img.shields.io/crates/v/skrillax-stream.svg)](https://crates.io/crates/skrillax-stream)
[![Docs.rs](https://docs.rs/skrillax-stream/badge.svg)](https://docs.rs/skrillax-stream)

This is the high-level (tcp) stream implementation for working with Silkroad Online connections. It is built on top
of the other crates (`skrillax-packet`, `skrillax-codec`, `skrillax-serde`, `skrillax-security`) from the
[`skrillax-network`](https://git.eternalwings.de/tim/skrillax-network) family of creates.
Additionally, it provides the initialization handshake for both the server and client party, whichever applies.

## Receiver limits

Streams created with `SilkroadTcpExt::into_silkroad_stream` accept at most
`DEFAULT_MAX_COLLECTION_ELEMENTS` (currently 10,000) elements in each decoded
collection. This conservative network-facing default prevents an untrusted
length prefix from requesting an unbounded allocation while preserving direct
`skrillax-serde` compatibility for callers that deserialize trusted data.

The policy is per collection, not cumulative, and it does not replace the
separate frame-count and payload-byte limits used while reframing logical
packets. Applications should choose a lower or higher limit to match their
packet models before reading:

```rust
use skrillax_serde::DeserializationLimits;

# fn configure<T: tokio::io::AsyncRead + Unpin>(
#     reader: &skrillax_stream::stream::SilkroadStreamRead<T>,
# ) {
reader.context().set_deserialization_limits(
    DeserializationLimits::with_max_collection_elements(2_000),
);
# }
```

For compatibility with peers that legitimately use the protocol's full count
range, call `reader.context().clear_deserialization_limits()` explicitly. This
opt-out permits unbounded per-collection counts and should only be used when a
separate trust boundary or resource policy makes that safe.