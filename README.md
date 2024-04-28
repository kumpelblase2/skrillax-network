# Skrillax Network

Skrillax Network is the Client-Server networking I'm using in my [Skrillax](https://github.com/kumpelblase2/skrillax)
project. This is a layer on top of tokio for both client and server to talk the same
protocol [Silkroad Online](https://joymax.com/silkroad) uses. It is composed of multiple layers that stack on top of
each other, but it's possible to use lower layers independently if desired. Skrillax Network comprises the following
individual crates:

- __skrillax-serde__: Serialization/Deserialization of data for silkroad. This is essentially serde with Silkroad only
  specific routines. Similarly to serde, this also contains an automatic derivation feature.
- __skrillax-packet__: Primitive (with automatic derivation) for defining full packets. A packet still needs to be
  serializable to be useful.
- __skrillax-codec__: Tokio Codec to frame a TPC stream into Silkroad Online frames.
- __skrillax-stream__: Using `skrillax-code`, `skrillax-packet`, and `skrillax-serde` to build a complete stream to
  easily read and write full packets in the format expected by Silkroad Online and establish a secured connection
  through a proper handshake.

Notably, this does not contain any specific packets, apart from the security handshake, for Silkroad Online. Given the
protocol constantly changes, as well as trying to allow multiple protocol versions to be used by users of this
crate/these crates, it was decided to keep the actual protocol away. 
