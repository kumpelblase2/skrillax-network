# Changelog
## [0.3.0](https://github.com/kumpelblase2/skrillax-network/compare/skrillax-stream-v0.2.0...skrillax-stream-v0.3.0) - 2026-08-17


- Expose handshake packets

- Cover zero-progress packet decoders

- Limit size of collections when deserializing

- Limit logical packet resources on reframing

- Avoid expect/unwrap in most cases

- Reject unrepresentable frame lengths

- Harden handshake arithmetic against malformed peers

- Complete zero-container massive packets

- Enforce coherent derived wire semantics

- Prevent packet output after serialization failures

- Unify derivation model and make serialization fallible

- Honor selected handshake security features

- Update to 2024 edition and resolve lints

- Carry opcode in dynamic packet

- Provide a bit more documentation on new types

- Pivot to using a more dynamic approach to handling packets

- Clean up dependencies and update them

- Apply remaining clippy lints

- Allow for stateful parsing for request-response operations

- Address warnings

- Remove unnecessary dependencies from crates

- Slightly improve wording of documentation

- Mark crates as version independent

- Bump tokio from 1.37.0 to 1.42.0
