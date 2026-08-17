# Changelog
## [0.4.0](https://github.com/kumpelblase2/skrillax-network/compare/skrillax-packet-v0.3.0...skrillax-packet-v0.4.0) - 2026-08-17


- Return unconsumed frames after packet reframing

- Limit logical packet resources on reframing

- Avoid expect/unwrap in most cases

- Reject unrepresentable frame lengths

- Reject malformed massive framing metadata

- Align massive container integrity checks

- Fix missing serde config for traits using serde context

- Complete zero-container massive packets

- Enforce coherent derived wire semantics

- Prevent packet output after serialization failures

- Unify derivation model and make serialization fallible

- Preserve complete massive packet payloads

- Reject malformed frames without panicking

- Update to 2024 edition and resolve lints

- Pivot to using a more dynamic approach to handling packets

- Allow for stateful parsing for request-response operations

- Address warnings

- Remove unnecessary dependencies from crates

- Slightly improve wording of documentation

- Mark crates as version independent
