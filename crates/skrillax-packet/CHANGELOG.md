# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0](https://github.com/kumpelblase2/skrillax-network/compare/skrillax-packet-v0.3.0...skrillax-packet-v0.4.0) - 2026-08-17

### Other

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
