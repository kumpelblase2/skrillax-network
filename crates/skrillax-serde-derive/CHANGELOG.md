# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0](https://github.com/kumpelblase2/skrillax-network/compare/skrillax-serde-derive-v0.2.0...skrillax-serde-derive-v0.3.0) - 2026-08-17

### Other

- Support providing callback hooks for packets directly
- Handle `matches!` macro in `when` expressions
- Honor conditional pattern bindings in derive expressions
- Limit collection sizes in deserialization
- Enforce coherent derived wire semantics
- Unify derivation model and make serialization fallible
- Migrate derive diagnostics to proc-macro2-diagnostics
- Update to 2024 edition and resolve lints
- Bump darling from 0.20.11 to 0.21.3
- Pivot to using a more dynamic approach to handling packets
- Migrate to `proc-macro-error2` to avoid duplicate `syn` crates
- Apply remaining clippy lints
- Implement some negative tests for derive macros
- Allow enums to have more complex conditions based on their own fields
- Allow for stateful parsing for request-response operations
- Address warnings
- Bump darling from 0.20.11 to 0.21.0
- Prefer using `abort!` or `expect` over `unwrap()` in proc macro
- Mark code snippets in derive macro as ignored
- Mark crates as version independent
