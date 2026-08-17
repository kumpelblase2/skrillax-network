# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0](https://github.com/kumpelblase2/skrillax-network/compare/skrillax-serde-v0.2.0...skrillax-serde-v0.3.0) - 2026-08-17

### Other

- Fix missing rand import change after update
- Update rand, blowfish, and criterion
- Provide easy zero value for silkroad time
- Reject non-canonical boolean bytes
- Limit size of collections when deserializing
- Avoid expect/unwrap in most cases
- More strict cargo deny rules
- Limit collection sizes in deserialization
- Make Silkroad time formats explicit and panic-free
- Enforce coherent derived wire semantics
- Unify derivation model and make serialization fallible
- Update to 2024 edition and resolve lints
- Pivot to using a more dynamic approach to handling packets
- Remove anymap and use simple custom implementation
- Allow removing previously associated values from context
- Migrate to `proc-macro-error2` to avoid duplicate `syn` crates
- Allow for stateful parsing for request-response operations
- Fix incorrect formatting
- Add in a bench test
- Slightly improve wording of documentation
- Mark crates as version independent
- Bump chrono from 0.4.37 to 0.4.38
