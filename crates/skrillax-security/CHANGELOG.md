# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/kumpelblase2/skrillax-network/compare/skrillax-security-v0.1.0...skrillax-security-v0.2.0) - 2026-08-17

### Other

- Update rand, blowfish, and criterion
- Avoid expect/unwrap in most cases
- More strict cargo deny rules
- Harden handshake arithmetic against malformed peers
- Update to 2024 edition and resolve lints
- Clean up dependencies and update them
- Allow enums to have more complex conditions based on their own fields
- Address warnings
- Remove unnecessary dependencies from crates
- Mark crates as version independent
- More dependency updates
- Do not store checksum table on stack
- Add rustfmt for more consistent formatting
- Correct invalid reference to blowfish after removal
- Do not assert inequality in counter doc
