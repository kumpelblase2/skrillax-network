# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.2](https://github.com/kumpelblase2/skrillax-network/compare/skrillax-codec-v0.1.1...skrillax-codec-v0.1.2) - 2026-08-17

### Other

- Reject unrepresentable frame lengths
- Reject malformed massive framing metadata
- Align massive container integrity checks
- Complete zero-container massive packets
- Preserve complete massive packet payloads
- Reject malformed frames without panicking
- Update to 2024 edition and resolve lints
- Clean up dependencies and update them
- Slightly improve wording of documentation
- Mark crates as version independent
- Bump tokio-util from 0.7.10 to 0.7.13
- Add rustfmt for more consistent formatting
