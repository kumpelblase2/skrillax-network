default:
    cargo check

doc:
    cargo doc --no-deps

test:
    cargo nextest run && cargo test --doc

fmt:
    cargo +nightly fmt
