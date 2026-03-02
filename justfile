default:
    cargo check

doc:
    cargo doc --no-deps

test:
    cargo nextest run && cargo test --doc

fmt:
    cargo +nightly fmt

bench:
    cargo bench --bench serde_bench --all-features
