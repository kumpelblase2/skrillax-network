default:
    cargo check

doc:
    cargo doc --no-deps
test:
    cargo nextest run
fmt:
    cargo +nightly fmt
