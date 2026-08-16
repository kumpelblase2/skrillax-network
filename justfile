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

prepare-release:
    @GIT_TOKEN="${GIT_TOKEN:-${RELEASE_PLZ_TOKEN:-$(gh auth token)}}" release-plz release-pr

# Publish the release PR after it has been merged and pulled into local master.
publish-release:
    @GIT_TOKEN="${GIT_TOKEN:-${RELEASE_PLZ_TOKEN:-$(gh auth token)}}" release-plz release
