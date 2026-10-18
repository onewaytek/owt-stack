# owt-stack's own commands (an app's start from templates/justfile instead).
# `just check` is the gate before every commit, and CI runs it.

set shell := ["bash", "-euo", "pipefail", "-c"]

# List the recipes.
default:
    @just --list --unsorted

# The README's Rust examples run as doctests in `test`; owt-bus's Redis test runs
# when REDIS_URL is set.
#
# Everything that must pass before a commit.
check: fmt lint features test audit templates

# Formatting, checked rather than applied.
fmt:
    cargo fmt --check

# Clippy over every crate and feature, warnings fatal.
lint:
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

# The builds `lint` cannot see: a crate without its default features (owt-auth without
# `jwt` is how owt-accounts builds it).
features:
    cargo clippy -p owt-change --all-targets --no-default-features --locked -- -D warnings
    cargo clippy -p owt-auth --all-targets --no-default-features --locked -- -D warnings

# The tests, README doctests included; arguments pass through.
test *args:
    cargo test --workspace --all-features --locked {{ args }}

# No advisories against Cargo.lock (ignored ones are in .cargo/audit.toml, with why).
audit:
    cargo audit --deny warnings

# The deploy script against a stand-in `oc` (bash only; no cluster, no Rust).
templates:
    bash templates/openshift/apply-test.sh
