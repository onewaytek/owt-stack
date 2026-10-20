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
check: fmt lint features dev-only test audit templates ci-config image-check

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

# owt-test seals a session for any account, and owt-accounts' `test-util` records a
# policy acceptance for any account id, so no crate of the stack may depend on owt-test, or
# turn `test-util` on, outside `[dev-dependencies]` (the `readme` crate, which is never
# shipped, aside). A failing `cargo tree` fails the recipe.
dev-only:
    #!/usr/bin/env bash
    set -euo pipefail
    tree() { cargo tree --workspace --exclude readme --edges normal,build --locked --prefix none "$@"; }
    users=$(tree -i owt-test)
    users=$(grep -v '^owt-test ' <<<"$users" || true)
    if [ -n "$users" ]; then
        echo "owt-test is a normal or build dependency of:" >&2
        echo "$users" >&2
        exit 1
    fi
    features=$(tree --exclude owt-test -e features -i owt-accounts)
    if grep -q 'feature "test-util"' <<<"$features"; then
        echo "owt-accounts' test-util is enabled outside dev-dependencies:" >&2
        grep -B1 -A3 'feature "test-util"' <<<"$features" >&2
        exit 1
    fi

# The tests, README doctests included; arguments pass through.
test *args:
    cargo test --workspace --all-features --locked {{ args }}

# No advisories against Cargo.lock (ignored ones are in .cargo/audit.toml, with why).
audit:
    cargo audit --deny warnings

# The deploy and environment scripts against a stand-in `oc` (bash only; no cluster, no Rust).
templates:
    bash templates/openshift/apply-test.sh
    bash templates/openshift/env-test.sh

# The commitlint rules conventional-commits.yml writes for an app without its own are
# commitlint.config.mjs, byte for byte.
ci-config:
    diff -u commitlint.config.mjs <(sed -n "/<<'JS'$/,/^ *JS$/p" .github/workflows/conventional-commits.yml | sed '1d;$d' | sed 's/^          //')

# image-check.yml's `build` and `verify` jobs are image.yml's: `build` but for the
# release's version and tag checkout, `verify` byte for byte.
image-check:
    #!/usr/bin/env bash
    set -euo pipefail
    job() {
        local out
        out="$(awk -v j="  $2:" '$0 == j {on=1; print; next} on && /^  [^ ]/ {exit} on' ".github/workflows/$1")"
        [ -n "$out" ] || { echo "no job $2 in $1" >&2; exit 1; }
        printf '%s\n' "$out"
    }
    # Without what differs by design: the release's version and its tag checkout (two
    # steps), the commit output, and image-check.yml's own checkout.
    build() {
        job "$1" build | sed -e '/^    outputs:$/,/^      commit:/d' -e '/RAW_VERSION/d' \
            -e '/^      # The event.s own checkout/,/^          persist-credentials: false$/d' \
            -e '/^      - name: Resolve version$/,/^          echo "VERSION=${VERSION}" >> "$GITHUB_ENV"$/d' \
            -e '/^      # The ref is qualified/,/^          persist-credentials: false$/d'
    }
    b1="$(build image.yml)"
    b2="$(build image-check.yml)"
    v1="$(job image.yml verify)"
    v2="$(job image-check.yml verify)"
    diff -u <(printf '%s\n' "$b1") <(printf '%s\n' "$b2")
    diff -u <(printf '%s\n' "$v1") <(printf '%s\n' "$v2")
