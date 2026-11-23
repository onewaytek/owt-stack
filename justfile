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
check: fmt audit lint features dev-only test templates ci-config image-check

# Formatting, checked rather than applied.
fmt:
    cargo fmt --check

# Clippy over every crate and feature, warnings fatal.
lint:
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

# The builds `lint` cannot see: a crate without its default features (owt-auth without
# `jwt` is how owt-accounts builds it), and owt-accounts without `passkeys`, which must
# neither build nor link webauthn-rs and must still pass its own tests (`test` runs them
# with every feature).
features:
    cargo clippy -p owt-change --all-targets --no-default-features --locked -- -D warnings
    cargo clippy -p owt-auth --all-targets --no-default-features --locked -- -D warnings
    cargo clippy -p owt-accounts --all-targets --locked -- -D warnings
    ! cargo tree -p owt-accounts --edges normal,build --locked --prefix none | grep -q '^webauthn-rs '
    cargo test -p owt-accounts --locked

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

# No advisories against any tracked lockfile, fuzz/'s and tests/image-sample/'s too (the
# ignored ones are in .cargo/audit.toml, with why). It compiles nothing, so `check` runs it
# second, before anything that builds.
audit:
    #!/usr/bin/env bash
    set -euo pipefail
    # safe.directory: in a CI container the checkout's owner need not be the user.
    locks=$(git -c safe.directory="$PWD" ls-files '*Cargo.lock')
    [ -n "$locks" ] || { echo "no tracked Cargo.lock to audit" >&2; exit 1; }
    status=0
    while IFS= read -r lock; do
        echo "cargo audit --file $lock"
        cargo audit --deny warnings --file "$lock" || status=1
    done <<<"$locks"
    exit "$status"

# The deploy and environment scripts against a stand-in `oc`, and the workflows' shell
# (bash and git only; no cluster, no network, no Rust).
templates:
    bash templates/openshift/apply-test.sh
    bash templates/openshift/env-test.sh
    bash scripts/bao-set-test.sh
    bash scripts/deploy-pin-test.sh
    bash scripts/housekeeping-test.sh
    bash scripts/rust-ci-test.sh

# charts/owt-app renders what templates/openshift renders, fixture by fixture, and its
# schema refuses what it must (needs oc, helm, yq and jq; no cluster, no Rust). Not in
# `check`: chart.yml runs it on GitHub-hosted runners with the tools pinned.
chart *cases:
    bash charts/owt-app/tests/render-equivalence.sh {{ cases }}

# The commitlint rules conventional-commits.yml writes for an app without its own are
# commitlint.config.mjs, byte for byte; the Renovate preset reads every digest pin it
# should (scripts/renovate-test.sh).
ci-config:
    diff -u commitlint.config.mjs <(sed -n "/<<'JS'$/,/^ *JS$/p" .github/workflows/conventional-commits.yml | sed '1d;$d' | sed 's/^          //')
    bash scripts/renovate-test.sh

# image-check.yml's `build` and `scan` jobs are image.yml's: `build` but for the
# release's version and tag checkout, `scan` but for its checkout's ref and comments.
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
        job "$1" build | sed -e '/^      # Recorded by the checkout/d' -e '/^      commit: /d' -e '/RAW_VERSION/d' \
            -e '/^      # The event.s own checkout/,/^          persist-credentials: false$/d' \
            -e '/^      - name: Resolve version$/,/^          echo "VERSION=${VERSION}" >> "$GITHUB_ENV"$/d' \
            -e '/^      # The ref is qualified/,/^          persist-credentials: false$/d'
    }
    b1="$(build image.yml)"
    b2="$(build image-check.yml)"
    # The scan job checks out the ignore file at the build's commit in image.yml and at
    # the event's merge commit in image-check.yml; the head comments differ by design.
    scan() {
        job "$1" scan | sed -e '/^      # Only for the ignore file; /d' \
            -e '/^          ref: .*needs\.build\.outputs\.commit/d'
    }
    v1="$(scan image.yml)"
    v2="$(scan image-check.yml)"
    diff -u <(printf '%s\n' "$b1") <(printf '%s\n' "$b2")
    diff -u <(printf '%s\n' "$v1") <(printf '%s\n' "$v2")
    # A staging tag can be moved by any build (Quay's write permission includes it), so
    # every read from the staging registry names a digest: each crane call on
    # `${staging}` is `${staging}@${...}`, and the only call on STAGING_REGISTRY itself
    # is the build job's push and its login.
    for f in image.yml image-check.yml; do
        bad="$(grep -nE 'crane [a-z]+ .*\$\{?staging' ".github/workflows/$f" | grep -vE '"\$\{staging\}@\$\{[A-Za-z_]+\}"' || true)"
        bad+="$(grep -nE 'crane [a-z]+ .*STAGING_REGISTRY' ".github/workflows/$f" | grep -vE 'crane auth login "\$\{STAGING_REGISTRY%%/\*\}"' || true)"
        bad+="$(grep -nE '^ *-t "\$\{STAGING_REGISTRY\}' ".github/workflows/$f" | grep -vE ':run-\$\{GITHUB_RUN_ID\}-' || true)"
        [ -z "$bad" ] || { echo "$f: staging registry read not by digest:" >&2; echo "$bad" >&2; exit 1; }
        n="$(grep -c 'crane manifest "${staging}@${STAGED}"' ".github/workflows/$f")"
        [ "$n" -ge 1 ] || { echo "$f: no digest fetch of the staged layer" >&2; exit 1; }
    done
