#!/usr/bin/env bash
# .githooks/pre-push's commit-message lint against messages commitlint passes and
# refuses under commitlint.config.mjs. Bash only.
set -euo pipefail
cd "$(dirname "$0")/.."
hook=.githooks/pre-push
fail=0
check() {
    local want=$1 msg=$2 got=pass
    printf '%s' "$msg" | "$hook" --lint >/dev/null || got=refuse
    if [ "$got" != "$want" ]; then
        echo "pre-push-test: expected $want, got $got: ${msg%%$'\n'*}" >&2
        fail=1
    fi
}
long=$(printf 'x%.0s' $(seq 1 200))
check pass "fix(web): drop the stale header"
check pass "feat!: rename the session cookie"
check pass "fix(deploy): PUBLIC_URL comes only from the params file"
check pass "fix(web): \`Sessions::from_env\` reads the key once"
check pass "refactor(accounts): S3 uploads stream"
check pass "fix: a subject"$'\n\n'"$long"
check pass "Merge branch 'main' of github.com:o/r into fix/x"
check pass "Merge origin/main"
check pass "bump things"$'\n\n'"Signed-off-by: dependabot[bot] <support@github.com>"
check pass "fix: $(printf 'y%.0s' $(seq 1 110))"
check refuse "fix: $(printf 'y%.0s' $(seq 1 116))"
check refuse "nav: move the menu"
check refuse "fix(web): Drop the stale header"
check refuse "fix: ALL CAPS HERE"
check refuse "fix: a subject."
check refuse "fix:"
check refuse "fix(Web): drop it"
check refuse "drop the stale header"
check refuse "Merge pull request #1 from o/x"
check refuse "Merge branch 'main' and more"
exit "$fail"
