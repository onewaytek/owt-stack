#!/usr/bin/env bash
# Proves rust-ci.yml's `unbuilt` step (`skip-unbuilt`) in the clone actions/checkout
# makes for it: blobless (`--filter=blob:none`), shallow and sparse, from a local
# origin. Lazy fetches are forbidden (GIT_NO_LAZY_FETCH), as an unauthenticated one is
# in a private repository, so every blob the step reads comes through its own fetch.
# Also: the step gives git the token for the server alone, and a read that fails (no
# origin) runs the checks. `just templates` runs it; it needs bash 4 and git 2.44.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
wf="$here/../.github/workflows"
work=$(mktemp -d)
trap '[ -n "${KEEP:-}" ] || rm -rf "$work"' EXIT
fails=0
check() { if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: want '$3', got '$2'"; fails=$((fails + 1)); fi; }

# The step's `run: |` script, dedented.
awk '
  /^      - id: unbuilt$/ { in_step = 1; next }
  in_step && /^      - / { exit }
  in_step && /^  [a-z]/ { exit }
  in_step && /^        run: \|$/ { in_run = 1; next }
  in_run { sub(/^          /, ""); print }
' "$wf/rust-ci.yml" >"$work/unbuilt.sh"
[ -s "$work/unbuilt.sh" ] || { echo "no unbuilt script found" >&2; exit 1; }

grep -qF 'GIT_CONFIG_KEY_0="http.${GITHUB_SERVER_URL}/.extraHeader"' "$work/unbuilt.sh" && c=yes || c=no
check "unbuilt: git carries the token, for the server only" "$c" yes

export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@t GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@t
src="$work/src"
git init -q -b main "$src"
mkdir -p "$src/src" "$src/docs" "$src/.github/workflows"
printf '# app\n' >"$src/README.md"
printf '# guide\n' >"$src/docs/guide.md"
printf 'pub const G: &str = include_str!("../docs/guide.md");\n' >"$src/src/lib.rs"
printf 'jobs: {ci: {uses: o/s/.github/workflows/rust-ci.yml@x}}\n' >"$src/.github/workflows/ci.yml"
printf 'jobs: {a: {uses: o/s/.github/workflows/actions-cleanup.yml@x}}\n' >"$src/.github/workflows/housekeeping.yml"
git -C "$src" add -A && git -C "$src" commit -qm base
base=$(git -C "$src" rev-parse HEAD)
origin="$work/origin.git"
git clone -q --bare "$src" "$origin"
git -C "$origin" config uploadpack.allowFilter true
git -C "$origin" config uploadpack.allowAnySHA1InWant true

# change <message> <file=content>...: a commit on the base, pushed; prints its sha.
change() {
  local msg=$1 kv; shift
  git -C "$src" checkout -q --detach "$base"
  for kv in "$@"; do printf '%s\n' "${kv#*=}" >"$src/${kv%%=*}"; done
  git -C "$src" commit -qam "$msg"
  git -C "$src" push -q "$origin" "HEAD:refs/heads/$msg"
  git -C "$src" rev-parse HEAD
}
# run <sha>: the step in a fresh checkout-style clone of <sha>, as a push from the base.
run() {
  local co="$work/co"
  rm -rf "$co" && git init -q "$co"
  git -C "$co" remote add origin "file://$origin"
  git -C "$co" -c protocol.version=2 fetch -q --no-tags --filter=blob:none --depth=1 origin "$1"
  git -C "$co" sparse-checkout set .github
  git -C "$co" checkout -q --detach FETCH_HEAD
  : >"$work/output"
  (cd "$co" && GIT_NO_LAZY_FETCH=1 TOKEN=t REF="" DIFF_BASE="" EVENT=push BEFORE="$base" \
    GITHUB_SERVER_URL=https://github.invalid GITHUB_OUTPUT="$work/output" \
    bash "$work/unbuilt.sh" >"$work/out" 2>&1) || true
  grep -q '^unbuilt=true$' "$work/output" && echo skip || echo run
}

check "unbuilt: a README no file names skips" "$(run "$(change readme 'README.md=# app, more')")" skip
check "unbuilt: a Markdown file that code embeds runs" "$(run "$(change guide 'docs/guide.md=# more')")" run
check "unbuilt: a source change runs" "$(run "$(change code 'src/lib.rs=pub fn f() {}')")" run
check "unbuilt: a workflow that calls none of the gates skips" \
  "$(run "$(change pin '.github/workflows/housekeeping.yml=jobs: {a: {uses: o/s/.github/workflows/actions-cleanup.yml@y}}')")" skip
check "unbuilt: a workflow that calls the checks runs" \
  "$(run "$(change ci '.github/workflows/ci.yml=jobs: {ci: {uses: o/s/.github/workflows/rust-ci.yml@y}}')")" run
sha=$(change readme2 'README.md=# app, again')
mv "$origin" "$origin.gone"; mkdir "$origin"
check "unbuilt: a failed read runs the checks" "$(run "$sha" 2>/dev/null || echo run)" run
rmdir "$origin"; mv "$origin.gone" "$origin"

[ "$fails" = 0 ] || { echo "$fails rust-ci test(s) failed"; exit 1; }
echo "rust-ci tests passed"
