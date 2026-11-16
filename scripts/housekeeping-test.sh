#!/usr/bin/env bash
# Proves the housekeeping workflows' shell without a network: actions-cleanup.yml treats
# a 404 on DELETE as success and fails on any other error; ghcr-prune.yml's "Read the
# pins" step fails a deletion run (and warns on a dry run) when the deployments checkout
# yields no pins, reads digest and `version:` pins, and its tag resolution protects the
# version carrying a pinned tag. `just templates` runs it; it needs bash 4, jq and sed.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
wf="$here/../.github/workflows"
work=$(mktemp -d)
trap '[ -n "${KEEP:-}" ] || rm -rf "$work"' EXIT
mkdir -p "$work/bin"
fails=0
check() { if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: want '$3', got '$2'"; fails=$((fails + 1)); fi; }

# A step's `run: |` script, dedented, from a workflow.
step() {
  awk -v name="$2" '
    index($0, "- name: " name) { in_step = 1; next }
    in_step && /^      - / { exit }
    in_step && /^        run: \|$/ { in_run = 1; next }
    in_run { sub(/^          /, ""); print }
  ' "$1"
}

# --- actions-cleanup.yml -----------------------------------------------------
step "$wf/actions-cleanup.yml" "Delete the artifacts of succeeded runs" >"$work/clean.sh"
[ -s "$work/clean.sh" ] || { echo "no cleanup script found" >&2; exit 1; }
cat >"$work/bin/curl" <<'CURL'
#!/usr/bin/env bash
# Answers per the request: listings and runs from fixtures, DELETE by $DELETE_CODE[id].
url="${*: -1}"; method=GET; out=""; want_code=false; prev=""
for a in "$@"; do
  [ "$prev" = -X ] && method=$a
  [ "$prev" = -w ] && want_code=true
  prev=$a
done
echo "$method $url" >>"$CALLS"
if [ "$method" = DELETE ]; then
  id="${url##*/}"; code=$(sed -n "s/^$id //p" "$DELETE_CODES")
  $want_code && printf '%s' "$code"
  [ "$code" = 204 ] || [ "$code" = 404 ] && exit 22 || exit 22
fi
case "$url" in
  */actions/artifacts\?*page=1) echo '{"artifacts":[{"id":1,"expired":false,"size_in_bytes":10,"workflow_run":{"id":9}},{"id":2,"expired":false,"size_in_bytes":20,"workflow_run":{"id":9}}]}' ;;
  */actions/artifacts\?*) echo '{"artifacts":[]}' ;;
  */actions/runs/9) echo '{"conclusion":"success"}' ;;
esac
CURL
chmod +x "$work/bin/curl"
run_clean() { # $1 = delete codes
  printf '%s\n' "$1" >"$work/codes"; : >"$work/calls"
  (cd "$work" && PATH="$work/bin:$PATH" CALLS="$work/calls" DELETE_CODES="$work/codes" \
    TOKEN=t RUN_ID="" NAMES=image-layer GITHUB_REPOSITORY=o/r RUNNER_TEMP="$work" \
    GITHUB_STEP_SUMMARY="$work/summary" bash "$work/clean.sh" >"$work/out" 2>&1)
}
rc=0; run_clean $'1 204\n2 404' || rc=$?
check "cleanup: 404 on DELETE is success" "$rc" 0
check "cleanup: both deletes attempted" "$(grep -c DELETE "$work/calls")" 2
rc=0; run_clean $'1 204\n2 500' || rc=$?
check "cleanup: 500 on DELETE fails" "$rc" 1
grep -q '^concurrency:\|^    concurrency:' "$wf/actions-cleanup.yml" && c=yes || c=no
check "cleanup: concurrency group" "$c" yes
grep -A3 'concurrency:' "$wf/actions-cleanup.yml" | grep -q 'cancel-in-progress: false' && c=yes || c=no
check "cleanup: no cancel-in-progress" "$c" yes

# --- ghcr-prune.yml: Read the pins ---------------------------------------------
step "$wf/ghcr-prune.yml" "Read the pins" >"$work/pins.sh"
[ -s "$work/pins.sh" ] || { echo "no pins script found" >&2; exit 1; }
run_pins() { # $1 = delete, in $work/ws
  (cd "$work/ws" && RUNNER_TEMP="$work/tmp" DELETE="$1" bash "$work/pins.sh" >"$work/out" 2>&1)
}
d1=sha256:$(printf 'a%.0s' {1..64}); d2=sha256:$(printf 'b%.0s' {1..64})
rm -rf "$work/ws" "$work/tmp"; mkdir -p "$work/ws/deployments/apps/x/prod" "$work/ws/deployments/apps/x/rc" "$work/tmp"
rc=0; run_pins true || rc=$?
check "prune: delete with zero pins fails" "$rc" 1
grep -q 'pins read: 0 digests' "$work/out" && c=yes || c=no
check "prune: the failure says why" "$c" yes
rc=0; run_pins false || rc=$?
check "prune: dry run with zero pins proceeds" "$rc" 0
grep -q '^::warning::pins read: 0 digests' "$work/out" && c=yes || c=no
check "prune: dry run warns" "$c" yes
printf 'image:\n  repository: ghcr.io/o/x\n  digest: %s\n  version: 1.2.3\n' "$d1" \
  >"$work/ws/deployments/apps/x/prod/image.yaml"
printf 'image:\n  repository: ghcr.io/o/x\n  version: "1.3.0-rc.4"  # by tag\n' \
  >"$work/ws/deployments/apps/x/rc/image.yaml"
rc=0; run_pins true || rc=$?
check "prune: delete with pins proceeds" "$rc" 0
check "prune: digest pin read" "$(cat "$work/tmp/ghcr-prune/pins")" "$d1"
check "prune: version pins read" "$(paste -sd' ' "$work/tmp/ghcr-prune/pin-tags")" "1.2.3 1.3.0-rc.4"
printf 'image:\n  version: 1.3.0-rc.4\n' >"$work/ws/deployments/apps/x/rc/image.yaml"
rm -f "$work/ws/deployments/apps/x/prod/image.yaml"
rc=0; run_pins true || rc=$?
check "prune: a tag pin alone counts as a pin" "$rc" 0

# --- ghcr-prune.yml: tag resolution -----------------------------------------------
awk '/# resolve-begin/ {on=1; next} /# resolve-end/ {on=0} on {sub(/^          /, ""); print}' \
  "$wf/ghcr-prune.yml" >"$work/resolve.sh"
[ -s "$work/resolve.sh" ] || { echo "no resolve block found" >&2; exit 1; }
cat >"$work/tmp/ghcr-prune/classified.json" <<JSON
[{"digest":"$d1","tags":["1.3.0-rc.4"]},{"digest":"$d2","tags":["1.3.0-rc.5"]},
 {"digest":"sha256:$(printf 'c%.0s' {1..64})","tags":["v1.3.0-rc.4-hsm"]}]
JSON
: >"$work/tmp/ghcr-prune/pins"
(cd "$work" && work="$work/tmp/ghcr-prune" bash "$work/resolve.sh")
check "prune: a pinned rc tag resolves to its digest only" "$(cat "$work/tmp/ghcr-prune/pins")" "$d1"

[ "$fails" -eq 0 ] || { echo "$fails failed" >&2; exit 1; }
echo "housekeeping tests passed"
