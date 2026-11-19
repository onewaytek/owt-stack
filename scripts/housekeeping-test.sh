#!/usr/bin/env bash
# Proves the housekeeping workflows' shell without a network: actions-cleanup.yml treats
# a 404 on DELETE as success and fails on any other error, and deletes a completed run's
# layer unless a job reading it failed or timed out, and names in its default `consumers`
# only image.yml jobs that read the layer; ghcr-prune.yml's "Read the
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
step "$wf/actions-cleanup.yml" "Delete the artifacts of completed runs" >"$work/clean.sh"
[ -s "$work/clean.sh" ] || { echo "no cleanup script found" >&2; exit 1; }
cat >"$work/bin/curl" <<'CURL'
#!/usr/bin/env bash
# Answers per the request: the listing from $FIX/artifacts.json, a run from
# $FIX/run-<id>.json and its jobs from $FIX/jobs-<id>.json (page 1 only; an error when
# the file is missing), DELETE by
# the code $DELETE_CODES gives the artifact id.
url="${*: -1}"; method=GET; want_code=false; prev=""
for a in "$@"; do
  [ "$prev" = -X ] && method=$a
  [ "$prev" = -w ] && want_code=true
  prev=$a
done
echo "$method $url" >>"$CALLS"
if [ "$method" = DELETE ]; then
  id="${url##*/}"; code=$(sed -n "s/^$id //p" "$DELETE_CODES")
  $want_code && printf '%s' "$code"
  exit 22
fi
case "$url" in
  */actions/artifacts\?*page=1) cat "$FIX/artifacts.json" ;;
  */actions/artifacts\?*) echo '{"artifacts":[]}' ;;
  */actions/runs/*/jobs\?*page=1) r="${url%%/jobs*}"; cat "$FIX/jobs-${r##*/}.json" 2>/dev/null || exit 22 ;;
  */actions/runs/*/jobs\?*) echo '{"jobs":[]}' ;;
  */actions/runs/*) cat "$FIX/run-${url##*/}.json" ;;
esac
CURL
chmod +x "$work/bin/curl"
fix="$work/fix"; mkdir -p "$fix"
# Artifact <id> of run <id>, ten bytes each.
artifacts() {
  local id rows=()
  for id in "$@"; do rows+=("{\"id\":$id,\"expired\":false,\"size_in_bytes\":10,\"workflow_run\":{\"id\":$id}}"); done
  local IFS=,; echo "{\"artifacts\":[${rows[*]}]}" >"$fix/artifacts.json"
}
# run <id> <status> <job name>=<conclusion>...
run() {
  local id=$1 status=$2 rows=() j; shift 2
  echo "{\"status\":\"$status\"}" >"$fix/run-$id.json"
  for j in "$@"; do rows+=("{\"name\":\"${j%=*}\",\"conclusion\":\"${j#*=}\"}"); done
  local IFS=,; echo "{\"jobs\":[${rows[*]}]}" >"$fix/jobs-$id.json"
}
# The workflow's own default, and each name in it a job that reads the layer.
consumers=$(awk '/^      consumers:/ {on = 1} on && /^        default: / {sub(/^        default: /, ""); print; exit}' \
  "$wf/actions-cleanup.yml")
check "cleanup: the default consumers" "$consumers" "scan push"
for j in $consumers; do
  grep -qx "  $j:" "$wf/image.yml" && grep -q "image-layer" <(awk -v j="  $j:" '$0 == j {on=1; next} on && /^  [^ ]/ {exit} on' "$wf/image.yml") \
    && c=yes || c=no
  check "cleanup: consumer $j is an image.yml job that reads the layer" "$c" yes
done
run_clean() { # $1 = delete codes
  printf '%s\n' "$1" >"$work/codes"; : >"$work/calls"; : >"$work/summary"
  (cd "$work" && PATH="$work/bin:$PATH" CALLS="$work/calls" DELETE_CODES="$work/codes" FIX="$fix" \
    TOKEN=t RUN_ID="" NAMES=image-layer CONSUMERS="$consumers" GITHUB_REPOSITORY=o/r \
    RUNNER_TEMP="$work" GITHUB_STEP_SUMMARY="$work/summary" bash "$work/clean.sh" >"$work/out" 2>&1)
}
deleted() { sed -n 's|^DELETE .*/artifacts/||p' "$work/calls" | sort -n | paste -sd' '; }
artifacts 1 2
run 1 completed "image-check / build=success" "image-check / scan=success"
run 2 completed "image-check / build=success" "image-check / scan=success"
rc=0; run_clean $'1 204\n2 404' || rc=$?
check "cleanup: 404 on DELETE is success" "$rc" 0
check "cleanup: both deletes attempted" "$(deleted)" "1 2"
rc=0; run_clean $'1 204\n2 500' || rc=$?
check "cleanup: 500 on DELETE fails" "$rc" 1
# 1 in progress, 2 scan failed, 3 push timed out, 4 another job failed,
# 5 cancelled, 6 succeeded.
artifacts 1 2 3 4 5 6
run 1 in_progress "image-check / build=success" "image-check / scan=null"
run 2 completed "image-check / build=success" "image-check / scan=failure"
run 3 completed "release / image / scan=success" "release / image / push=timed_out"
run 4 completed "image-check / scan=success" "check-rc / checks / rust=failure"
run 5 completed "image-check / scan=cancelled"
run 6 completed "release / image / scan=success" "release / image / push=success" "release / image / attest=failure"
rc=0; run_clean "$(printf '%s 204\n' 1 2 3 4 5 6)" || rc=$?
check "cleanup: the decision run succeeds" "$rc" 0
check "cleanup: deletes failure elsewhere, cancelled and succeeded; keeps in progress and failed consumers" \
  "$(deleted)" "4 5 6"
check "cleanup: the summary counts" "$(cat "$work/summary")" "deleted 3 artifacts, 30 bytes; kept 3"
artifacts 4; rm -f "$fix/jobs-4.json"
run_clean "$(printf '%s 204\n' 4)" || true
check "cleanup: a run whose jobs cannot be read keeps its layer" "$(deleted)" ""
grep -q '^concurrency:\|^    concurrency:' "$wf/actions-cleanup.yml" && c=yes || c=no
check "cleanup: concurrency group" "$c" yes
grep -A3 'concurrency:' "$wf/actions-cleanup.yml" | grep -q 'cancel-in-progress: false' && c=yes || c=no
check "cleanup: no cancel-in-progress" "$c" yes

# --- ghcr-prune.yml: Read the pins ---------------------------------------------
step "$wf/ghcr-prune.yml" "Read the pins" >"$work/pins.sh"
[ -s "$work/pins.sh" ] || { echo "no pins script found" >&2; exit 1; }
d1=sha256:$(printf 'a%.0s' {1..64}); d2=sha256:$(printf 'b%.0s' {1..64})
mkdir -p "$work/prbin"
cat >"$work/prbin/curl" <<'CURL'
#!/usr/bin/env bash
# The deployments repository's open pull requests: none when NOPR is set, an error when
# PRFAIL is set, else #7, whose diff moves a pin from the digest $PRDIGEST.
url="${*: -1}"
[ -z "${PRFAIL:-}" ] || exit 22
case "$url" in
  */pulls\?*) [ -n "${NOPR:-}" ] && echo '[]' || echo '[{"number":7}]' ;;
  */pulls/7) printf -- '-  digest: %s\n+  digest: sha256:%s\n+  version: 2.0.0-rc.1\n' "$PRDIGEST" "$(printf 'e%.0s' {1..64})" ;;
esac
CURL
chmod +x "$work/prbin/curl"
run_pins() { # $1 = delete, in $work/ws
  (cd "$work/ws" && PATH="$work/prbin:$PATH" NOPR="${NOPR-1}" PRFAIL="${PRFAIL:-}" PRDIGEST="$d2" TOKEN=t \
    DEPLOYMENTS=o/d RUNNER_TEMP="$work/tmp" DELETE="$1" bash "$work/pins.sh" >"$work/out" 2>&1)
}
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
NOPR= run_pins true
check "prune: open pull request digests are pins" "$(grep -c "$d2\|eeee" "$work/tmp/ghcr-prune/pins")" 2
check "prune: open pull request versions are pin tags" "$(grep -c '^2.0.0-rc.1$' "$work/tmp/ghcr-prune/pin-tags")" 1
rc=0; PRFAIL=1 run_pins true || rc=$?
check "prune: delete fails when the pull requests cannot be read" "$rc" 1
rc=0; PRFAIL=1 run_pins false || rc=$?
check "prune: a dry run proceeds when they cannot be read" "$rc" 0

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
