#!/usr/bin/env bash
# apply.sh against a stand-in `oc` that records what it is asked: which templates
# are rendered with which parameters, diff against apply, the jobs' files, the
# egress policies per set of pods, and the refusals. It proves the script's own
# logic; the templates' output is `oc process`'s to render, on a real run.
#
#   templates/openshift/apply-test.sh       (`just templates` runs it)
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/deploy/jobs"
cp "$here"/*.yaml "$here/apply.sh" "$work/deploy/"

cat >"$work/bin/oc" <<'FAKE'
#!/usr/bin/env bash
# Answers the calls apply.sh makes, and logs each one. A rendered document is a line
# naming the template and the parameters given, so the log shows what was applied.
set -euo pipefail
printf 'oc %s\n' "$*" >>"$FAKE_LOG"
case "$*" in
  "process --local -f "*" --parameters")
    echo "NAME DESCRIPTION GENERATOR VALUE"
    sed -nE 's/^  - name: ([A-Z_]+).*/\1/p' "$4"
    ;;
  "process --local -f "*)
    printf 'rendered %s' "$(basename "$4")"
    shift 4
    while [ $# -gt 0 ]; do
      case "$1" in -p) printf ' %s' "$2"; shift 2 ;; *) shift ;; esac
    done
    echo
    ;;
  "diff -f -")
    cat >>"$FAKE_LOG"
    exit "${FAKE_DIFF:-1}"
    ;;
  "apply -f -")
    cat >>"$FAKE_LOG"
    echo "applied"
    ;;
  *) echo "unexpected: oc $*" >&2; exit 9 ;;
esac
FAKE
chmod +x "$work/bin/oc"

log=$work/log
run() {
  : >"$log"
  PATH=$work/bin:$PATH FAKE_LOG=$log bash "$work/deploy/apply.sh" "$@" >"$work/out" 2>"$work/err"
}
fail() { echo "FAIL: $*" >&2; echo "--- out"; cat "$work/out"; echo "--- err"; cat "$work/err"; echo "--- log"; cat "$log"; exit 1; }
logged() { grep -qF -- "$1" "$log"; }

cat >"$work/deploy/params.env" <<'ENV'
# The app's deploy.
NAME=myapp
NAMESPACE=myapp-staging
IMAGE=ghcr.io/example/myapp
CHANNEL=rc
PORT=8000
POSTGRES_MAJOR=16
MAXMEMORY_POLICY=noeviction
INTERNET_CIDR=0.0.0.0/0
NOT_A_PARAMETER=ignored
ENV

# 1. A diff, by default, of every template present, each with the parameters it
#    declares and no other; differences are the exit status 1.
rc=0; run || rc=$?
[ "$rc" -eq 1 ] || fail "diff with changes exits 1 (got $rc)"
logged "rendered app.yaml NAME=myapp NAMESPACE=myapp-staging IMAGE=ghcr.io/example/myapp CHANNEL=rc PORT=8000 POSTGRES_MAJOR=16" || fail "app.yaml's parameters"
logged "rendered redis.yaml NAME=myapp NAMESPACE=myapp-staging MAXMEMORY_POLICY=noeviction" || fail "redis.yaml's parameters (the app's IMAGE is not Redis's)"
logged "rendered monitoring.yaml NAME=myapp NAMESPACE=myapp-staging" || fail "monitoring.yaml's parameters"
logged "rendered egress.yaml NAME=myapp NAMESPACE=myapp-staging POD=myapp INTERNET_CIDR=0.0.0.0/0" || fail "egress.yaml for the app"
grep -q "NOT_A_PARAMETER" "$log" && fail "a key no template declares was passed"
grep -q "^oc apply" "$log" && fail "a diff applied something"
grep -c "^oc diff -f -" "$log" | grep -qx 4 || fail "four diffs"
grep -q "cronjob.yaml is here but jobs/ holds no" "$work/err" || fail "the empty jobs/ warning"

# 2. No change: exit 0.
FAKE_DIFF=0 run || fail "a diff with no changes exits 0"
grep -q "no change" "$work/out" || fail "says no change"

# 3. --apply applies each rendered document, in order.
run --apply || fail "apply"
grep -c "^oc apply -f -" "$log" | grep -qx 4 || fail "four applies"
grep -q "^oc diff" "$log" && fail "an apply diffed"
awk '/^oc process --local -f .*-o yaml$/ { print $5 }' "$log" | tr '\n' ' ' | grep -q "app.yaml .*redis.yaml .*monitoring.yaml .*egress.yaml" || fail "order"

# 4. Each jobs/<JOB>.env renders cronjob.yaml over params.env, then its egress
#    policy; nothing a job sets reaches the next, nor the app's own.
cat >"$work/deploy/jobs/digest.env" <<'ENV'
JOB=digest
SCHEDULE=0 6 * * *
ARGS=["send-digest"]
INTERNET_CIDR=0.0.0.0/32
MEMORY_LIMIT=512Mi
ENV
cat >"$work/deploy/jobs/sweep.env" <<'ENV'
JOB=sweep
SCHEDULE=*/15 * * * *
ARGS=["sweep"]
ENV
rc=0; run || rc=$?
[ "$rc" -eq 1 ] || fail "diff with jobs"
logged 'rendered cronjob.yaml NAME=myapp NAMESPACE=myapp-staging JOB=digest SCHEDULE=0 6 * * * ARGS=["send-digest"] CHANNEL=rc MEMORY_LIMIT=512Mi' || fail "digest's cronjob"
logged "rendered egress.yaml NAME=myapp NAMESPACE=myapp-staging POD=myapp-digest INTERNET_CIDR=0.0.0.0/32" || fail "digest's egress"
logged 'rendered cronjob.yaml NAME=myapp NAMESPACE=myapp-staging JOB=sweep SCHEDULE=*/15 * * * * ARGS=["sweep"] CHANNEL=rc' || fail "sweep's cronjob"
logged "rendered egress.yaml NAME=myapp NAMESPACE=myapp-staging POD=myapp-sweep INTERNET_CIDR=0.0.0.0/0" || fail "sweep's egress keeps the app's CIDR"
logged "rendered egress.yaml NAME=myapp NAMESPACE=myapp-staging POD=myapp INTERNET_CIDR=0.0.0.0/0" || fail "the app's egress"
grep -q "MEMORY_LIMIT=512Mi.*sweep\|sweep.*MEMORY_LIMIT=512Mi" "$log" && fail "digest's override leaked into sweep"
grep -q "rendered app.yaml.*MEMORY_LIMIT" "$log" && fail "a job's override leaked into the app"
grep -q "cronjob.yaml is here but" "$work/err" && fail "warned with jobs present"

# 5. Only the templates present are rendered.
rm "$work/deploy/redis.yaml" "$work/deploy/monitoring.yaml" "$work/deploy/egress.yaml" "$work/deploy/cronjob.yaml"
rc=0; run || rc=$?
grep -c "^oc diff -f -" "$log" | grep -qx 1 || fail "app.yaml alone"

# 6. Refusals: no params.env, a malformed line, a missing NAME, an unknown flag.
rc=0; PARAMS=$work/none.env run || rc=$?; [ "$rc" -eq 2 ] || fail "missing params.env exits 2"
cp "$work/deploy/params.env" "$work/good.env"
echo "not a pair" >>"$work/deploy/params.env"
rc=0; run || rc=$?; [ "$rc" -eq 2 ] || fail "a malformed line exits 2"
grep -q "not a KEY=VALUE line" "$work/err" || fail "names the malformed line"
grep -v '^NAME=' "$work/good.env" >"$work/deploy/params.env"
rc=0; run || rc=$?; [ "$rc" -ne 0 ] || fail "a missing NAME is refused"
grep -q "must set NAME" "$work/err" || fail "names the missing NAME"
cp "$work/good.env" "$work/deploy/params.env"
rc=0; run --force || rc=$?; [ "$rc" -eq 2 ] || fail "an unknown flag exits 2"

# 7. A value is taken as written: spaces, `=` and quotes inside it stay.
echo 'BACKUP_SCHEDULE="0 0 2 * * *"' >>"$work/deploy/params.env"
rc=0; run || rc=$?
logged 'BACKUP_SCHEDULE="0 0 2 * * *"' || fail "a value with spaces and quotes"

echo "apply.sh: ok"
