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
# It encodes three things about the real client: `--parameters` prints a header line
# and then one parameter a line, name first; `--param-file` holds one KEY=VALUE a
# line, a comma in a value is no list, and `-p` is refused (it would split one);
# `diff` exits 1 on a difference.
set -euo pipefail
printf 'oc %s\n' "$*" >>"$FAKE_LOG"
case "$*" in
  "process --local -f "*" --parameters")
    echo "NAME DESCRIPTION GENERATOR VALUE"
    sed -nE 's/^  - name: ([A-Z_]+).*/\1/p' "$4"
    ;;
  "process --local -f "*)
    [ "$(basename "$4")" != "${FAKE_PROCESS_FAIL:-}" ] || { echo "fake: render refused" >&2; exit 1; }
    printf 'rendered %s' "$(basename "$4")"
    shift 4
    while [ $# -gt 0 ]; do
      case "$1" in
        --param-file=*) while IFS= read -r pair; do printf ' %s' "$pair"; done <"${1#--param-file=}"; shift ;;
        -p|--param) echo "fake: -p reads commas as a list" >&2; exit 1 ;;
        *) shift ;;
      esac
    done
    echo
    ;;
  "diff -f "*)
    cat "$3" >>"$FAKE_LOG"
    exit "${FAKE_DIFF:-1}"
    ;;
  "apply -f "*)
    cat "$3" >>"$FAKE_LOG"
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
MEMORY_LIMIT=1Gi
INTERNET_CIDR=0.0.0.0/0
NOT_A_PARAMETER=ignored
ENV

# 1. A diff, by default, of every template present but monitoring.yaml, each with
#    the parameters it declares and no other; differences are the exit status 1.
rc=0; run || rc=$?
[ "$rc" -eq 1 ] || fail "diff with changes exits 1 (got $rc)"
logged "rendered app.yaml NAME=myapp NAMESPACE=myapp-staging IMAGE=ghcr.io/example/myapp CHANNEL=rc PORT=8000 POSTGRES_MAJOR=16 MEMORY_LIMIT=1Gi" || fail "app.yaml's parameters"
logged "rendered redis.yaml NAME=myapp NAMESPACE=myapp-staging MAXMEMORY_POLICY=noeviction" || fail "redis.yaml's parameters (the app's IMAGE and MEMORY_LIMIT are not Redis's)"
logged "rendered egress.yaml NAME=myapp NAMESPACE=myapp-staging POD=myapp INTERNET_CIDR=0.0.0.0/0" || fail "egress.yaml for the app"
grep -q "NOT_A_PARAMETER" "$log" && fail "a key no template declares was passed"
grep -q "monitoring.yaml" "$log" && fail "monitoring.yaml rendered without --monitoring"
grep -q "^oc apply" "$log" && fail "a diff applied something"
grep -c "^oc diff -f " "$log" | grep -qx 3 || fail "three diffs"
grep -q "cronjob.yaml is here but jobs/ holds no" "$work/err" || fail "the empty jobs/ warning"

# 2. No change: exit 0. A diff that fails (no rights to the kind, say): exit 2.
FAKE_DIFF=0 run || fail "a diff with no changes exits 0"
grep -q "no change" "$work/out" || fail "says no change"
rc=0; FAKE_DIFF=3 run || rc=$?; [ "$rc" -eq 2 ] || fail "a failed diff exits 2 (got $rc)"
grep -q "oc diff failed (3) on app.yaml" "$work/err" || fail "names the failed diff"

# 3. --apply applies each rendered document, in order; --monitoring adds
#    monitoring.yaml last, in either mode.
run --apply --monitoring || fail "apply"
grep -c "^oc apply -f " "$log" | grep -qx 4 || fail "four applies"
grep -q "^oc diff" "$log" && fail "an apply diffed"
logged "rendered monitoring.yaml NAME=myapp NAMESPACE=myapp-staging" || fail "monitoring.yaml's parameters"
awk '/^oc process --local -f .*-o yaml$/ { print $5 }' "$log" | tr '\n' ' ' | grep -q "app.yaml .*redis.yaml .*egress.yaml .*monitoring.yaml" || fail "order"

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
grep -q "rendered app.yaml.*MEMORY_LIMIT=512Mi" "$log" && fail "a job's override leaked into the app"
grep -q "cronjob.yaml is here but" "$work/err" && fail "warned with jobs present"

# 5. Only the templates present are rendered.
rm "$work/deploy/redis.yaml" "$work/deploy/monitoring.yaml" "$work/deploy/egress.yaml" "$work/deploy/cronjob.yaml"
rc=0; run || rc=$?
grep -c "^oc diff -f " "$log" | grep -qx 1 || fail "app.yaml alone"
rc=0; run --apply --monitoring || rc=$?; [ "$rc" -eq 2 ] || fail "--monitoring without monitoring.yaml exits 2"
grep -q "^oc apply" "$log" && fail "--monitoring without monitoring.yaml applied something first"

# 6. Refusals: no params.env, a malformed line, a missing NAME, an unknown flag.
rc=0; PARAMS=$work/none.env run || rc=$?; [ "$rc" -eq 2 ] || fail "missing params.env exits 2"
cp "$work/deploy/params.env" "$work/good.env"
echo "not a pair" >>"$work/deploy/params.env"
rc=0; run || rc=$?; [ "$rc" -eq 2 ] || fail "a malformed line exits 2"
grep -q "not a KEY=VALUE line" "$work/err" || fail "names the malformed line"
grep -v '^NAME=' "$work/good.env" >"$work/deploy/params.env"
rc=0; run || rc=$?; [ "$rc" -eq 2 ] || fail "a missing NAME exits 2 (got $rc)"
grep -q "params.env must set NAME" "$work/err" || fail "names the missing NAME and its file"
grep -v '^NAMESPACE=' "$work/good.env" >"$work/deploy/params.env"
rc=0; run || rc=$?; [ "$rc" -eq 2 ] || fail "a missing NAMESPACE exits 2 (got $rc)"
cp "$work/good.env" "$work/deploy/params.env"
cp "$here/cronjob.yaml" "$work/deploy/"
echo "SCHEDULE=0 1 * * *" >"$work/deploy/jobs/nameless.env"
rc=0; run || rc=$?; [ "$rc" -eq 2 ] || fail "a job without JOB exits 2 (got $rc)"
grep -q "jobs/nameless.env must set JOB" "$work/err" || fail "names the job's file"
rm "$work/deploy/jobs/nameless.env" "$work/deploy/cronjob.yaml"
rc=0; FAKE_PROCESS_FAIL=app.yaml run || rc=$?; [ "$rc" -eq 2 ] || fail "a failed render exits 2 (got $rc)"
grep -q "oc process failed on app.yaml" "$work/err" || fail "names the failed render"
grep -q "^oc diff" "$log" && fail "a failed render was diffed"
cp "$work/good.env" "$work/deploy/params.env"
rc=0; run --force || rc=$?; [ "$rc" -eq 2 ] || fail "an unknown flag exits 2"
for bad in 300 30S 2.5m 0s; do
  { cat "$work/good.env"; echo "ROUTE_TIMEOUT=$bad"; } >"$work/deploy/params.env"
  rc=0; run || rc=$?; [ "$rc" -eq 2 ] || fail "ROUTE_TIMEOUT=$bad exits 2 (got $rc)"
  grep -q "ROUTE_TIMEOUT=$bad is not a number with a unit" "$work/err" || fail "names ROUTE_TIMEOUT=$bad"
  grep -q "^oc process" "$log" && fail "ROUTE_TIMEOUT=$bad rendered something"
done
{ cat "$work/good.env"; echo "ROUTE_TIMEOUT=300s"; } >"$work/deploy/params.env"
rc=0; run || rc=$?; [ "$rc" -eq 1 ] || fail "ROUTE_TIMEOUT=300s is taken (got $rc)"
logged "ROUTE_TIMEOUT=300s" || fail "ROUTE_TIMEOUT reaches app.yaml"
cp "$work/good.env" "$work/deploy/params.env"

# 7. One pair of quotes comes off a value; what is inside (spaces, `=`, `$`, a
#    quote of the other kind) is taken as written.
cat >>"$work/deploy/params.env" <<'ENV'
BACKUP_SCHEDULE="0 0 2 * * *"
CHANNEL='rc "quoted", it's'
IMAGE=ghcr.io/example/my$app
ENV
rc=0; run || rc=$?
logged 'BACKUP_SCHEDULE=0 0 2 * * *' || fail "a quoted value loses its quotes"
grep -qF 'CHANNEL=rc "quoted", it'"'"'s' "$log" || fail "what is inside is kept"
logged 'IMAGE=ghcr.io/example/my$app' || fail "a dollar is literal"

# 8. A comma in a value reaches the template whole (a parameter file, not `-p`).
echo 'RUST_LOG=info,myapp=debug' >>"$work/deploy/params.env"
rc=0; run || rc=$?
logged 'RUST_LOG=info,myapp=debug' || fail "a comma in a value is kept"
grep -qE '^oc process .* (-p|--param) ' "$log" && fail "a parameter passed with -p"

# 9. cronjob.yaml reads the app's Secret, then the task's own, both optional. The
#    stand-in `oc` renders nothing, so the template's source stands in for its output.
grep -qF 'secretRef: {name: "${NAME}-env", optional: true}' "$here/cronjob.yaml" || fail "cronjob.yaml reads the app's Secret"
grep -qF 'secretRef: {name: "${NAME}-${JOB}-env", optional: true}' "$here/cronjob.yaml" || fail "cronjob.yaml reads the task's Secret"

echo "apply.sh: ok"
