#!/usr/bin/env bash
# apply.sh against a stand-in `oc` that records what it is asked: which templates
# are rendered with which parameters, diff against apply, the jobs' files, the
# egress policies per set of pods, the tunnel and its config checksum, and the
# refusals. It proves the script's own
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
# `diff` exits 1 on a difference. A jsonpath render (the tunnel's config, for its
# checksum) prints the parameters it was given, so it changes when they do.
set -euo pipefail
printf 'oc %s\n' "$*" >>"$FAKE_LOG"
case "$*" in
  "process --local -f "*" --parameters")
    echo "NAME DESCRIPTION GENERATOR VALUE"
    sed -nE 's/^  - name: ([A-Z_]+).*/\1/p' "$4"
    ;;
  "process --local -f "*" -o jsonpath="*)
    printf 'config of %s:' "$(basename "$4")"
    cat "${5#--param-file=}"
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

# 10. An executable pre-render beside the script: params.env is its environment, its
#     stdout joins the parameters over params.env's, and it runs once, before any
#     render. A failure, a line that is no pair, or a hook that cannot run exits 2.
cp "$work/good.env" "$work/deploy/params.env"
cat >"$work/deploy/pre-render" <<'HOOK'
#!/usr/bin/env bash
echo "hook ran with NAME=$NAME in $(basename "$PWD")" >&2
echo "# a comment"
echo "PORT=9000"
echo 'BACKUP_SCHEDULE="0 0 3 * * *"'
echo "RUST_LOG=info,a=b"
HOOK
chmod +x "$work/deploy/pre-render"
rc=0; run || rc=$?
[ "$rc" -eq 1 ] || fail "diff with a hook (got $rc)"
grep -q "hook ran with NAME=myapp in deploy" "$work/err" || fail "the hook's environment and directory"
logged "rendered app.yaml NAME=myapp NAMESPACE=myapp-staging IMAGE=ghcr.io/example/myapp CHANNEL=rc PORT=9000" || fail "the hook's value wins over params.env"
logged 'BACKUP_SCHEDULE=0 0 3 * * *' || fail "the hook's quoted value loses its quotes"
logged 'RUST_LOG=info,a=b' || fail "a hook value reaches the template that declares it"
[ "$(grep -c 'hook ran' "$work/err")" -eq 1 ] || fail "the hook runs once"
cp "$here/cronjob.yaml" "$work/deploy/"
printf 'JOB=sweep\nSCHEDULE=* * * * *\nARGS=["x"]\nPORT=7000\n' >"$work/deploy/jobs/sweep.env"
rc=0; run || rc=$?
[ "$(grep -c 'hook ran' "$work/err")" -eq 1 ] || fail "the hook runs once with jobs"
logged 'rendered cronjob.yaml NAME=myapp NAMESPACE=myapp-staging JOB=sweep' || fail "the task renders"
rm "$work/deploy/jobs/sweep.env" "$work/deploy/cronjob.yaml"
printf '#!/usr/bin/env bash\necho partial\nexit 4\n' >"$work/deploy/pre-render"
rc=0; run || rc=$?; [ "$rc" -eq 2 ] || fail "a failing hook exits 2 (got $rc)"
grep -q "pre-render failed" "$work/err" || fail "names the failed hook"
grep -q "^oc process" "$log" && fail "rendered after a failed hook"
printf '#!/usr/bin/env bash\nprintf "PORT=1\\nsecond line\\n"\n' >"$work/deploy/pre-render"
rc=0; run || rc=$?; [ "$rc" -eq 2 ] || fail "a hook line that is no pair exits 2 (got $rc)"
grep -q "pre-render: not a KEY=VALUE line: second line" "$work/err" || fail "names the hook's bad line"
chmod -x "$work/deploy/pre-render"
rc=0; run || rc=$?; [ "$rc" -eq 2 ] || fail "a hook that is not executable exits 2 (got $rc)"
grep -q "pre-render is not an executable file" "$work/err" || fail "names the unexecutable hook"
printf '#!/usr/bin/env bash\nread -r x && echo "PORT=$x"\necho PORT=5\n' >"$work/deploy/pre-render"
chmod +x "$work/deploy/pre-render"
echo typed | PATH=$work/bin:$PATH FAKE_LOG=$log bash "$work/deploy/apply.sh" >"$work/out" 2>"$work/err" && rc=0 || rc=$?
[ "$rc" -eq 2 ] || [ "$rc" -eq 1 ] || fail "a hook reading stdin does not hang (got $rc)"
grep -q "PORT=typed" "$log" && fail "the hook read apply.sh's stdin"
for pair in NAME=other NAMESPACE=other NAME=; do
  printf '#!/usr/bin/env bash\necho %s\n' "$pair" >"$work/deploy/pre-render"
  rc=0; run || rc=$?; [ "$rc" -eq 2 ] || fail "a hook setting $pair exits 2 (got $rc)"
  grep -q "NAME and NAMESPACE are params.env's alone" "$work/err" || fail "names the refused $pair"
  grep -q "^oc process" "$log" && fail "rendered after a hook set $pair"
done
printf '#!/usr/bin/env bash\necho NAME=myapp\n' >"$work/deploy/pre-render"
rc=0; run || rc=$?; [ "$rc" -eq 1 ] || fail "a hook restating NAME is harmless (got $rc)"
rm "$work/deploy/pre-render"
ln -s "$work/deploy/missing" "$work/deploy/pre-render"
rc=0; run || rc=$?; [ "$rc" -eq 2 ] || fail "a dangling pre-render exits 2 (got $rc)"
grep -q "not an executable file" "$work/err" || fail "names the dangling hook"
rm "$work/deploy/pre-render"

# 11. The tunnel: rendered when params.env sets TUNNEL_HOST and TUNNEL_ID, after the
#     app's egress, with CREDENTIALS_SECRET defaulting to <NAME>-tunnel and a checksum
#     of its config that changes with the config and with nothing else; skipped when
#     neither is set; refused when one is set without the other, when TUNNEL_ID is no
#     UUID, or when tunnel.yaml is not here.
cp "$here/egress.yaml" "$work/deploy/"
cp "$work/good.env" "$work/deploy/params.env"
rc=0; run || rc=$?
[ "$rc" -eq 1 ] || fail "diff without a tunnel (got $rc)"
grep -q "rendered tunnel.yaml" "$log" && fail "a tunnel rendered without TUNNEL_HOST"
grep -q "tunnel.yaml is here but .* sets no TUNNEL_HOST" "$work/err" || fail "the no-tunnel note"
id=0f6a3c1e-8b2d-4c5e-9a7f-1d2e3f4a5b6c
tunnel_run() {
  { cat "$work/good.env"; printf '%s\n' "$@"; } >"$work/deploy/params.env"
  rc=0; run --apply || rc=$?
}
checksum() { sed -n 's/^rendered tunnel.yaml .*TUNNEL_CONFIG_CHECKSUM=\([0-9a-f]*\).*/\1/p' "$log"; }
tunnel_run "TUNNEL_HOST=myapp.example.com" "TUNNEL_ID=$id"
[ "$rc" -eq 0 ] || fail "apply with a tunnel (got $rc)"
logged "rendered tunnel.yaml NAME=myapp NAMESPACE=myapp-staging TUNNEL_HOST=myapp.example.com TUNNEL_ID=$id CREDENTIALS_SECRET=myapp-tunnel TUNNEL_CONFIG_CHECKSUM=" || fail "tunnel.yaml's parameters"
grep -q "tunnel.yaml is here but" "$work/err" && fail "the no-tunnel note with a tunnel"
grep -c "^oc apply -f " "$log" | grep -qx 3 || fail "three applies with the tunnel"
awk '/^oc process --local -f .*-o yaml$/ { print $5 }' "$log" | tr '\n' ' ' | grep -q "app.yaml .*egress.yaml .*tunnel.yaml" || fail "the tunnel after the app's egress"
grep -q "^config of tunnel.yaml:.*TUNNEL_CONFIG_CHECKSUM" "$log" && fail "the checksum fed its own render"
first=$(checksum)
[[ $first =~ ^[0-9a-f]{16}$ ]] || fail "a 16-digit checksum (got '$first')"
tunnel_run "TUNNEL_HOST=myapp.example.com" "TUNNEL_ID=$id"
[ "$(checksum)" = "$first" ] || fail "the same config, the same checksum"
tunnel_run "TUNNEL_HOST=www.example.com" "TUNNEL_ID=$id"
[ "$(checksum)" != "$first" ] || fail "a new host, a new checksum"
tunnel_run "TUNNEL_HOST=myapp.example.com" "TUNNEL_ID=$id" "CREDENTIALS_SECRET=other-creds"
logged "CREDENTIALS_SECRET=other-creds" || fail "params.env names the credentials Secret"
tunnel_run "TUNNEL_HOST=myapp.example.com" "TUNNEL_ID=$id" "TUNNEL_CONFIG_CHECKSUM=stale"
grep -q "TUNNEL_CONFIG_CHECKSUM=stale" "$log" && fail "a checksum in params.env wins over the computed one"
[ "$(checksum)" = "$first" ] || fail "a checksum in params.env changes the computed one"
for half in "TUNNEL_HOST=myapp.example.com" "TUNNEL_ID=$id" "TUNNEL_HOST=myapp.example.com TUNNEL_ID="; do
  # shellcheck disable=SC2086 # each word is a line
  tunnel_run $half
  [ "$rc" -eq 2 ] || fail "'$half' exits 2 (got $rc)"
  grep -q "TUNNEL_HOST and TUNNEL_ID go together" "$work/err" || fail "names the half-set tunnel '$half'"
  grep -q "^oc process" "$log" && fail "'$half' rendered something"
done
tunnel_run "TUNNEL_HOST=myapp.example.com" "TUNNEL_ID=myapp"
[ "$rc" -eq 2 ] || fail "a TUNNEL_ID that is no UUID exits 2 (got $rc)"
grep -q "TUNNEL_ID=myapp is not a tunnel's UUID" "$work/err" || fail "names the bad TUNNEL_ID"
rm "$work/deploy/tunnel.yaml"
tunnel_run "TUNNEL_HOST=myapp.example.com" "TUNNEL_ID=$id"
[ "$rc" -eq 2 ] || fail "a tunnel without tunnel.yaml exits 2 (got $rc)"
grep -q "sets TUNNEL_HOST, and tunnel.yaml is not here" "$work/err" || fail "names the missing tunnel.yaml"
grep -q "^oc process" "$log" && fail "rendered without tunnel.yaml"
cp "$work/good.env" "$work/deploy/params.env"
rc=0; run || rc=$?
grep -q "tunnel.yaml" "$work/err" && fail "a note about a tunnel.yaml that is not here"

echo "apply.sh: ok"
