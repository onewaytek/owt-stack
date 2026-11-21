#!/usr/bin/env bash
# Proves rust-ci.yml's `unbuilt` step (`skip-unbuilt`) in the clone actions/checkout
# makes for it: blobless (`--filter=blob:none`), shallow and sparse, from a local
# origin. Lazy fetches are forbidden (GIT_NO_LAZY_FETCH), as an unauthenticated one is
# in a private repository, so every blob the step reads comes through its own fetch.
# Also: the step gives git the token for the server alone, and a read that fails (no
# origin) runs the checks, and the `code` output is "false" only on the step's answer.
# Then the rc-checked record end to end: publish-rc.yml's "Record the checked commit"
# step writes it to a local origin and rust-ci.yml's `rc` step (its github-script, run
# by Node with stand-ins for `core`, `exec` and `fetch`) honours it only when the OIDC
# token in it verifies; a bare ref, another key, audience, repository, workflow or age,
# and unreachable keys all run the checks. Tokens are signed with a key made here.
# `just templates` runs it; it needs bash 4, git 2.44 and Node 18 (on PATH, or the
# Actions runner's own, which a job container sees under /__e).
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

# The `code` output is "false" only on the step's positive answer: the job's output
# reads the step alone, and the workflow's turns anything but "false" (a skipped or
# failed classification, a fork's skipped job) into "true", so a promotion is never
# skipped for want of an answer.
grep -qxF "      code: \${{ steps.unbuilt.outputs.unbuilt == 'true' && 'false' || 'true' }}" "$wf/rust-ci.yml" && c=yes || c=no
check "code: false only when the step found nothing built" "$c" yes
grep -qxF "        value: \${{ jobs.tested.outputs.code == 'false' && 'false' || 'true' }}" "$wf/rust-ci.yml" && c=yes || c=no
check "code: the workflow's output is true unless the job said false" "$c" yes

# --- the rc-checked record (publish-rc.yml writes, rust-ci.yml's `rc` reads) --------
# The Actions runner's own Node: /__e in a job container, externals/ on the host.
node=$(command -v node || ls -d /__e/node*/bin/node /home/runner/externals/node*/bin/node 2>/dev/null | tail -n1 || true)
[ -n "$node" ] || { echo "FAIL rc-checked: no Node to run the rc step with"; exit 1; }
# The `rc` step's github-script and publish-rc.yml's two record steps.
awk '
  /^      - id: rc$/ { in_step = 1; next }
  in_step && /^      - / { exit }
  in_step && /^          script: \|$/ { in_run = 1; next }
  in_run && !/^            / && !/^$/ { exit }
  in_run { sub(/^            /, ""); print }
' "$wf/rust-ci.yml" >"$work/rc.js"
[ -s "$work/rc.js" ] || { echo "no rc script found" >&2; exit 1; }
awk '
  /^      - name: Record the checked commit$/ { in_step = 1; next }
  in_step && /^      - / { exit }
  in_step && /^        run: \|$/ { in_run = 1; next }
  in_run { sub(/^          /, ""); print }
' "$wf/publish-rc.yml" >"$work/record.sh"
[ -s "$work/record.sh" ] || { echo "no record script found" >&2; exit 1; }
grep -qF 'core.getIDToken(`owt-rc-checked:${process.env.SHA}:${process.env.GATE}`)' "$wf/publish-rc.yml" && c=yes || c=no
check "rc-checked: publish-rc.yml signs for the audience the rc step verifies" "$c" \
  "$(grep -qF 'aud !== `owt-rc-checked:${sha}:${gate}`' "$work/rc.js" && echo yes || echo no)"
grep -qE '^      id-token: write$' "$wf/publish-rc.yml" && c=yes || c=no
check "rc-checked: publish-rc.yml's job can mint the token" "$c" yes

cat >"$work/harness.cjs" <<'JS'
// mint <claims json>: prints an RS256 token with key $KEY (kid $KID).
// verify <script>: runs the rc step in the current directory against the keys in $JWKS
// ("down" for an issuer that answers 503); prints "checked" or "run".
const crypto = require("crypto"), fs = require("fs"), cp = require("child_process");
const [mode, arg] = process.argv.slice(2);
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
if (mode === "keys") {
  for (const name of ["good", "evil"]) {
    const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    fs.writeFileSync(`${arg}/${name}.pem`, privateKey.export({ type: "pkcs8", format: "pem" }));
    if (name === "good") fs.writeFileSync(`${arg}/jwks.json`, JSON.stringify({ keys: [{ ...publicKey.export({ format: "jwk" }), kid: "k1", alg: "RS256", use: "sig" }] }));
  }
} else if (mode === "mint") {
  const head = b64({ alg: "RS256", typ: "JWT", kid: process.env.KID || "k1" });
  const body = b64(JSON.parse(arg));
  const sig = crypto.sign("RSA-SHA256", Buffer.from(`${head}.${body}`), fs.readFileSync(process.env.KEY)).toString("base64url");
  process.stdout.write(`${head}.${body}.${sig}`);
} else {
  let checked = false;
  const core = { info: (m) => console.error(m), notice: (m) => console.error(m), setOutput: (k, v) => { if (k === "checked" && v === "true") checked = true; } };
  const exec = { getExecOutput: async (cmd, args, o) => { const r = cp.spawnSync(cmd, args, { env: o.env, encoding: "utf8" }); return { exitCode: r.status, stdout: r.stdout, stderr: r.stderr }; } };
  const fetch = async () => process.env.JWKS === "down" ? { ok: false, status: 503 } : { ok: true, json: async () => JSON.parse(fs.readFileSync(process.env.JWKS, "utf8")) };
  const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
  Promise.resolve().then(() => new AsyncFunction("require", "core", "exec", "fetch", fs.readFileSync(arg, "utf8"))(require, core, exec, fetch)).then(() => console.log(checked ? "checked" : "run"), (e) => { console.error(e); console.log("run"); });
}
JS
"$node" "$work/harness.cjs" keys "$work"

repo=o/app
appo="$work/$repo.git"
mkdir -p "$work/o" && git clone -q --bare "$src" "$appo"
x=$(git -C "$src" rev-parse "$base")
y=$sha
gate=0123456789abcdef
now=$(date +%s)
claims() { # claims [field=json]...: an honest record's claims with fields replaced
  local c
  c=$(printf '{"iss":"https://token.actions.githubusercontent.com","aud":"owt-rc-checked:%s:%s","repository":"%s","job_workflow_ref":"onewaytek/owt-stack/.github/workflows/publish-rc.yml@%s","iat":%s,"exp":%s}' \
    "$x" "$gate" "$repo" "$x" "$now" "$((now + 300))")
  for kv in "$@"; do c=$("$node" -e 'const c=JSON.parse(process.argv[1]); c[process.argv[2]]=JSON.parse(process.argv[3]); console.log(JSON.stringify(c))' "$c" "${kv%%=*}" "${kv#*=}"); done
  printf '%s' "$c"
}
mint() { KEY="$work/${KEY_NAME:-good}.pem" "$node" "$work/harness.cjs" mint "$1"; }
# record <jwt> [target]: publish-rc.yml's step, from a full clone, for <target> (X).
record() {
  local pub="$work/pub"
  rm -rf "$pub" "$work/tmp" && mkdir "$work/tmp" && git clone -q "$appo" "$pub"
  printf '%s' "$1" >"$work/tmp/rc-checked.jwt"
  (cd "$pub" && SHA="${2:-$x}" GATE="$gate" RUNNER_TEMP="$work/tmp" bash "$work/record.sh" >/dev/null 2>&1)
}
# verify [jwks]: the rc step in a checkout-style clone of X, as rc's release of X.
verify() {
  local co="$work/rc"
  rm -rf "$co" && git init -q "$co"
  git -C "$co" -c protocol.version=2 fetch -q --no-tags --filter=blob:none --depth=1 "file://$appo" "$x"
  git -C "$co" sparse-checkout set .github
  git -C "$co" checkout -q --detach FETCH_HEAD
  (cd "$co" && GATE="$gate" TOKEN=t GITHUB_SHA="$x" GITHUB_REPOSITORY="$repo" GITHUB_SERVER_URL="file://$work" \
    JWKS="${1:-$work/jwks.json}" "$node" "$work/harness.cjs" verify "$work/rc.js" 2>>"$work/rc.log")
}

record "$(mint "$(claims)")"
check "rc-checked: a record publish-rc.yml signed skips" "$(verify)" checked
check "rc-checked: it is the only record left" \
  "$(git -C "$appo" for-each-ref --format='%(objecttype)' refs/owt/rc-checked/ | tr '\n' ' ')" "tag "
check "rc-checked: the issuer's keys out of reach runs" "$(verify down)" run
record "$(mint "$(claims)")" "$y"
check "rc-checked: a signed record on another commit runs" "$(verify)" run
git -C "$appo" update-ref -d "$(git -C "$appo" for-each-ref --format='%(refname)' refs/owt/rc-checked/)"
git -C "$appo" update-ref "refs/owt/rc-checked/$gate/$now" "$x"
check "rc-checked: a bare ref on the commit (a push) runs" "$(verify)" run
record "$(KEY_NAME=evil mint "$(claims)")"
check "rc-checked: a token signed by another key runs" "$(verify)" run
record "$(KID=k2 mint "$(claims)")"
check "rc-checked: a key the issuer does not publish runs" "$(verify)" run
record "$(mint "$(claims aud="\"owt-rc-checked:$x:fedcba9876543210\"")")"
check "rc-checked: another gate runs" "$(verify)" run
record "$(mint "$(claims repository='"o/other"')")"
check "rc-checked: another repository runs" "$(verify)" run
record "$(mint "$(claims job_workflow_ref="\"$repo/.github/workflows/rc.yml@refs/heads/x\"")")"
check "rc-checked: a token another workflow minted runs" "$(verify)" run
record "$(mint "$(claims iss='"https://example.invalid"')")"
check "rc-checked: another issuer runs" "$(verify)" run
record "$(mint "$(claims iat=$((now - 43300)))")"
check "rc-checked: a token older than 12 hours runs" "$(verify)" run
record "$(printf '%s.%s.' "$(printf '{"alg":"none"}' | base64 -w0 | tr '+/' '-_' | tr -d =)" \
  "$(claims | base64 -w0 | tr '+/' '-_' | tr -d =)")"
check "rc-checked: an unsigned token runs" "$(verify)" run
record "$(mint "$(claims)")"
check "rc-checked: an honest record again skips" "$(verify)" checked

[ "$fails" = 0 ] || { echo "$fails rust-ci test(s) failed"; exit 1; }
echo "rust-ci tests passed"
