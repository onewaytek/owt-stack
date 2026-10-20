#!/usr/bin/env bash
# env.sh against a stand-in `oc` that keeps one Secret in a file: what is created,
# set, kept and left alone; that a generated key is made once; that no value is
# printed or put on a command line; and the refusals.
#
#   templates/openshift/env-test.sh       (`just templates` runs it)
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/deploy"
cp "$here/env.sh" "$work/deploy/"

cat >"$work/bin/oc" <<'FAKE'
#!/usr/bin/env bash
# The Secret is $FAKE_SECRET, a KEY=base64 line each; no file is no Secret. Every call
# is logged by its arguments, which is where a value must never appear.
set -euo pipefail
printf 'oc %s\n' "$*" >>"$FAKE_LOG"
yaml_pairs() { sed -nE 's/^  "([^"]+)": "([^"]*)"$/\1=\2/p' "$1"; }
case "$*" in
  "-n myapp-staging get secret myapp-env --ignore-not-found -o go-template="*)
    [ -f "$FAKE_SECRET" ] || exit 0
    echo myapp-env
    cat "$FAKE_SECRET"
    ;;
  "-n myapp-staging create -f "*)
    [ ! -f "$FAKE_SECRET" ] || { echo "fake: already exists" >&2; exit 1; }
    cp "$5" "$FAKE_SECRET.create"
    yaml_pairs "$5" >"$FAKE_SECRET"
    ;;
  "-n myapp-staging patch secret/myapp-env --type=merge --patch-file="*)
    [ -f "$FAKE_SECRET" ] || { echo "fake: not found" >&2; exit 1; }
    cp "${6#--patch-file=}" "$FAKE_SECRET.patch"
    yaml_pairs "${6#--patch-file=}" | while IFS='=' read -r k v; do
      sed -i "/^$k=/d" "$FAKE_SECRET"
      echo "$k=$v" >>"$FAKE_SECRET"
    done
    ;;
  *) echo "unexpected: oc $*" >&2; exit 9 ;;
esac
FAKE
chmod +x "$work/bin/oc"

log=$work/log
export FAKE_SECRET=$work/secret
run() {
  : >"$log"
  PATH=$work/bin:$PATH FAKE_LOG=$log bash "$work/deploy/env.sh" "$@" >"$work/out" 2>"$work/err"
}
fail() { echo "FAIL: $*" >&2; echo "--- out"; cat "$work/out"; echo "--- err"; cat "$work/err"; echo "--- log"; cat "$log"; exit 1; }
held() { grep -E "^$1=" "$FAKE_SECRET" | cut -d= -f2- | base64 -d; }
stored() { grep -E "^$1=" "$FAKE_SECRET" | cut -d= -f2-; }

printf 'NAME=myapp\nNAMESPACE=myapp-staging\nPORT=8000\n' >"$work/deploy/params.env"
cat >"$work/deploy/env.env" <<'ENV'
# The app's environment.
PUBLIC_BASE_URL="https://myapp.example"
SESSION_SECRET=@generate
PROVIDER_TOKEN=@env
ENV

# 1. Without the Secret: a diff reports and exits 1, writing nothing.
rc=0; PROVIDER_TOKEN=tok-1 run || rc=$?
[ "$rc" -eq 1 ] || fail "a diff with changes exits 1 (got $rc)"
grep -qx "created PUBLIC_BASE_URL" "$work/out" || fail "reports PUBLIC_BASE_URL"
grep -qx "created SESSION_SECRET (generated)" "$work/out" || fail "reports SESSION_SECRET"
grep -qx "created PROVIDER_TOKEN" "$work/out" || fail "reports PROVIDER_TOKEN"
[ ! -f "$FAKE_SECRET" ] || fail "a diff wrote the Secret"

# 2. --apply creates it, with the three keys; no value reaches the output or an argument.
PROVIDER_TOKEN=tok-1 run --apply || fail "apply"
[ "$(held PUBLIC_BASE_URL)" = "https://myapp.example" ] || fail "a literal is written as given"
[ "$(held PROVIDER_TOKEN)" = "tok-1" ] || fail "@env takes the caller's variable"
generated=$(stored SESSION_SECRET)
[ "${#generated}" -eq 88 ] || fail "a generated key is 64 bytes (88 base64 characters)"
for v in "https://myapp.example" tok-1 "$generated"; do
  grep -qF -- "$v" "$work/out" "$work/err" "$log" && fail "a value was printed or passed as an argument"
done

# 3. Again: nothing changes, and the generated key is the one made before.
run || fail "a second run exits 0 (no change)"
grep -qx "no change" "$work/out" || fail "says no change"
grep -qx "kept SESSION_SECRET" "$work/out" || fail "keeps the generated key"
grep -qx "kept PROVIDER_TOKEN" "$work/out" || fail "@env unset keeps the held value"
grep -qx "unchanged PUBLIC_BASE_URL" "$work/out" || fail "reports an unchanged literal"
[ "$(stored SESSION_SECRET)" = "$generated" ] || fail "a generated key was regenerated"

# 4. A changed literal and a new @env value are set; a key set by hand is left alone;
#    the generated key still survives. An apply patches an existing Secret.
echo "EXTRA=$(printf %s hand | base64 -w0)" >>"$FAKE_SECRET"
sed -i 's#https://myapp.example#https://myapp.example/v2#' "$work/deploy/env.env"
rc=0; PROVIDER_TOKEN=tok-2 run || rc=$?
[ "$rc" -eq 1 ] || fail "a changed value is a change (got $rc)"
grep -qx "set PUBLIC_BASE_URL" "$work/out" || fail "reports the changed literal"
grep -qx "set PROVIDER_TOKEN" "$work/out" || fail "reports the new @env value"
PROVIDER_TOKEN=tok-2 run --apply || fail "apply over an existing Secret"
grep -q "patch secret/myapp-env" "$log" || fail "an existing Secret is patched"
[ "$(held PUBLIC_BASE_URL)" = "https://myapp.example/v2" ] || fail "the literal was patched"
[ "$(held PROVIDER_TOKEN)" = "tok-2" ] || fail "the @env value was patched"
[ "$(held EXTRA)" = "hand" ] || fail "a key not in the file was touched"
[ "$(stored SESSION_SECRET)" = "$generated" ] || fail "the generated key changed on a patch"

# 5. Refusals: a value with a newline, an @env key neither set nor held, an unknown
#    @word, a missing file, a missing NAME, an unknown flag. None writes anything.
rm "$FAKE_SECRET"
printf 'A=@env\n' >"$work/deploy/env.env"
rc=0; A=$'one\ntwo' run --apply || rc=$?; [ "$rc" -eq 2 ] || fail "an @env value with a newline exits 2 (got $rc)"
grep -q "A: a value with a newline is refused" "$work/err" || fail "names the multi-line key"
rc=0; run --apply || rc=$?; [ "$rc" -eq 2 ] || fail "an unset @env key exits 2 (got $rc)"
grep -q 'A=@env: $A is not set, and myapp-env has no A' "$work/err" || fail "names the unset key"
# @env reads the caller's environment, not the script's variables (secret, name,
# RANDOM, values) nor an empty variable.
for k in secret name RANDOM values; do
  printf '%s=@env\n' "$k" >"$work/deploy/env.env"
  rc=0; run --apply || rc=$?; [ "$rc" -eq 2 ] || fail "$k=@env took a script variable (got $rc)"
  grep -q "is not set, and myapp-env has no $k" "$work/err" || fail "names the unset $k"
done
printf 'TOK=@env\n' >"$work/deploy/env.env"
rc=0; TOK= run --apply || rc=$?; [ "$rc" -eq 2 ] || fail "an empty @env counts as unset (got $rc)"
[ ! -f "$FAKE_SECRET" ] || fail "an empty @env wrote the Secret"
printf 'TOK=%s\n' "$(printf held | base64 | tr -d '\n')" >"$FAKE_SECRET"
rc=0; TOK= run --apply || rc=$?; [ "$rc" -eq 0 ] || fail "an empty @env keeps the held value (got $rc)"
grep -qx "kept TOK" "$work/out" || fail "reports the kept TOK"
[ "$(held TOK)" = held ] || fail "an empty @env overwrote the held value"
rm "$FAKE_SECRET"
# A generator that fails is a refusal (2), not the diff's 1.
printf 'G=@generate\n' >"$work/deploy/env.env"
mkdir "$work/broken"
printf '#!/bin/sh\nexit 1\n' >"$work/broken/head"
chmod +x "$work/broken/head"
: >"$log"
rc=0; PATH=$work/broken:$work/bin:$PATH FAKE_LOG=$log bash "$work/deploy/env.sh" >"$work/out" 2>"$work/err" || rc=$?
[ "$rc" -eq 2 ] || fail "a failing generator exits 2 (got $rc)"
grep -q "G=@generate: could not make a value" "$work/err" || fail "names the failed generator"
# A patch to an existing Secret leaves its type alone.
printf 'K=%s\n' "$(printf v | base64 | tr -d '\n')" >"$FAKE_SECRET"
printf 'K=new\n' >"$work/deploy/env.env"
run --apply || fail "patch an existing Secret"
grep -q "type:\|kind:" "$FAKE_SECRET.patch" && fail "the patch repeats the Secret's immutable type"
[ "$(held K)" = new ] || fail "the existing Secret was patched"
rm "$FAKE_SECRET"
printf 'K=v\n' >"$work/deploy/env.env"
run --apply || fail "create"
grep -q "type: Opaque" "$FAKE_SECRET.create" || fail "a create sets the type"
rm "$FAKE_SECRET"
printf 'A=@random\n' >"$work/deploy/env.env"
rc=0; run || rc=$?; [ "$rc" -eq 2 ] || fail "an unknown @word exits 2 (got $rc)"
grep -q "is reserved" "$work/err" || fail "names the reserved prefix"
printf 'not a pair\n' >"$work/deploy/env.env"
rc=0; run || rc=$?; [ "$rc" -eq 2 ] || fail "a malformed line exits 2 (got $rc)"
rc=0; ENV_FILE=$work/none run || rc=$?; [ "$rc" -eq 2 ] || fail "a missing env.env exits 2 (got $rc)"
printf 'A=x\n' >"$work/deploy/env.env"
printf 'NAMESPACE=myapp-staging\n' >"$work/deploy/params.env"
rc=0; run || rc=$?; [ "$rc" -eq 2 ] || fail "a missing NAME exits 2 (got $rc)"
rc=0; run --force || rc=$?; [ "$rc" -eq 2 ] || fail "an unknown flag exits 2"
[ ! -f "$FAKE_SECRET" ] || fail "a refusal wrote the Secret"

echo "env.sh: ok"
