#!/usr/bin/env bash
# Proves bao-set.sh against a stand-in `oc` whose `exec … bao kv` keeps the secret in
# a JSON file: what a diff reports, what --apply writes (put, then patch), that
# @generate and @env keep what OpenBao holds, that a refused token is an error and
# not an absent secret, and that no value reaches the output. `just templates` runs
# it; it needs bash 4 and jq, and no cluster. The stand-in keeps one secret whatever
# the path, so the KEY case checks only the path read.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin"
cat >"$work/bin/oc" <<'OC'
#!/usr/bin/env bash
# oc -n NS exec -i POD -- sh -c SCRIPT bao kv OP -mount=M [-format=json] PATH [-]
shift 9
read -r tok
[ "$tok" = good-token ] || { echo "permission denied" >&2; exit 2; }
op=$3; last=${*: -1}; [ "$last" = - ] && last=${*: -2:1}
echo "$op $last" >>"$STORE.log"
case $op in
  get) [ -f "$STORE" ] || { echo "No value found at $last" >&2; exit 2; }
       jq '{data: {data: .}}' "$STORE" ;;
  put) cat >"$STORE" ;;
  patch) jq -s '.[0] * .[1]' "$STORE" - >"$STORE.new" && mv "$STORE.new" "$STORE" ;;
esac
OC
chmod +x "$work/bin/oc"
export PATH="$work/bin:$PATH" STORE="$work/store.json"

fails=0
check() { # description, expected exit, command...
  local want=$2 got=0 desc=$1; shift 2
  "$@" >"$work/out" 2>&1 || got=$?
  if [ "$got" != "$want" ]; then
    echo "FAIL: $desc: exit $got, want $want"; sed 's/^/    /' "$work/out"; fails=1
  else
    echo "ok: $desc"
  fi
}
has() { grep -qF -- "$1" "$work/out" || { echo "FAIL: output lacks '$1'"; fails=1; }; }
lacks() { ! grep -qF -- "$1" "$work/out" || { echo "FAIL: output shows '$1'"; fails=1; }; }
set_() { echo good-token | "$here/bao-set.sh" "$@"; }

printf 'URL=https://myapp.example\nSESSION_SECRET=@generate\nPROVIDER_TOKEN=@env\n# note\nQUOTED="a b"\n' >"$work/env.env"
export PROVIDER_TOKEN=provider-value

check "diff of a new secret" 1 set_ myapp rc "$work/env.env"
has "URL: created"; has "run with --apply"; lacks provider-value
[ ! -f "$STORE" ] || { echo "FAIL: a diff wrote"; fails=1; }

check "apply creates it" 0 set_ myapp rc "$work/env.env" --apply
has "written (put)"; lacks provider-value
[ "$(jq -r .QUOTED "$STORE")" = "a b" ] || { echo "FAIL: quotes not taken off"; fails=1; }
secret=$(jq -r .SESSION_SECRET "$STORE")
[ "${#secret}" -ge 80 ] || { echo "FAIL: @generate made no 64-byte value"; fails=1; }

printf 'URL=https://other.example\nSESSION_SECRET=@generate\nPROVIDER_TOKEN=@env\nQUOTED="a b"\n' >"$work/env.env"
echo '{"HAND_SET": "kept"}' | jq -s '.[0] * .[1]' "$STORE" - >"$STORE.new" && mv "$STORE.new" "$STORE"
check "apply patches what changed" 0 env PROVIDER_TOKEN= "$here/bao-set.sh" myapp rc "$work/env.env" --apply <<<good-token
has "URL: set"; has "SESSION_SECRET: kept"; has "PROVIDER_TOKEN: kept"; has "QUOTED: unchanged"
has "written (patch)"
[ "$(jq -r .SESSION_SECRET "$STORE")" = "$secret" ] || { echo "FAIL: @generate replaced a value"; fails=1; }
[ "$(jq -r .HAND_SET "$STORE")" = kept ] || { echo "FAIL: an unlisted key was dropped"; fails=1; }
[ "$(jq -r .PROVIDER_TOKEN "$STORE")" = provider-value ] || { echo "FAIL: an empty @env replaced a value"; fails=1; }

check "nothing to change" 0 set_ myapp rc "$work/env.env"
has "nothing to change"

check "a refused token is an error" 2 env bash -c "echo bad-token | '$here/bao-set.sh' myapp rc '$work/env.env'"
has "permission denied"

check "KEY picks the secret" 0 env KEY=redis bash -c "echo good-token | '$here/bao-set.sh' myapp rc '$work/env.env'"
grep -q 'get apps/myapp/rc/redis' "$STORE.log" || { echo "FAIL: KEY=redis read another path"; fails=1; }

printf 'NEW=@env\n' >"$work/env2.env"
check "@env with nothing to keep is refused" 2 env -u NEW bash -c "echo good-token | '$here/bao-set.sh' myapp rc '$work/env2.env'"
printf 'not a pair\n' >"$work/env3.env"
check "a malformed line is refused" 2 set_ myapp rc "$work/env3.env"
check "a bad name is refused" 2 set_ 'My App' rc "$work/env.env"

[ "$fails" = 0 ] && echo "bao-set-test: ok" || { echo "bao-set-test: FAILED"; exit 1; }
