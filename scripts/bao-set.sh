#!/usr/bin/env bash
# Write an app environment's secrets into OpenBao, where charts/owt-app's
# ExternalSecrets read them: env.sh's job for an app deployed with GitOps
# (README, "Deploying with GitOps": "Secrets from OpenBao").
#
#   scripts/bao-set.sh myapp rc env.env            # what would change
#   scripts/bao-set.sh myapp rc env.env --apply    # write it
#
# The file is env.sh's format, one KEY=VALUE a line (`#` comments, one pair of quotes
# off a value), with one more kind of value:
#
#   PUBLIC_BASE_URL=https://myapp.example   written as given; a changed value is set
#   SESSION_SECRET=@generate                64 random bytes, base64, made once: a key
#                                           OpenBao already holds is never touched
#   PROVIDER_TOKEN=@env                     the caller's exported variable of that name,
#                                           written when set and not empty, else kept
#   SMTP_PASSWORD=@prompt                   typed at a hidden prompt (empty: kept)
#
# The secret is <mount>/apps/<app>/<env>/<key>: KEY defaults to `env` (the Secret
# <name>-env); pass KEY=db-runtime, redis or tunnel, or an `externalSecrets.extra`
# key, for the others. MOUNT defaults to `kv`. A key in OpenBao that the file does not
# list is left alone.
#
# Values are never printed, only each key and what happens to it: created, set, kept
# or unchanged. Every value, the OpenBao token included, reaches the OpenBao pod on
# stdin (`oc exec -i`), never in argv, the environment of a local process or a file.
# The token, one from `bao login -method=userpass username=<you>` with write access to
# the path, is asked for at a hidden prompt, or read from stdin's first line when
# stdin is not a terminal.
#
# OPENBAO_NAMESPACE (openbao) and OPENBAO_POD (openbao-0) say where OpenBao runs; the
# caller is logged in with `oc` as someone who may `oc exec` there. A Secret's change
# reaches pods only when they start: ESO refreshes the Secret within its
# refreshInterval, then bump `podAnnotations.rotation` in the deployments repository.
#
# Exit status, as env.sh's: 0 when nothing would change (or it was written), 1 when
# the diff found changes, 2 for a refusal or a failed command. Needs bash 4, jq and oc.
set -euo pipefail

usage() { echo "usage: $0 <app> <env> <file> [--diff | --apply]" >&2; exit 2; }
[ $# -ge 3 ] || usage
app=$1 env=$2 file=$3; shift 3
mode=diff
for flag in "$@"; do
  case "$flag" in
    --apply) mode=apply ;;
    --diff) mode=diff ;;
    *) usage ;;
  esac
done
name_re='^[a-z0-9]([a-z0-9-]*[a-z0-9])?$'
key=${KEY:-env} mount=${MOUNT:-kv}
for v in "$app" "$env" "$key" "$mount"; do
  [[ $v =~ $name_re ]] || { echo "'$v' is not a name" >&2; exit 2; }
done
[ -f "$file" ] || { echo "$file: no such file" >&2; exit 2; }
for c in oc jq; do command -v "$c" >/dev/null || { echo "$c is not on the PATH" >&2; exit 2; }; done
[ "${BASH_VERSINFO[0]}" -ge 4 ] || { echo "bao-set.sh needs bash 4 or later" >&2; exit 2; }
ns=${OPENBAO_NAMESPACE:-openbao} pod=${OPENBAO_POD:-openbao-0}
path="apps/$app/$env/$key"

# Runs a bao command in the pod with the token as stdin's first line; the rest of
# stdin is the command's.
bao() {
  { printf '%s\n' "$token"; cat; } | oc -n "$ns" exec -i "$pod" -- \
    sh -c 'read -r BAO_TOKEN; export BAO_TOKEN; exec bao "$@"' bao "$@"
}

# At a hidden prompt, or as stdin's first line when stdin is not a terminal (piped
# from a password manager).
if [ -t 0 ]; then
  IFS= read -r -s -p "OpenBao token (bao login -method=userpass): " token; echo >&2
else
  IFS= read -r token || true
fi
[ -n "$token" ] || { echo "empty token" >&2; exit 2; }

# What OpenBao holds now: {} when the secret does not exist yet.
err=$(mktemp); trap 'rm -f "$err"' EXIT
if current=$(bao kv get -mount="$mount" -format=json "$path" </dev/null 2>"$err"); then
  current=$(jq -c '.data.data // {}' <<<"$current") || exit 2
  exists=1
elif grep -q 'No value found' "$err"; then
  current='{}' exists=0
else
  # A refused token, a wrong mount, an unreachable pod: never mistaken for "absent".
  echo "reading $mount/$path failed:" >&2; cat "$err" >&2; exit 2
fi

updates='{}' changed=0
lineno=0
while IFS= read -r line || [ -n "$line" ]; do
  lineno=$((lineno + 1))
  line=${line%$'\r'}
  [[ $line =~ ^[[:space:]]*(#|$) ]] && continue
  [[ $line =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]] \
    || { echo "$file:$lineno: not KEY=VALUE" >&2; exit 2; }
  k=${BASH_REMATCH[1]} v=${BASH_REMATCH[2]}
  if [[ $v =~ ^\"(.*)\"$ || $v =~ ^\'(.*)\'$ ]]; then v=${BASH_REMATCH[1]}; fi
  have=$(jq -r --arg k "$k" 'has($k)' <<<"$current")
  case "$v" in
    @generate)
      if [ "$have" = true ]; then echo "$k: kept"; continue; fi
      v=$(head -c 64 /dev/urandom | base64 | tr -d '\n') ;;
    @env)
      if [ -z "${!k:-}" ]; then
        [ "$have" = true ] || { echo "$k: @env, but \$$k is not set and OpenBao has no value" >&2; exit 2; }
        echo "$k: kept"; continue
      fi
      v=${!k} ;;
    @prompt)
      IFS= read -r -s -p "$k (empty keeps the current value): " v </dev/tty; echo >&2
      if [ -z "$v" ]; then
        [ "$have" = true ] || { echo "$k: no value typed and OpenBao has none" >&2; exit 2; }
        echo "$k: kept"; continue
      fi ;;
  esac
  [[ $v != *$'\n'* ]] || { echo "$k: a value with a newline is refused" >&2; exit 2; }
  if [ "$have" = true ] && [ "$(jq -r --arg k "$k" '.[$k]' <<<"$current")" = "$v" ]; then
    echo "$k: unchanged"; continue
  fi
  if [ "$have" = true ]; then echo "$k: set"; else echo "$k: created"; fi
  # The value goes to jq on stdin, never in its argv.
  updates=$(printf '%s\n%s\n' "$updates" "$v" | jq -c -n -R --arg k "$k" 'input as $u | input as $v | ($u | fromjson) + {($k): $v}')
  changed=1
done <"$file"

if [ "$changed" = 0 ]; then echo "$mount/$path: nothing to change"; exit 0; fi
if [ "$mode" = diff ]; then echo "$mount/$path: run with --apply to write"; exit 1; fi
# patch keeps the keys the file does not list; put creates the secret.
if [ "$exists" = 1 ]; then op=patch; else op=put; fi
bao kv "$op" -mount="$mount" "$path" - <<<"$updates" >/dev/null || exit 2
echo "$mount/$path: written ($op)"
