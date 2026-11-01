#!/usr/bin/env bash
# Make the app's environment Secret, $NAME-env, from a file of its settings, and show
# what that would change, or do it.
#
#   deploy/openshift/env.sh                 # what would change
#   deploy/openshift/env.sh --apply         # create or patch the Secret
#
# NAME and NAMESPACE come from params.env (PARAMS=path names another). The Secret's
# keys are listed in env.env beside the script (ENV_FILE=path names another), one
# KEY=VALUE a line, read as params.env's are (`#` comments, one pair of quotes off a
# value). A value is one of:
#
#   PUBLIC_BASE_URL=https://myapp.example   written as given: the file owns the key,
#                                           and a changed value is patched in
#   SESSION_SECRET=@generate                64 random bytes, base64, made once: a key
#                                           the Secret already holds is never touched
#   PROVIDER_TOKEN=@env                     the caller's exported variable of that name,
#                                           written when set and not empty; kept when not
#                                           and the Secret has it (CI often exports an
#                                           unavailable secret as an empty string)
#
# The file is meant to be committed, so it holds no secret value: those are @generate
# or @env. A key in the Secret that the file does not list is left alone (so is a
# value set by hand with `oc set data`). Values are never printed, only each key and
# what happens to it: created, set, kept or unchanged. They reach oc in a file, never
# as arguments. A value with a newline is refused (an env file is a line a key), and
# so is an @env key that is neither set nor already in the Secret. params.env is
# read leniently, for NAME and NAMESPACE alone; apply.sh is its strict reader. Two
# runs at once on one Secret race: the last patch wins.
#
# A Secret's change reaches pods only when they start: `oc rollout restart` after.
#
# Exit status, as apply.sh's: 0 when nothing would change (or it was applied), 1 when
# the diff found changes, 2 for a refusal or a failed oc. Needs bash 4 or later.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
params=${PARAMS:-$here/params.env}
envfile=${ENV_FILE:-$here/env.env}
mode=diff
for flag in "$@"; do
  case "$flag" in
    --apply) mode=apply ;;
    --diff) mode=diff ;;
    *) echo "usage: $0 [--diff | --apply]" >&2; exit 2 ;;
  esac
done
for f in "$params" "$envfile"; do
  [ -f "$f" ] || { echo "$f: no such file" >&2; exit 2; }
done
command -v oc >/dev/null || { echo "oc is not on the PATH" >&2; exit 2; }
[ "${BASH_VERSINFO[0]}" -ge 4 ] || { echo "env.sh needs bash 4 or later" >&2; exit 2; }
patch=$(mktemp)
trap 'rm -f "$patch"' EXIT

# `encode`: stdin as one line of base64; `generate`: 64 random bytes as base64 text,
# which the Secret stores encoded once more, as every value, so the app reads text. A
# failure in either pipeline is the caller's to refuse (exit 2, not the 1 of a diff).
encode() { base64 | tr -d '\n'; }
generate() { head -c 64 /dev/urandom | encode; }

# `parse FILE`: the file's pairs, in order, into `keys` and `values`.
declare -a keys=()
declare -A values=()
parse() {
  local file=$1 line key value
  keys=()
  values=()
  while IFS= read -r line || [ -n "$line" ]; do
    line=${line%$'\r'}
    [[ $line =~ ^[[:space:]]*(#|$) ]] && continue
    if [[ $line =~ ^([A-Za-z_][A-Za-z0-9_.-]*)=(.*)$ ]]; then
      key=${BASH_REMATCH[1]}
      value=${BASH_REMATCH[2]}
      if [[ $value =~ ^\"(.*)\"$ || $value =~ ^\'(.*)\'$ ]]; then
        value=${BASH_REMATCH[1]}
      fi
      [ "${values[$key]+set}" ] || keys+=("$key")
      values[$key]=$value
    else
      echo "$file: not a KEY=VALUE line" >&2
      exit 2
    fi
  done <"$file"
}

# NAME and NAMESPACE from params.env; its other keys are the templates'.
parse "$params"
name=${values[NAME]:-}
namespace=${values[NAMESPACE]:-}
[ -n "$name" ] || { echo "$params must set NAME" >&2; exit 2; }
[ -n "$namespace" ] || { echo "$params must set NAMESPACE" >&2; exit 2; }
secret=$name-env
parse "$envfile"
[ "${#keys[@]}" -gt 0 ] || { echo "$envfile lists no key" >&2; exit 2; }

# The Secret as it stands: its name on the first line when it exists, then
# KEY=base64 a line.
declare -A held=()
exists=no
listing=$(oc -n "$namespace" get secret "$secret" --ignore-not-found \
  -o go-template='{{.metadata.name}}{{"\n"}}{{range $k, $v := .data}}{{$k}}={{$v}}{{"\n"}}{{end}}') ||
  { echo "oc get secret/$secret failed" >&2; exit 2; }
if [ -n "$listing" ]; then
  exists=yes
  while IFS= read -r line; do
    [ "$line" = "$secret" ] || held[${line%%=*}]=${line#*=}
  done <<<"$listing"
fi

# What each key becomes: `change[key]` holds the base64 value to write, for a key
# that is created or set; `report` the line for each.
declare -A change=()
report=()
for key in "${keys[@]}"; do
  value=${values[$key]}
  case $value in
    @generate)
      if [ "${held[$key]+set}" ]; then
        report+=("kept $key")
      else
        change[$key]=$(generate | encode) || { echo "$key=@generate: could not make a value" >&2; exit 2; }
        report+=("created $key (generated)")
      fi
      continue
      ;;
    @env)
      [[ $key =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] ||
        { echo "$envfile: $key=@env: $key is not a variable name" >&2; exit 2; }
      # printenv reads the exported environment alone: `${!key}` would also find the
      # script's own variables (secret, name, PWD, RANDOM).
      if [ -n "$(printenv "$key" || true)" ]; then
        [ "$(printenv "$key" | wc -l)" -le 1 ] ||
          { echo "$key: a value with a newline is refused" >&2; exit 2; }
        value=$(printenv "$key")
      elif [ "${held[$key]+set}" ]; then
        report+=("kept $key")
        continue
      else
        echo "$key=@env: \$$key is not set, and $secret has no $key" >&2
        exit 2
      fi
      ;;
    @*)
      echo "$envfile: $key=$value: a value starting with @ is reserved (@generate, @env)" >&2
      exit 2
      ;;
  esac
  if [[ $value == *$'\n'* ]]; then
    echo "$key: a value with a newline is refused" >&2
    exit 2
  fi
  encoded=$(printf '%s' "$value" | encode) || { echo "$key: could not encode the value" >&2; exit 2; }
  if [ "${held[$key]+set}" ] && [ "${held[$key]}" = "$encoded" ]; then
    report+=("unchanged $key")
  elif [ "${held[$key]+set}" ]; then
    change[$key]=$encoded
    report+=("set $key")
  else
    change[$key]=$encoded
    report+=("created $key")
  fi
done

echo "== secret/$secret in $namespace ($exists)"
printf '%s\n' "${report[@]}"
[ "${#change[@]}" -gt 0 ] || { echo "no change"; exit 0; }
[ "$mode" = apply ] || exit 1

# A file, not arguments: a value on a command line shows in the process list. A merge
# patch adds or replaces these keys and leaves the rest, and any label, as they are.
{
  # `type` is immutable, so a patch leaves it to the Secret; a create sets it.
  if [ "$exists" = no ]; then
    echo "apiVersion: v1"
    echo "kind: Secret"
    echo "metadata: {name: \"$secret\", namespace: \"$namespace\"}"
    echo "type: Opaque"
  fi
  echo "data:"
  for key in "${!change[@]}"; do
    echo "  \"$key\": \"${change[$key]}\""
  done
} >"$patch"
if [ "$exists" = yes ]; then
  oc -n "$namespace" patch "secret/$secret" --type=merge --patch-file="$patch" >/dev/null ||
    { echo "oc patch failed on secret/$secret" >&2; exit 2; }
else
  oc -n "$namespace" create -f "$patch" >/dev/null ||
    { echo "oc create failed on secret/$secret" >&2; exit 2; }
fi
echo "applied"
