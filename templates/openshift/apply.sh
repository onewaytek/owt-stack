#!/usr/bin/env bash
# Render owt-stack's OpenShift templates for one app from its parameters, and show
# what an apply would change, or apply it.
#
#   deploy/openshift/apply.sh            # oc diff: what would change
#   deploy/openshift/apply.sh --apply    # oc apply
#
# Copy this script and the templates it reads into the app's deploy/openshift/, and
# keep the app's parameters beside them in params.env, one KEY=VALUE a line (a `#`
# starts a comment; a value is taken as written, quotes included). Every template
# parameter the app sets is a key there, NAME and NAMESPACE first:
#
#   NAME=myapp
#   NAMESPACE=myapp
#   IMAGE=ghcr.io/onewaytek/myapp
#   CHANNEL=latest
#   PORT=8000
#   POSTGRES_MAJOR=18
#
# Each template present beside the script is rendered with the keys it declares
# (`oc process --parameters` says which), so one file holds the whole deploy's
# configuration, and the apply that upgrades Postgres in place cannot mistype it. A
# name two templates declare means one thing in both (NAME, NAMESPACE, CHANNEL,
# DB_SUFFIX, MEMORY_LIMIT: a job's own goes in its jobs/<JOB>.env):
#
#   app.yaml         always
#   redis.yaml       when present
#   monitoring.yaml  when present (needs monitoring-edit: a cluster admin runs it)
#   egress.yaml      when present: for the app's pods (POD=NAME), and each task's
#   cronjob.yaml     when present: once per jobs/<JOB>.env, whose lines (JOB,
#                    SCHEDULE, ARGS, and any override) are read over params.env
#
# Upgrading owt-stack is "copy the templates again, keep params.env". The script
# never writes a Secret: the app's environment ($NAME-env) and a Redis password are
# made by hand, as the templates' headers say.
#
# Exit status: 0 when nothing would change (or everything applied), 1 when a diff
# found changes, anything else for an error. `oc diff` on a cluster the objects are
# not on yet shows every object as new.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
params=${PARAMS:-$here/params.env}
mode=diff
case "${1:-}" in
  "") ;;
  --apply) mode=apply ;;
  --diff) ;;
  *) echo "usage: $0 [--diff | --apply]" >&2; exit 2 ;;
esac
[ -f "$params" ] || { echo "$params: no such file (NAME=… lines, one per template parameter)" >&2; exit 2; }
command -v oc >/dev/null || { echo "oc is not on the PATH" >&2; exit 2; }

# The parameters, in a file's order, later lines winning: `read_env FILE...` fills
# the associative array `given`.
declare -A given=()
read_env() {
  local file line key value
  for file in "$@"; do
    while IFS= read -r line || [ -n "$line" ]; do
      line=${line%$'\r'}
      [[ $line =~ ^[[:space:]]*(#|$) ]] && continue
      if [[ $line =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
        key=${BASH_REMATCH[1]}
        value=${BASH_REMATCH[2]}
        given[$key]=$value
      else
        echo "$file: not a KEY=VALUE line: $line" >&2
        exit 2
      fi
    done <"$file"
  done
}

# `-p KEY=VALUE` for each parameter `template` declares that `given` holds; a
# required one that is missing is left for `oc process` to refuse by name.
args_for() {
  local template=$1 name
  args=()
  while IFS= read -r name; do
    [ -n "$name" ] || continue
    if [ "${given[$name]+set}" ]; then
      args+=(-p "$name=${given[$name]}")
    fi
  done < <(oc process --local -f "$template" --parameters | awk 'NR > 1 { print $1 }')
}

status=0
# Render `template` and diff or apply it, naming it in the output.
run() {
  local template=$1 label=$2
  args_for "$template"
  echo "== $label"
  if [ "$mode" = apply ]; then
    oc process --local -f "$template" "${args[@]}" -o yaml | oc apply -f -
  else
    # oc diff exits 1 on differences, which is an answer, not a failure.
    local rc=0
    oc process --local -f "$template" "${args[@]}" -o yaml | oc diff -f - || rc=$?
    case $rc in
      0) echo "no change" ;;
      1) status=1 ;;
      *) echo "oc diff failed ($rc)" >&2; exit "$rc" ;;
    esac
  fi
}

read_env "$params"
: "${given[NAME]:?params.env must set NAME}" "${given[NAMESPACE]:?params.env must set NAMESPACE}"

run "$here/app.yaml" "app.yaml"
[ -f "$here/redis.yaml" ] && run "$here/redis.yaml" "redis.yaml"
[ -f "$here/monitoring.yaml" ] && run "$here/monitoring.yaml" "monitoring.yaml (needs monitoring-edit)"
if [ -f "$here/egress.yaml" ]; then
  given[POD]=${given[NAME]}
  run "$here/egress.yaml" "egress.yaml for ${given[POD]}"
  unset 'given[POD]'
fi
if [ -f "$here/cronjob.yaml" ]; then
  shopt -s nullglob
  jobs=("$here"/jobs/*.env)
  shopt -u nullglob
  [ "${#jobs[@]}" -gt 0 ] || echo "cronjob.yaml is here but jobs/ holds no <JOB>.env: no task rendered" >&2
  for job in "${jobs[@]}"; do
    # The job's lines over the app's; nothing a job sets leaks into the next.
    declare -A app_given=()
    for k in "${!given[@]}"; do app_given[$k]=${given[$k]}; done
    read_env "$job"
    : "${given[JOB]:?$job must set JOB}"
    run "$here/cronjob.yaml" "cronjob.yaml for ${given[JOB]}"
    if [ -f "$here/egress.yaml" ]; then
      given[POD]="${given[NAME]}-${given[JOB]}"
      run "$here/egress.yaml" "egress.yaml for ${given[POD]}"
    fi
    unset given
    declare -A given=()
    for k in "${!app_given[@]}"; do given[$k]=${app_given[$k]}; done
  done
fi
exit "$status"
