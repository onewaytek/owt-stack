#!/usr/bin/env bash
# Render owt-stack's OpenShift templates for one app from its parameters, and show
# what an apply would change, or apply it.
#
#   deploy/openshift/apply.sh                 # oc diff: what would change
#   deploy/openshift/apply.sh --apply         # oc apply
#   deploy/openshift/apply.sh --monitoring    # monitoring.yaml too (either mode)
#
# Copy this script and the templates it reads into the app's deploy/openshift/, and
# keep the app's parameters beside them in params.env, one KEY=VALUE a line (a `#`
# starts a comment; one pair of quotes around a value comes off, as in a shell, and
# the rest is taken as written). Every template parameter the app sets is a key
# there, NAME and NAMESPACE first:
#
#   NAME=myapp
#   NAMESPACE=myapp
#   IMAGE=ghcr.io/onewaytek/myapp
#   CHANNEL=latest
#   PORT=8000
#   POSTGRES_MAJOR=18
#   BACKUP_SCHEDULE="0 0 2 * * *"
#
# Each template present beside the script is rendered with the keys it declares
# (`oc process --parameters` says which), so one file holds the whole deploy's
# configuration, and the apply that upgrades Postgres in place cannot mistype it. A
# name two templates declare means one thing in both (NAME, NAMESPACE, CHANNEL,
# DB_SUFFIX, RUST_LOG); a job's own MEMORY_LIMIT or RUST_LOG goes in its
# jobs/<JOB>.env:
#
#   app.yaml         always
#   redis.yaml       when present
#   egress.yaml      when present: for the app's pods (POD=NAME), and each task's
#   cronjob.yaml     when present: once per jobs/<JOB>.env, whose lines (JOB,
#                    SCHEDULE, ARGS, and any override) are read over params.env;
#                    a key the job's file leaves out keeps the app's value
#   monitoring.yaml  with --monitoring: it needs monitoring-edit, which a cluster
#                    admin grants, and a diff without it is refused
#
# Upgrading owt-stack is "copy the templates again, keep params.env". The script
# never writes a Secret: the app's environment ($NAME-env) is env.sh's, and a Redis
# password is made by hand, as the templates' headers say. PARAMS=path names another params.env.
#
# An executable `pre-render` beside the script computes parameters params.env cannot
# hold (a checksum of a ConfigMap, a value derived from the cluster). It runs once,
# in this directory, in diff and apply alike, so it only reads; the parameters from
# params.env are its environment. Its stdout is KEY=VALUE lines, read as params.env's
# are and over them (a job's file still wins; NAME and NAMESPACE stay params.env's,
# and a hook that changes one is refused); its stdin is empty, its stderr shows, and
# a failure stops the run before anything renders.
#
# Exit status: 0 when nothing would change (or everything applied), 1 when a diff
# found changes, 2 for a refusal (a bad params.env, a missing NAME) or a failed oc.
# `oc diff` on a cluster the objects are not on yet shows every object as new.
# Needs bash 4 or later.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
params=${PARAMS:-$here/params.env}
mode=diff
monitoring=no
for flag in "$@"; do
  case "$flag" in
    --apply) mode=apply ;;
    --diff) mode=diff ;;
    --monitoring) monitoring=yes ;;
    *) echo "usage: $0 [--diff | --apply] [--monitoring]" >&2; exit 2 ;;
  esac
done
[ -f "$params" ] || { echo "$params: no such file (NAME=… lines, one per template parameter)" >&2; exit 2; }
command -v oc >/dev/null || { echo "oc is not on the PATH" >&2; exit 2; }
[ "${BASH_VERSINFO[0]}" -ge 4 ] || { echo "apply.sh needs bash 4 or later" >&2; exit 2; }
[ "$monitoring" = no ] || [ -f "$here/monitoring.yaml" ] || { echo "--monitoring: no monitoring.yaml here" >&2; exit 2; }
rendered=$(mktemp)
paramfile=$(mktemp)
trap 'rm -f "$rendered" "$paramfile"' EXIT

# The parameters, in a file's order, later lines winning: `read_env FILE...` fills
# the associative array `given`; `read_label`, when set, names the file in a refusal.
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
        # One pair of matching quotes comes off; the templates get what is inside.
        if [[ $value =~ ^\"(.*)\"$ || $value =~ ^\'(.*)\'$ ]]; then
          value=${BASH_REMATCH[1]}
        fi
        given[$key]=$value
      else
        echo "${read_label:-$file}: not a KEY=VALUE line: $line" >&2
        exit 2
      fi
    done <"$file"
  done
}

# `given` must hold each KEY named, or `file` does not describe its deploy.
need() {
  local file=$1 key
  shift
  for key in "$@"; do
    [ "${given[$key]+set}" ] || { echo "$file must set $key" >&2; exit 2; }
  done
}

# `--param-file FILE` for `template`, holding a `KEY=VALUE` line for each parameter
# it declares that `given` holds; a required one that is missing is left for `oc
# process` to refuse by name. A file, not `-p`, because `-p` reads a comma in a value
# (`RUST_LOG=info,myapp=debug`) as a list of parameters. The names are the first
# column of `oc process --parameters`, under its header line.
args_for() {
  local template=$1 name names
  names=$(oc process --local -f "$template" --parameters | awk 'NR > 1 { print $1 }') ||
    { echo "oc process --parameters failed on $template" >&2; exit 2; }
  : >"$paramfile"
  while IFS= read -r name; do
    [ -n "$name" ] || continue
    if [ "${given[$name]+set}" ]; then
      printf '%s=%s\n' "$name" "${given[$name]}" >>"$paramfile"
    fi
  done <<<"$names"
  args=(--param-file="$paramfile")
}

status=0
# Render `template` to a file, then diff or apply it, naming it in the output. A
# render that fails stops the run: its exit is nothing the diff's could be mistaken for.
run() {
  local template=$1 label=$2
  args_for "$template"
  echo "== $label"
  oc process --local -f "$template" "${args[@]}" -o yaml >"$rendered" ||
    { echo "oc process failed on $label" >&2; exit 2; }
  if [ "$mode" = apply ]; then
    oc apply -f "$rendered" || { echo "oc apply failed on $label" >&2; exit 2; }
  else
    # oc diff exits 1 on differences, which is an answer, not a failure.
    local rc=0
    oc diff -f "$rendered" || rc=$?
    case $rc in
      0) echo "no change" ;;
      1) status=1 ;;
      *) echo "oc diff failed ($rc) on $label" >&2; exit 2 ;;
    esac
  fi
}

read_env "$params"
need "$params" NAME NAMESPACE
hook=$here/pre-render
if [ -e "$hook" ] || [ -L "$hook" ]; then
  [ -x "$hook" ] || { echo "$hook is not an executable file (a dangling link, or no x bit)" >&2; exit 2; }
  hook_env=()
  for k in "${!given[@]}"; do hook_env+=("$k=${given[$k]}"); done
  (cd "$here" && env "${hook_env[@]}" "$hook" </dev/null) >"$rendered" ||
    { echo "$hook failed" >&2; exit 2; }
  app_name=${given[NAME]} app_namespace=${given[NAMESPACE]}
  read_label=$hook read_env "$rendered"
  if [ "${given[NAME]}" != "$app_name" ] || [ "${given[NAMESPACE]}" != "$app_namespace" ]; then
    echo "$hook: NAME and NAMESPACE are params.env's alone, and the hook sets one of them" >&2
    exit 2
  fi
fi
# The router reads ROUTE_TIMEOUT as an haproxy duration: a bare number is
# milliseconds (300 would fail nearly every request), and a value it cannot parse
# is ignored without a word. So a value without a unit is refused here.
if [ "${given[ROUTE_TIMEOUT]+set}" ] && ! [[ ${given[ROUTE_TIMEOUT]} =~ ^[1-9][0-9]*(us|ms|s|m|h|d)$ ]]; then
  echo "$params: ROUTE_TIMEOUT=${given[ROUTE_TIMEOUT]} is not a number with a unit (us, ms, s, m, h or d: 30s, 2m)" >&2
  exit 2
fi

run "$here/app.yaml" "app.yaml"
[ -f "$here/redis.yaml" ] && run "$here/redis.yaml" "redis.yaml"
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
  # The app's parameters, kept so that nothing a job sets leaks into the next.
  declare -A app_given=()
  for k in "${!given[@]}"; do app_given[$k]=${given[$k]}; done
  for job in "${jobs[@]}"; do
    read_env "$job"
    need "$job" JOB
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
[ "$monitoring" = no ] || run "$here/monitoring.yaml" "monitoring.yaml"
exit "$status"
