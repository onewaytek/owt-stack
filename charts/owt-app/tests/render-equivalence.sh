#!/usr/bin/env bash
# Proves charts/owt-app renders what templates/openshift renders, fixture by fixture.
#
#   charts/owt-app/tests/render-equivalence.sh            # every fixture
#   charts/owt-app/tests/render-equivalence.sh redis-port # the ones named
#
# Each fixtures/<case>/ holds an app's deploy as apply.sh reads it (params.env, and
# jobs/<JOB>.env), a `templates` file naming the optional templates the app keeps
# beside app.yaml (redis, egress, tunnel, cronjob, monitoring), and values.yaml, the
# same deploy as the chart's values. The old side is apply.sh itself, run with
# --apply against a stand-in `oc` that keeps what it would apply and hands every
# other call (`oc process --local`) to the real oc; the new side is `helm template`.
# Both are normalised the same way (one list, sorted by kind and name, keys sorted
# with `yq -P 'sort_keys(..)'`, comments dropped), and the old side is given the
# differences the chart makes on purpose before the two are compared:
#
# - no ImageStream, and no image.openshift.io/triggers annotation;
# - the image placeholder <NAME>:<CHANNEL> is <repository>@<digest>;
# - argocd.argoproj.io/sync-options: Prune=false,Delete=false on the CNPG Cluster.
#
# Any other difference fails, with the diff. After the fixtures, the chart's own
# features (ExternalSecrets, settings, persistence, pod annotations) render and the
# schema refuses values without a digest or postgresMajor.
#
# Needs bash 4, oc, helm, yq (mikefarah, v4) and jq; no cluster.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
chart=$(cd "$here/.." && pwd)
root=$(cd "$chart/../.." && pwd)
templates=$root/templates/openshift
for tool in oc helm yq jq; do
  command -v "$tool" >/dev/null || { echo "$tool is not on the PATH" >&2; exit 2; }
done
real_oc=$(command -v oc)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# A YAML stream (a file, or - for stdin) as one JSON array of its objects, with
# oc's Lists unwrapped and empty documents dropped.
objects() {
  yq -o=json ea '[.]' "$1" | jq '[.[] | select(. != null) | if .kind == "List" then .items[] else . end]'
}

# A JSON array of objects as the YAML the comparison reads: sorted by kind, then
# namespace and name, keys sorted.
normal() {
  jq -S 'sort_by(.kind, .metadata.namespace, .metadata.name)' | yq -P 'sort_keys(..)' -
}

# The old side with the chart's intended differences applied.
expected() {
  local placeholder=$1 pinned=$2
  jq --arg placeholder "$placeholder" --arg pinned "$pinned" '
    [ .[]
      | select(.kind != "ImageStream")
      | if .metadata.annotations then
          del(.metadata.annotations["image.openshift.io/triggers"])
          | if .metadata.annotations == {} then del(.metadata.annotations) else . end
        else . end
      | walk(if type == "object" and .image == $placeholder then .image = $pinned else . end)
      | if .kind == "Cluster" then
          .metadata.annotations["argocd.argoproj.io/sync-options"] = "Prune=false,Delete=false"
        else . end
    ]'
}

# The value of KEY in a params.env (the last line wins, one pair of quotes off).
param() {
  sed -n "s/^$2=//p" "$1" | tail -n 1 | sed -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'$/\1/"
}

failed=0
compare() {
  local case=$1 dir=$here/fixtures/$1 deploy=$work/$1
  mkdir -p "$deploy/bin"
  cp "$templates/app.yaml" "$templates/apply.sh" "$dir/params.env" "$deploy/"
  [ -d "$dir/jobs" ] && cp -r "$dir/jobs" "$deploy/"
  local flags=(--apply) t
  for t in $(cat "$dir/templates" 2>/dev/null); do
    cp "$templates/$t.yaml" "$deploy/"
    [ "$t" = monitoring ] && flags+=(--monitoring)
  done
  # The stand-in: `oc apply -f FILE` keeps FILE; everything else is the real oc.
  cat >"$deploy/bin/oc" <<EOF
#!/usr/bin/env bash
if [ "\$1" = apply ]; then
  for a in "\$@"; do [ "\${prev:-}" = -f ] && { cat "\$a"; echo '---'; } >>"$deploy/old.yaml"; prev=\$a; done
  exit 0
fi
exec "$real_oc" "\$@"
EOF
  chmod +x "$deploy/bin/oc"
  : >"$deploy/old.yaml"
  PATH="$deploy/bin:$PATH" bash "$deploy/apply.sh" "${flags[@]}" >"$deploy/apply.log" 2>&1 ||
    { echo "FAIL $case: apply.sh failed"; cat "$deploy/apply.log"; failed=1; return; }

  local name channel image digest
  name=$(param "$dir/params.env" NAME)
  channel=$(param "$dir/params.env" CHANNEL)
  image=$(yq '.image.repository' "$dir/values.yaml")
  digest=$(yq '.image.digest' "$dir/values.yaml")
  objects "$deploy/old.yaml" | expected "$name:${channel:-rc}" "$image@$digest" | normal >"$deploy/old.norm.yaml"
  helm template "$name" "$chart" -f "$dir/values.yaml" >"$deploy/new.yaml" ||
    { echo "FAIL $case: helm template failed"; failed=1; return; }
  objects "$deploy/new.yaml" | normal >"$deploy/new.norm.yaml"
  if diff -u --label "$case: templates/openshift" --label "$case: charts/owt-app" \
    "$deploy/old.norm.yaml" "$deploy/new.norm.yaml"; then
    echo "ok   $case ($(jq length <(objects "$deploy/new.yaml")) objects)"
  else
    echo "FAIL $case: the renders differ (above)"
    failed=1
  fi
}

# A render of the chart that must fail, and say why.
refuses() {
  local label=$1 want=$2 out
  shift 2
  if out=$(helm template t "$chart" "$@" 2>&1); then
    echo "FAIL $label: rendered"; failed=1
  elif ! grep -q -- "$want" <<<"$out"; then
    echo "FAIL $label: refused without naming $want:"; echo "$out"; failed=1
  else
    echo "ok   $label"
  fi
}

# A render of the chart that must hold every jq condition given.
holds() {
  local label=$1 values=$2 rendered cond
  shift 2
  rendered=$(helm template t "$chart" -f "$values" | objects -) ||
    { echo "FAIL $label: helm template failed"; failed=1; return; }
  for cond in "$@"; do
    jq -e "$cond" <<<"$rendered" >/dev/null ||
      { echo "FAIL $label: $cond"; failed=1; return; }
  done
  echo "ok   $label"
}

cases=("$@")
if [ ${#cases[@]} -eq 0 ]; then
  for d in "$here"/fixtures/*/; do cases+=("$(basename "$d")"); done
fi
for c in "${cases[@]}"; do compare "$c"; done

base=$here/fixtures/minimal/values.yaml
refuses "no digest" "digest" -f "$base" --set image.digest=
refuses "no postgresMajor" "postgresMajor" -f "$base" --set postgresMajor=
refuses "a tag for a digest" "digest" -f "$base" --set image.digest=latest
refuses "a tunnel host alone" "tunnel" -f "$base" --set tunnel.host=myapp.example.com
refuses "a route timeout without a unit" "routeTimeout" -f "$base" --set routeTimeout=300
refuses "a role prefix with a hyphen" "rolePrefix" -f "$base" --set database.rolePrefix=my-app
holds "chart features" "$here/features.yaml" \
  '[.[] | select(.kind == "ExternalSecret")] | length == 4' \
  '.[] | select(.kind == "ExternalSecret" and .metadata.name == "myapp-db-runtime")
     | .spec.target.template.metadata.labels["cnpg.io/reload"] == "true"
       and .spec.target.creationPolicy == "Merge" and .spec.target.deletionPolicy == "Retain"
       and .spec.dataFrom[0].extract.key == "apps/myapp/rc/db-runtime"
       and .metadata.annotations["argocd.argoproj.io/sync-options"] == "Prune=false,Delete=false"' \
  '.[] | select(.kind == "SecretStore") | .spec.provider.vault.auth.kubernetes.role == "myapp"' \
  '.[] | select(.kind == "PersistentVolumeClaim" and .metadata.name == "myapp-exports")
     | .metadata.annotations["argocd.argoproj.io/sync-options"] == "Prune=false,Delete=false"' \
  '.[] | select(.kind == "Deployment" and .metadata.name == "myapp") | .spec.template
     | .metadata.annotations.rotation == "2"
       and (.spec.containers[0].envFrom | last | .configMapRef.name == "myapp-settings")
       and (.spec.initContainers[0].envFrom | last | .configMapRef.name == "myapp-settings")
       and (.spec.containers[0].volumeMounts | any(.mountPath == "/var/lib/myapp/exports"))' \
  '.[] | select(.kind == "ConfigMap" and .metadata.name == "myapp-settings") | .data.PUBLIC_URL == "https://myapp.example.com"'
exit "$failed"
