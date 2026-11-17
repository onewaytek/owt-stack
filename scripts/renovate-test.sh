#!/usr/bin/env bash
# Proves renovate/base-images.json against the files it governs: every custom manager
# matches at least one digest-pinned image in the files its managerFilePatterns select,
# every `name:tag@sha256:` pin in templates/, charts/ and .github/workflows/ is read by
# some manager (the pruner image, which names the cluster's internal registry and which
# Renovate cannot read, is the one listed exception), and no matchStrings pattern is
# anchored with ^ or $, which would match only if Renovate applied the multiline flag.
# The patterns are JavaScript regular expressions in Renovate; here `grep -P` (PCRE)
# runs them line by line, which agrees for these patterns (named groups, \s, classes,
# non-capturing groups). `just ci-config` runs it; it needs bash, jq, find and GNU grep,
# and no git or network.
set -euo pipefail
cd "$(dirname "$0")/.."
preset=renovate/base-images.json
fails=0
check() { if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; fails=$((fails + 1)); fi; }

mapfile -t files < <(find . -type f -not -path './.git/*' -not -path './target/*' | sed 's|^\./||' | LC_ALL=C sort)
# A Renovate file pattern is /regex/; strip the slashes.
unslash() { local p=$1; p=${p#/}; printf '%s' "${p%/}"; }
sample="    base-image: \"registry.access.redhat.com/hi/core-runtime:2@sha256:$(printf 'a%.0s' {1..64})\""
covered=$(mktemp); trap 'rm -f "$covered"' EXIT

n=$(jq '.customManagers | length' "$preset")
for ((m = 0; m < n; m++)); do
  desc=$(jq -r ".customManagers[$m].description" "$preset"); desc=${desc:0:40}
  targets=()
  while IFS= read -r fp; do
    re=$(unslash "$fp")
    selected=$(printf '%s\n' "${files[@]}" | grep -P -e "$re" || true)
    check "$fp selects a file" '[ -n "$selected" ]'
    while IFS= read -r f; do [ -z "$f" ] || targets+=("$f"); done <<<"$selected"
  done < <(jq -r ".customManagers[$m].managerFilePatterns[]" "$preset")
  while IFS= read -r s; do
    stripped=$(printf '%s' "$s" | sed -E 's/\[[^]]*\]//g')
    anchored=0
    [[ $stripped == ^* || $stripped == *\$ || $stripped == *'|^'* || $stripped == *'(^'* ]] && anchored=1
    check "$desc... pattern has no ^ or \$ anchor" '[ "$anchored" = 0 ]'
    total=0
    for t in "${targets[@]}"; do
      hits=$(grep -nP -e "$s" "$t" | cut -d: -f1 || true)
      for h in $hits; do echo "$t:$h" >>"$covered"; total=$((total + 1)); done
    done
    # The release-workflow manager governs an app's workflows; this repository's own
    # carry no pin, so a sample line stands in for them.
    if [ "$total" = 0 ] && [[ $s == *base-image* ]]; then
      total=$(printf '%s\n' "$sample" | grep -cP -e "$s" || true)
    fi
    check "$desc... matches a pin" '[ "$total" -gt 0 ]'
  done < <(jq -r ".customManagers[$m].matchStrings[]" "$preset")
done

for f in "${files[@]}"; do
  [[ $f =~ ^(templates|charts|\.github/workflows)/ && $f =~ \.(ya?ml|json)$ ]] || continue
  while IFS=: read -r line pin; do
    [[ $pin == image-registry.openshift-image-registry.svc:* ]] && continue
    check "$f:$line $pin is read by a manager" 'grep -qxF "$f:$line" "$covered"'
  done < <(grep -noP '[A-Za-z0-9][^\s"=]*:[^\s@"]+(?=@sha256:[a-f0-9]{64})' "$f" || true)
done
[ "$fails" = 0 ] || { echo "$fails check(s) failed"; exit 1; }
echo "renovate: all checks passed"
