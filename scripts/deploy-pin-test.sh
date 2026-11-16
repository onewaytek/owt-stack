#!/usr/bin/env bash
# Proves the "Pin the digest" step of deploy-pin.yml against a local bare repository
# and stand-in `gh` and `yq`: a first run opens one pull request, a rerun with the same
# digest changes nothing and reuses it, a rerun with another digest for the same
# version adds a commit to the same branch (a fast-forward push), a new version opens
# a new pull request and closes the old one, and a pin the base already holds opens
# nothing. `just templates` runs it; it needs bash 4 and git, and no network.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
wf="$here/../.github/workflows/deploy-pin.yml"
work=$(mktemp -d)
trap '[ -n "${KEEP:-}" ] || rm -rf "$work"' EXIT
mkdir -p "$work/bin"

# The step's script, dedented from the workflow.
awk '
  /^      - name: Pin the digest/ { in_step = 1 }
  in_step && /^        run: \|$/ { in_run = 1; next }
  in_run { sub(/^          /, ""); print }
' "$wf" >"$work/pin.sh"
[ -s "$work/pin.sh" ] || { echo "no pin script found in $wf" >&2; exit 1; }

cat >"$work/bin/yq" <<'YQ'
#!/usr/bin/env bash
# Only the three calls the step makes.
if [ "$1" = -n ]; then
  printf 'image:\n  repository: %s\n  digest: %s\n  version: %s\n' "$REPO" "$DIGEST" "$VERSION"
elif [[ $1 == *.promote* ]]; then
  sed -n 's/^promote: //p' "$2"
else
  v=$(sed -n 's/^variant: //p' "$2")
  [ "$(sed -n 's/^app: //p' "$2")" = "$APP" ] && [ "$(sed -n 's/^channel: //p' "$2")" = "$CHANNEL" ] \
    && [ "$v" = "$VARIANT" ] && echo true || echo false
fi
YQ
cat >"$work/bin/gh" <<'GH'
#!/usr/bin/env bash
# Pull requests are lines "number|head|state|url" in $PRS; every call is logged.
echo "gh ${*//$'\n'/ }" >>"$GH_LOG"
head=""; prev=""
for a in "$@"; do [ "$prev" = --head ] && head=$a; prev=$a; done
case "$1 $2" in
  "api users/"*) echo 42 ;;
  "label create") ;;
  "pr list")
    if [[ " $* " == *" --head "* ]]; then
      awk -F'|' -v h="$head" '$2 == h && $3 == "open" { print $4; exit }' "$PRS"
    else
      awk -F'|' '$3 == "open" { print $1 "\t" $2 }' "$PRS" \
        | while IFS=$'\t' read -r n h; do
            # The step's --jq selects by branch prefix; mirror it with the prefix it names.
            [[ $h == "$PREFIX"* && $h != "$BRANCH" ]] && echo "$n" || true
          done
    fi ;;
  "pr create")
    n=$(($(wc -l <"$PRS") + 1))
    echo "$n|$head|open|https://example.test/pull/$n" >>"$PRS"
    echo "https://example.test/pull/$n" ;;
  "pr edit"|"pr merge") ;;
  "pr close") sed -i "s/^$3|\([^|]*\)|open|/$3|\1|closed|/" "$PRS" ;;
  *) echo "fake gh: unexpected: $*" >&2; exit 1 ;;
esac
GH
chmod +x "$work/bin/yq" "$work/bin/gh"

# The deployments repository: a bare origin, and one environment following myapp rc.
git init -q --bare -b main "$work/origin.git"
git clone -q "$work/origin.git" "$work/seed" 2>/dev/null
(
  cd "$work/seed"
  git config user.name seed; git config user.email seed@example.test
  mkdir -p apps/myapp/rc
  printf 'app: myapp\nchannel: rc\npromote: auto\n' >apps/myapp/rc/target.yaml
  printf 'image:\n  repository: r\n  digest: sha256:old\n  version: 0.0.1-rc.0\n' >apps/myapp/rc/image.yaml
  git add -A; git commit -q -m seed; git push -q origin main
)

export PATH="$work/bin:$PATH" GH_LOG="$work/gh.log" PRS="$work/prs"
export GH_REPO=o/deployments SLUG=owt-deploy APP=myapp CHANNEL=rc VARIANT="" REPOSITORY=""
export SOURCE=https://example.test/run/1
export GITHUB_OUTPUT="$work/out"
: >"$PRS"; : >"$GH_LOG"

d1=sha256:$(printf 'a%.0s' {1..64}); d2=sha256:$(printf 'b%.0s' {1..64})
fails=0
check() { if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; fails=$((fails + 1)); fi; }

run() { # run VERSION DIGEST: a fresh clone each time, as the workflow checks out
  rm -rf "$work/deployments"; git clone -q "$work/origin.git" "$work/deployments" 2>/dev/null
  : >"$GITHUB_OUTPUT"
  export VERSION=$1 DIGEST=$2 PREFIX=deploy-pin/myapp-rc-auto- BRANCH=deploy-pin/myapp-rc-auto-$1
  (cd "$work/deployments" && bash -c "$(cat "$work/pin.sh")") >"$work/run.log" 2>&1 \
    || { cat "$work/run.log"; echo "FAIL run $1 exited non-zero"; fails=$((fails + 1)); }
}
tip() { git -C "$work/origin.git" rev-parse "refs/heads/deploy-pin/myapp-rc-auto-$1"; }
commits() { git -C "$work/origin.git" rev-list --count "main..refs/heads/deploy-pin/myapp-rc-auto-$1"; }
prs() { grep -c "|$1|" "$PRS" || true; }

run 1.0.0-rc.1 "$d1"
check "first run opens one pull request" '[ "$(prs open)" = 1 ] && grep -q "^pull-requests=https://example.test/pull/1$" "$GITHUB_OUTPUT"'
check "first run pushes one commit" '[ "$(commits 1.0.0-rc.1)" = 1 ]'
t1=$(tip 1.0.0-rc.1)

run 1.0.0-rc.1 "$d1"
check "rerun with the same digest keeps the branch" '[ "$(tip 1.0.0-rc.1)" = "$t1" ]'
check "rerun with the same digest reuses the pull request" \
  '[ "$(wc -l <"$PRS")" = 1 ] && grep -q "^reused https://example.test/pull/1$" "$work/run.log" && grep -q "^pull-requests=https://example.test/pull/1$" "$GITHUB_OUTPUT"'

run 1.0.0-rc.1 "$d2"
check "another digest for the version adds a commit by fast-forward" \
  '[ "$(commits 1.0.0-rc.1)" = 2 ] && git -C "$work/origin.git" merge-base --is-ancestor "$t1" "$(tip 1.0.0-rc.1)"'
check "another digest keeps the one pull request" '[ "$(wc -l <"$PRS")" = 1 ]'
check "the branch holds the new digest" \
  'git -C "$work/origin.git" show "refs/heads/deploy-pin/myapp-rc-auto-1.0.0-rc.1:apps/myapp/rc/image.yaml" | grep -q "$d2"'

run 1.0.0-rc.2 "$d1"
check "a new version opens a second pull request" '[ "$(wc -l <"$PRS")" = 2 ] && [ "$(prs open)" = 1 ]'
check "the older pin is closed as superseded" 'grep -q "^1|.*|closed|" "$PRS"'

# The base takes the pin (a squash merge that leaves the branch behind), then reruns.
(
  cd "$work/seed"; git pull -q origin main
  printf 'image:\n  repository: ghcr.io/onewaytek/myapp\n  digest: %s\n  version: 1.0.0-rc.2\n' "$d1" >apps/myapp/rc/image.yaml
  git commit -q -am merged; git push -q origin main
)
before=$(wc -l <"$PRS")
run 1.0.0-rc.2 "$d1"
check "a pin the base already holds opens nothing" \
  '[ "$(wc -l <"$PRS")" = "$before" ] && grep -q "already run" "$work/run.log" && grep -q "^pull-requests=$" "$GITHUB_OUTPUT"'
check "the step never force-pushes" '! grep -Eq "push.*(--force|-f )" "$work/pin.sh"'

[ "$fails" = 0 ] || { echo "$fails check(s) failed"; exit 1; }
echo "deploy-pin: all checks passed"
