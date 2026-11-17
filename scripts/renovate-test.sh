#!/usr/bin/env bash
# Proves renovate/base-images.json against the files it governs: every custom manager
# matches at least one digest-pinned image in the tracked files its managerFilePatterns
# select, every `name:tag@sha256:` pin in templates/, charts/ and .github/workflows/ is
# read by some manager (the pruner image, which names the cluster's internal registry
# and which Renovate cannot read, is the one listed exception), and no matchStrings
# pattern is anchored with ^ or $, which would match only if Renovate applied the
# multiline flag. `just ci-config` runs it; it needs node and git, and no network.
set -euo pipefail
cd "$(dirname "$0")/.."
git ls-files -z | node -e '
const fs = require("fs");
const preset = JSON.parse(fs.readFileSync("renovate/base-images.json", "utf8"));
const files = fs.readFileSync(0, "utf8").split("\0").filter(Boolean);
const unreadable = /^image-registry\.openshift-image-registry\.svc:/;
const pin = /([A-Za-z0-9][^\s"=]*:[^\s@"]+)@sha256:[a-f0-9]{64}/g;
let fails = 0;
const check = (name, ok) => { console.log((ok ? "ok   " : "FAIL ") + name); if (!ok) fails++; };
const asRegex = (p) => new RegExp(p.replace(/^\/|\/$/g, ""));
const read = (f) => fs.readFileSync(f, "utf8");
const covered = new Map(); // "file:offset" -> true
for (const m of preset.customManagers) {
  const label = m.managerFilePatterns.join(", ");
  const targets = files.filter((f) => m.managerFilePatterns.some((p) => asRegex(p).test(f)));
  for (const f of m.managerFilePatterns) {
    const re = asRegex(f);
    check(`${f} selects a file`, files.some((t) => re.test(t)));
  }
  for (const s of m.matchStrings) {
    check(`${s.slice(0, 40)}... has no ^ or $ anchor`, !/(^|[^\\])[\^$]/.test(s.replace(/\[[^\]]*\]/g, "")));
    const re = new RegExp(s, "g");
    // The release-workflow manager governs an app'"'"'s workflows; this repository'"'"'s own
    // carry no pin, so a sample line stands in for them.
    let total = 0;
    for (const t of targets) {
      const found = [...read(t).matchAll(re)];
      total += found.length;
      for (const x of found) covered.set(t + ":" + (x.index + x[0].indexOf(x.groups.depName)), true);
    }
    const sample = `    base-image: "registry.access.redhat.com/hi/core-runtime:2@sha256:${"a".repeat(64)}"`;
    if (total === 0 && /base-image/.test(s)) total = [...sample.matchAll(re)].length;
    check(`${m.description.slice(0, 40)}... matches a pin`, total > 0);
  }
}
for (const f of files.filter((f) => /^(templates|charts)\//.test(f) || /^\.github\/workflows\//.test(f))) {
  if (!/\.(ya?ml|json)$/.test(f)) continue;
  const text = read(f);
  for (const x of text.matchAll(pin)) {
    if (unreadable.test(x[1])) continue;
    check(`${f}: ${x[1]} is read by a manager`, covered.has(f + ":" + x.index));
  }
}
process.exit(fails ? 1 : 0);
' && echo "renovate: all checks passed"
