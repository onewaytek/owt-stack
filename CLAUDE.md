# Working on owt-stack

Three apps build on this repository (epicpartygame-rs, pets, and kynestro after its
port), and they learn how to use it from `README.md`. So:

- **Keep the README's instructions current.** A change to a public API, a template,
  the reusable workflow's inputs, or how an app adopts something updates the matching
  README section in the same pull request.
- **README Rust examples are doctests.** `crates/readme` includes the README as its
  docs, so every ```` ```rust ```` block must compile against the workspace (`no_run`
  for anything needing a database or the network; `#`-prefixed lines for setup).
  Never mark one `ignore` to get past a failure: fix the example. YAML, CSS, shell and
  TOML blocks are not compiled; check them by eye.
- **Conventional Commits** for every commit message and pull request title (CI checks
  both): `type(scope): summary`, scopes as in the README's "Working on owt-stack". A
  change an app must adapt to is `type!:` with a `BREAKING CHANGE:` footer saying what
  the app changes; it becomes the release's upgrade notes.
- **Never bump versions or tag by hand.** release-please owns `version` in
  `Cargo.toml`, `Cargo.lock`, `package.json`, `fuzz/Cargo.toml`, `fuzz/Cargo.lock`
  and the README's tags, through its release pull request. A new mention of the
  version goes between `<!-- x-release-please-start-version -->` and
  `<!-- x-release-please-end -->` (or
  ends its line with `x-release-please-version`). Never in `.github/workflows/`: the
  default token cannot change a workflow file, and the release pull request fails.
- Gate: `just check` (the root `justfile`); CI runs the same command. With
  `REDIS_URL` set, `owt-bus`'s Redis test runs too.
