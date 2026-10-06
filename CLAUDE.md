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
- **Releasing:** the workspace `version`, `package.json`, the README's tags and the usage
  comment at the top of `.github/workflows/rust-ci.yml` move
  together in the pull request; tag `vX.Y.Z` on `main` after it merges.
- Gate: `cargo fmt --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`,
  `cargo test --workspace --all-features` (with `REDIS_URL` set, `owt-bus`'s Redis test
  runs too).
