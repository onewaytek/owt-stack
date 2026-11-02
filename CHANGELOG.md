# Changelog

## [0.12.1](https://github.com/onewaytek/owt-stack/compare/v0.12.0...v0.12.1) (2026-11-02)


### Features

* **accounts:** configurable admin step-up window and an opt-out ([#302](https://github.com/onewaytek/owt-stack/issues/302)) ([331dd25](https://github.com/onewaytek/owt-stack/commit/331dd258b5a17f71d6e5d32ff26fa45e21235fea))
* **accounts:** mountable second-factor pages (mfa::pages) ([#299](https://github.com/onewaytek/owt-stack/issues/299)) ([244d353](https://github.com/onewaytek/owt-stack/commit/244d353c902639572e339fe5f6306e6918b45762))


### Bug Fixes

* **templates:** name the runtime role from NAME with hyphens as underscores ([#301](https://github.com/onewaytek/owt-stack/issues/301)) ([a489173](https://github.com/onewaytek/owt-stack/commit/a489173345ba3cd9b25eb9842bd29d0ebf3f54db))

## [0.12.0](https://github.com/onewaytek/owt-stack/compare/v0.11.0...v0.12.0) (2026-11-01)


### ⚠ BREAKING CHANGES

* **accounts:** the layer's query names two columns of its own, owt_has_factor and owt_accepted. An Extra::QUERY that names a column of either name now fails the load as a duplicate column; rename it.
* **audit:** `cli::run(&pool, cmd)` is `cli::run(&pool, store, cmd)`; pass `Some(&store)` (a read-only credential with `s3:ListBucket`, `s3:GetObject`, `s3:GetObjectVersion`, `s3:GetObjectRetention`) or `None::<&NoAnchor>`. An `Anchor` implemented outside owt-audit adds `get`. `VerifyError` has a `Store` variant. Anchors recorded with `NoAnchor` fail the default verify; use `--db-only` until the job anchors with the store.
* **crypt:** a build without this change refuses 0x02 ciphertexts as CryptError::Malformed, so roll the release out to every replica (and every job) before any of them seals; there is no rollback past the first 0x02 write. owt_crypt::format changes: FORMAT, NONCE_LEN and MIN_LEN are replaced by the Format enum (byte, from_byte, nonce_len, min_len) and CURRENT; Sealed gains `format` and its `nonce` is a slice; aad and assemble take a Format first. Crypt, Sealer and their methods keep their signatures.
* **runtime,web:** a statement running past 30 s now fails (57014) and a transaction idle for 60 s is ended; long work sets `SET LOCAL statement_timeout` or uses a pool with `statement_timeout: None`. A pool acquire fails after 5 s. A `PoolConfig` struct literal without `..PoolConfig::default()` adds `statement_timeout` and `idle_in_transaction_timeout`. Under `Stack`, the account loader's time counts toward `Limits::request_timeout`. A pooler in transaction mode that refuses startup parameters needs both timeouts set to `None`.
* **templates:** an app deployed from templates/openshift/app.yaml must create the <NAME>-<DB_SUFFIX>-runtime Secret (kubernetes.io/basic-auth, username <NAME>_runtime, a hex password, label cnpg.io/reload=true) before applying, give its binary a `migrate` subcommand that migrates and then calls `owt_runtime::db::grant_runtime` and `owt_audit::grant_runtime` with DB_RUNTIME_ROLE, and stop migrating at serve time. See the README's "Database roles".
* **crypt:** a build without this change refuses 0x02 ciphertexts as CryptError::Malformed, so roll the release out to every replica (and every job) before any of them seals; there is no rollback past the first 0x02 write. owt_crypt::format changes: FORMAT, NONCE_LEN and MIN_LEN are replaced by the Format enum (byte, from_byte, nonce_len, min_len) and CURRENT; Sealed gains `format` and its `nonce` is a slice; aad and assemble take a Format first. Crypt, Sealer and their methods keep their signatures.
* **accounts:** an exemption without a trailing slash no longer covers sibling paths that merely start with the same letters (`.exempt(&["/ws"])` no longer exempts `/ws-live`). List each such path, or end the prefix in `/`.
* **auth:** `owt_auth::password::{verify, check, verify_or_decoy, check_or_decoy}` and `owt_auth::recovery::find_match` return `Result<_, password::Busy>`. `hash` keeps its signature; its error downcasts to `Busy`. `SignInRefused::Fault` and `MfaError::Fault` lose their derived `From<owt_accounts::Error>` in favour of a hand-written one that maps `Error::Busy` to `Unavailable`.
* **accounts:** staff must have a second factor and have used it within 15 minutes to change anything in the accounts admin; staff without a TOTP factor must enrol one, and the app must serve its re-authentication page (`Accounts::reauth_at`). An app with its own session type calls `Admin::session::<T>()`. `Admin::sign_in_links` caps the lifetime at 24 hours. Give the admin a recorder with `Admin::audit` to write its events to the audit log.
* **accounts:** sessions end after 30 minutes without activity and 24 hours after they began unless the app sets idle_timeout/absolute_lifetime (a longer max_age still extends the absolute lifetime). Call without_idle_timeout() to keep the old idle behaviour. Responses to a request with a session now carry owt-idle-remaining. On upgrade, sessions older than the timeout end.
* **accounts,runtime:** a release build using Mfa without Mfa::sealer can no longer enroll or verify TOTP factors; set a real SecretSealer.
* **runtime:** `diagnosis`, `note`, `notes`, `transcript`, `mrn` and `patient_name` are no longer redacted by default (`patient_name` still is, by the word `name`). An app handling health records sets `redact_words: logging::HEALTH_WORDS.iter().map(|w| (*w).to_owned()).collect()`. An app building `logging::Options` as a struct literal without `..Default::default()` adds `redact_words`. JSON-output apps no longer see panic payloads in their logs.
* **crypt:** CryptError is non_exhaustive and gains Stale and NotLoaded; add a wildcard arm.
* **audit:** the S3 anchor's HTTP client ignores HTTPS_PROXY, HTTP_PROXY and ALL_PROXY; an app that reached its store only through a proxy must allow direct egress to the endpoint instead.

### Features

* **accounts:** audit admin changes and require a recent second factor ([#278](https://github.com/onewaytek/owt-stack/issues/278)) ([9287a0a](https://github.com/onewaytek/owt-stack/commit/9287a0a2cdfd62c87e44a1276a8d20d876325d99))
* **accounts:** end sessions sooner and revoke the one sign_out ends ([#281](https://github.com/onewaytek/owt-stack/issues/281)) ([f221378](https://github.com/onewaytek/owt-stack/commit/f2213785c7a8aab1df3d4562ef5008db83574a03))
* **audit:** report whether the connected role can unprotect the audit log ([#276](https://github.com/onewaytek/owt-stack/issues/276)) ([826e45f](https://github.com/onewaytek/owt-stack/commit/826e45f25109e1880bc65b65985d3ff8a6f8b8d9))
* **audit:** verify against the anchor store by default ([#295](https://github.com/onewaytek/owt-stack/issues/295)) ([d261fdc](https://github.com/onewaytek/owt-stack/commit/d261fdcbd72032aea72480232f7ba266fe9fe860))
* **audit:** verify the anchors as a chain and alarm on a stale anchor ([#277](https://github.com/onewaytek/owt-stack/issues/277)) ([86344ff](https://github.com/onewaytek/owt-stack/commit/86344ff0217db0c090035498793be714851602fe))
* **crypt:** add a synchronous per-scope Sealer ([#272](https://github.com/onewaytek/owt-stack/issues/272)) ([05dbd02](https://github.com/onewaytek/owt-stack/commit/05dbd02d531d52c0560c9fd0d32562f801ccbbfb))
* **crypt:** opt-in length padding for sealed values ([#291](https://github.com/onewaytek/owt-stack/issues/291)) ([6a13b93](https://github.com/onewaytek/owt-stack/commit/6a13b93d6c8c2a7533b80e9b392110a9ad5bee1e))
* **crypt:** seal fields with XChaCha20-Poly1305 as ciphertext format 0x02 ([#287](https://github.com/onewaytek/owt-stack/issues/287)) ([6ec5975](https://github.com/onewaytek/owt-stack/commit/6ec5975bbce91c0d5cabac01ccc12998ab3b350b))
* **runtime:** hold a singleton's lock on a dedicated connection ([#294](https://github.com/onewaytek/owt-stack/issues/294)) ([02996d7](https://github.com/onewaytek/owt-stack/commit/02996d74af986bbfb1588dadadb34a257f08372a))
* **runtime:** poll the job queue every 5 s by default ([#293](https://github.com/onewaytek/owt-stack/issues/293)) ([12dfd79](https://github.com/onewaytek/owt-stack/commit/12dfd79a1e8e1cf6ef71391be0b0568d55441580))
* **templates:** migrate as the owner in an init container, serve as a runtime role ([#279](https://github.com/onewaytek/owt-stack/issues/279)) ([73d2c55](https://github.com/onewaytek/owt-stack/commit/73d2c5527c679e504d4aa226651d08585c93b538))
* **test:** add TestSchema, a per-test schema unique per checkout and process ([#271](https://github.com/onewaytek/owt-stack/issues/271)) ([b0ecd70](https://github.com/onewaytek/owt-stack/commit/b0ecd70cbbae6a2bbbca8eeeef8daa0860bc79f3))


### Bug Fixes

* **accounts,runtime:** refuse unsealed TOTP in release builds and redact env Vars ([#282](https://github.com/onewaytek/owt-stack/issues/282)) ([d3574e3](https://github.com/onewaytek/owt-stack/commit/d3574e35be9d9d18ae180ac03fb7f961fe3d845c))
* **accounts:** match policy exemptions at a path-segment boundary ([#289](https://github.com/onewaytek/owt-stack/issues/289)) ([cd566a0](https://github.com/onewaytek/owt-stack/commit/cd566a009d47e52f8222b69e931e36d08fe42f27))
* **audit:** harden the S3 Object Lock provider ([268366d](https://github.com/onewaytek/owt-stack/commit/268366d4cf8c8ceb02b7db4c0e816ad83d62775c))
* **auth:** answer 503 when the Argon2 permit wait times out ([#290](https://github.com/onewaytek/owt-stack/issues/290)) ([05da234](https://github.com/onewaytek/owt-stack/commit/05da2341ff75f178bc07c9032420c93c05570dec))
* **auth:** key the sign-in throttle on the NFKC login and warn when it is per replica ([#280](https://github.com/onewaytek/owt-stack/issues/280)) ([8d94a5a](https://github.com/onewaytek/owt-stack/commit/8d94a5a3d4b11f54f16cbe773d3d3c44503039a1))
* **bus:** resync a subscriber that lost messages at a full queue ([#292](https://github.com/onewaytek/owt-stack/issues/292)) ([c807b1a](https://github.com/onewaytek/owt-stack/commit/c807b1a3f3478850b3bb60e8735d772e5c9065fc))
* **ci:** install cosign without cosign-installer so attest runs on ARC ([#273](https://github.com/onewaytek/owt-stack/issues/273)) ([946883c](https://github.com/onewaytek/owt-stack/commit/946883cbe5040f4935216afc1c882ff4493c19f9))
* **runtime,web:** bound the per-request DB hot path ([#284](https://github.com/onewaytek/owt-stack/issues/284)) ([4eecfcb](https://github.com/onewaytek/owt-stack/commit/4eecfcbbd0ef7bf5d46d78c3cf12d6acfaac05fe))
* **runtime:** abort a queue handler whose heartbeat finds its claim lost ([#285](https://github.com/onewaytek/owt-stack/issues/285)) ([c64e18a](https://github.com/onewaytek/owt-stack/commit/c64e18a333d4f05e82b703217f94f6666e32716d))
* **runtime:** make health vocabulary app-supplied; log panics without payload ([#283](https://github.com/onewaytek/owt-stack/issues/283)) ([bc9b083](https://github.com/onewaytek/owt-stack/commit/bc9b08375c5b71194cd97fa61d980d4a1e9d33b1))
* **templates:** env.sh stores a generated value as base64 text, as the app reads it ([#298](https://github.com/onewaytek/owt-stack/issues/298)) ([bcdce50](https://github.com/onewaytek/owt-stack/commit/bcdce507e46a9100650421b1924e3b5878765ecd))


### Performance Improvements

* **accounts:** read the factor and policy state in the account's query ([#296](https://github.com/onewaytek/owt-stack/issues/296)) ([8560519](https://github.com/onewaytek/owt-stack/commit/85605198e869f9934150f8c31c5d6865c5bdb902))

## [0.11.0](https://github.com/onewaytek/owt-stack/compare/v0.10.0...v0.11.0) (2026-10-30)


### ⚠ BREAKING CHANGES

* **accounts:** `session::Data` has a new public field `mfa`, so a struct literal of `Data` must end with `..Default::default()`. A custom session type that implements `session::Signed` is unaffected unless it adopts `mfa::MfaSession`.
* **runtime:** logging::Options has three new fields; an app that builds it as a struct literal adds `..logging::Options::default()`. Fields on the default denylist (name, address, email, note and others) now log as [redacted]; rename one that must stay visible, or set redact_defaults to false. JSON log output comes from a custom formatter (a bridged `log` record keeps its own target and drops its `log.*` fields; a span field named `name` is written as `field.name`), and the OTLP exporter redacts matching span, event and link attributes (span names, event names and status descriptions are exported as written).
* **ci:** the app's image job calling image.yml grants id-token: write besides contents: read and packages: write. A reusable workflow cannot take a permission its caller withholds, so without it the call fails to start. An image with a critical vulnerability now fails the job; set vuln-fail-on: none to report only, or waive a finding in a grype configuration named by vuln-ignore-file.

### Features

* **accounts:** add a TOTP second factor, recovery codes and step-up re-authentication ([#256](https://github.com/onewaytek/owt-stack/issues/256)) ([3852996](https://github.com/onewaytek/owt-stack/commit/38529960926459db214d8b1187adae71a570ef54))
* **audit:** add owt-audit, an append-only hash-chained audit log ([#251](https://github.com/onewaytek/owt-stack/issues/251)) ([0553364](https://github.com/onewaytek/owt-stack/commit/0553364781cb2ccca7771830ccf7e8efbdab9b49))
* **audit:** anchor to an S3 bucket under Object Lock ([#261](https://github.com/onewaytek/owt-stack/issues/261)) ([e74b7f0](https://github.com/onewaytek/owt-stack/commit/e74b7f0649b6fc92adf53d8bc4e800b433b62ae9))
* **auth:** add TOTP, recovery codes, a NIST password policy and a Redis throttle ([#255](https://github.com/onewaytek/owt-stack/issues/255)) ([eba19b3](https://github.com/onewaytek/owt-stack/commit/eba19b3eb3dfec8126a1409ea508ca2a33e0157a))
* **ci:** sign images with cosign, attach an SBOM, and fail on critical vulnerabilities ([#249](https://github.com/onewaytek/owt-stack/issues/249)) ([d2e968d](https://github.com/onewaytek/owt-stack/commit/d2e968d548e517c991c55400e8ba904a5b0a9b2f))
* **crypt:** add owt-crypt, envelope field encryption with a YubiHSM 2 KEK ([#252](https://github.com/onewaytek/owt-stack/issues/252)) ([529eac2](https://github.com/onewaytek/owt-stack/commit/529eac2c27965c868c0410a53f186617db8d1262))
* **runtime:** add a durable job queue in Postgres ([#250](https://github.com/onewaytek/owt-stack/issues/250)) ([2fbb988](https://github.com/onewaytek/owt-stack/commit/2fbb9884ed73f3727127e997e8d07cd4b6955ca2))
* **runtime:** redact sensitive fields in logs ([#257](https://github.com/onewaytek/owt-stack/issues/257)) ([d23cb1b](https://github.com/onewaytek/owt-stack/commit/d23cb1bd910ef995aea09e3a6676b15354b4965d))
* **storage:** add owt-storage, encrypted objects in S3-compatible buckets ([626e7c1](https://github.com/onewaytek/owt-stack/commit/626e7c1518d668fa40be13d66cc01d615aa7879d))
* **web:** end sessions after an idle timeout ([#254](https://github.com/onewaytek/owt-stack/issues/254)) ([1e24d39](https://github.com/onewaytek/owt-stack/commit/1e24d39f6fdbe05a225667d1e28641f2efed025c))


### Bug Fixes

* **accounts:** index every recovery code by account and test concurrent single-use ([#267](https://github.com/onewaytek/owt-stack/issues/267)) ([3d4cafe](https://github.com/onewaytek/owt-stack/commit/3d4cafe57b2bf8d32c7a3ff1e3a86396d4a88038))
* **crypt:** report rows without a key, bound get_sealed's reservation ([#263](https://github.com/onewaytek/owt-stack/issues/263)) ([4ee71b3](https://github.com/onewaytek/owt-stack/commit/4ee71b32254a1bd61c7010f411c933044f443bf2))
* **runtime:** count queue states from their partial indexes; pin the image signer ref ([#264](https://github.com/onewaytek/owt-stack/issues/264)) ([467db10](https://github.com/onewaytek/owt-stack/commit/467db104cb7f4a7c3951abb0428efcc083d1558a))


### Performance Improvements

* optimize crypto dependencies in dev and test builds ([#262](https://github.com/onewaytek/owt-stack/issues/262)) ([85bb5d2](https://github.com/onewaytek/owt-stack/commit/85bb5d2c14264ce2e2b57f3bea2c1b23e6c6c9b5))

## [0.10.0](https://github.com/onewaytek/owt-stack/compare/v0.9.0...v0.10.0) (2026-10-27)


### ⚠ BREAKING CHANGES

* **accounts:** `AccountCommand::Create` and `AccountCommand::Link` are tuple variants holding `cli::CreateArgs` and `cli::LinkArgs`; an app that builds or matches them (a test, say) writes `Create(CreateArgs { .. })` and `Link(LinkArgs { .. })`, and `LinkArgs::minutes` is an `Option<u32>`. The command line is unchanged apart from the new flags. The app runs `migrations::run` (or `start`) to apply migration 0006; an app that keeps copies of the library's migration files may copy `0006_link_next.sql` as its next version, unaltered.
* **accounts:** `PageCtx::flashes` is a method returning `&[Flash]`, no longer a public `Vec<Flash>` field. An app reads `page.flashes()` where it read `page.flashes` (`Alerts { flashes: page.flashes() }`, `{% for f in page.flashes() %}`), and cannot construct the field or move the `Vec` out; clone the slice (`.to_vec()`) where it needs ownership.
* **auth:** `Budgets` has a new field `attempt_window: Duration`. An app that builds `Budgets` with a struct literal without `..Budgets::default()` adds the field or the `..Budgets::default()` rest.
* **auth:** `Turnstile::verify` returns `Result<Outcome, VerifyError>` instead of `Result<bool, VerifyError>`. An app calling it directly replaces `verify(..).await? ` used as a bool with `.is_passed()`, and may log `Outcome::Refused { codes }` (at warn or error when `is_misconfigured()`). Apps that only use `Guard` change nothing.
* **deps:** owt-stack's crates declare rust-version 1.99. An app that builds with an older toolchain (a pinned rust-toolchain.toml or an older image) moves to Rust 1.99 or later; one on rust:1 or stable changes nothing.

### Features

* **accounts:** link --reason and --next, and CreateArgs and LinkArgs for an app's own commands ([#247](https://github.com/onewaytek/owt-stack/issues/247)) ([f5e9082](https://github.com/onewaytek/owt-stack/commit/f5e90821ef1ea279b3a50d8ca7c590bc206a841c)), closes [#226](https://github.com/onewaytek/owt-stack/issues/226)
* **accounts:** PageCtx takes its flash messages when the page is drawn ([#244](https://github.com/onewaytek/owt-stack/issues/244)) ([60e0a67](https://github.com/onewaytek/owt-stack/commit/60e0a67e88756ea4e5702326c7d6348e72e1b357)), closes [#225](https://github.com/onewaytek/owt-stack/issues/225)
* **auth:** guard budget window, signed-in posters and sign-in-required mode ([#245](https://github.com/onewaytek/owt-stack/issues/245)) ([4e02e16](https://github.com/onewaytek/owt-stack/commit/4e02e16c32882b2003a1ad3ce1206df4dead8cd8)), closes [#227](https://github.com/onewaytek/owt-stack/issues/227)
* **auth:** Turnstile::verify reports siteverify's error-codes ([#243](https://github.com/onewaytek/owt-stack/issues/243)) ([0ee8f58](https://github.com/onewaytek/owt-stack/commit/0ee8f5878c12f043a73fcc4274ac2e833d667939)), closes [#229](https://github.com/onewaytek/owt-stack/issues/229)
* **ci:** cargo-profile input for image-check.yml and image.yml ([#242](https://github.com/onewaytek/owt-stack/issues/242)) ([fe63952](https://github.com/onewaytek/owt-stack/commit/fe63952fcc0f59cef20def0919813fda6a7e88c5))
* **templates:** tunnel.yaml, a Cloudflare named tunnel per app ([#235](https://github.com/onewaytek/owt-stack/issues/235)) ([b9d865d](https://github.com/onewaytek/owt-stack/commit/b9d865db4f555d25d17a7bef9c4cc92708a55d22))
* **web:** Assets::warm hashes every file at startup, lazy reads leave the executor ([#246](https://github.com/onewaytek/owt-stack/issues/246)) ([7dd463b](https://github.com/onewaytek/owt-stack/commit/7dd463b1d28f8452d2ca8263791faf375e5b47d9)), closes [#232](https://github.com/onewaytek/owt-stack/issues/232)
* **web:** version the URLs inside served stylesheets ([#248](https://github.com/onewaytek/owt-stack/issues/248)) ([31adfff](https://github.com/onewaytek/owt-stack/commit/31adfff31a524b7d4aa5550b2a60df45878f2f19)), closes [#231](https://github.com/onewaytek/owt-stack/issues/231)


### Bug Fixes

* **deps:** bump astral-sh/setup-uv from 10.3.0 to 10.3.2 ([#237](https://github.com/onewaytek/owt-stack/issues/237)) ([f4f8770](https://github.com/onewaytek/owt-stack/commit/f4f87708d53131dc505a9f6aa08a34e0d11e6ccd))
* **deps:** bump docker/login-action from 4.6.0 to 4.7.0 ([#238](https://github.com/onewaytek/owt-stack/issues/238)) ([e87b38b](https://github.com/onewaytek/owt-stack/commit/e87b38bfb8d72602dbb6bfd655fb582ac3f0534d))
* **deps:** bump Swatinem/rust-cache from 2.9.2 to 2.9.3 ([#240](https://github.com/onewaytek/owt-stack/issues/240)) ([d2002f8](https://github.com/onewaytek/owt-stack/commit/d2002f8e9244d39918721ab6f37ffe214e6b06bf))
* **deps:** bump taiki-e/install-action from 2.87.29 to 2.87.31 ([#239](https://github.com/onewaytek/owt-stack/issues/239)) ([58c7b8e](https://github.com/onewaytek/owt-stack/commit/58c7b8e9bcfad263bebea71a1ad3661931141346))
* **test:** asset_versions masks only asset URLs, not every ?v= link ([#241](https://github.com/onewaytek/owt-stack/issues/241)) ([2fc2ae4](https://github.com/onewaytek/owt-stack/commit/2fc2ae46f62e43b4e3ea30ead3c5405eb1db4893))


### Build System

* **deps:** dependencies to their latest, and Rust 1.99 ([#233](https://github.com/onewaytek/owt-stack/issues/233)) ([cd4b27f](https://github.com/onewaytek/owt-stack/commit/cd4b27f5662d1f50436b24456e753d22183fec24))

## [0.9.0](https://github.com/onewaytek/owt-stack/compare/v0.8.1...v0.9.0) (2026-10-21)


### ⚠ BREAKING CHANGES

* **accounts:** owt-accounts migrates its own tables; migrations::assert_installed is gone. An app awaits owt_accounts::migrations::run(&pool) at start, before its own migrator, then deletes its copies of the library's files from migrations/ (and the assert_installed test) and sets set_ignore_missing(true) on its migrator, since the copies' rows stay in _sqlx_migrations; the first run adopts them by checksum without re-running anything. Its binary takes a migrate subcommand running that sequence, which the justfile's migrate_command and rust-ci.yml's migrate-command run, and its tests use #[sqlx::test(migrations = false)] and await the same sequence. An app whose own migrations must precede the library's runs them first with

### Features

* **accounts:** PageCtx, the context a full page is drawn with ([#211](https://github.com/onewaytek/owt-stack/issues/211)) ([1567b63](https://github.com/onewaytek/owt-stack/commit/1567b6348df5b1858bf8b9651b53c57cde72ca1c))
* **accounts:** password_gate signs in a fixed account against a deployment-wide hash ([#207](https://github.com/onewaytek/owt-stack/issues/207)) ([b5abfe4](https://github.com/onewaytek/owt-stack/commit/b5abfe433a3e04f2ccd3f61bb5b61eb6875c8658))
* **accounts:** the account commands as a clap subcommand behind a cli feature ([#218](https://github.com/onewaytek/owt-stack/issues/218)) ([01cdb03](https://github.com/onewaytek/owt-stack/commit/01cdb03411b08cc3480814f9e768492cbf331a45))
* **accounts:** the library migrates its own tables, in a ledger of its own ([#197](https://github.com/onewaytek/owt-stack/issues/197)) ([67c0095](https://github.com/onewaytek/owt-stack/commit/67c00950b1b3122af2c2a5613746a10613480e8d))
* **auth:** a bot guard for anonymous forms: honeypot, Turnstile and a budget ([#221](https://github.com/onewaytek/owt-stack/issues/221)) ([c1ada63](https://github.com/onewaytek/owt-stack/commit/c1ada63060548c6cebdc5ab8240f4184d9f47288)), closes [#154](https://github.com/onewaytek/owt-stack/issues/154)
* **ci:** conventional-commits.yml takes a title input to skip the title check ([#203](https://github.com/onewaytek/owt-stack/issues/203)) ([97697a7](https://github.com/onewaytek/owt-stack/commit/97697a7ff2bddab47f908a482166710d1f927367))
* **ci:** image-check.yml builds and verifies the image on a pull request without pushing ([#217](https://github.com/onewaytek/owt-stack/issues/217)) ([87ed7d6](https://github.com/onewaytek/owt-stack/commit/87ed7d654d1f5d32b6155c07c1dac7e351d950bd))
* **runtime:** start-up sequence and metrics listener helpers ([#219](https://github.com/onewaytek/owt-stack/issues/219)) ([55d5fe0](https://github.com/onewaytek/owt-stack/commit/55d5fe09d03712f5a5c8db29f01416d2ca35db7e)), closes [#149](https://github.com/onewaytek/owt-stack/issues/149)
* **templates:** apply.sh runs an optional pre-render hook ([#209](https://github.com/onewaytek/owt-stack/issues/209)) ([5a3a72c](https://github.com/onewaytek/owt-stack/commit/5a3a72c972fd4d55cb0980349258addc8dc111cb))
* **templates:** cronjob.yaml reads a Secret of the task's own ([#205](https://github.com/onewaytek/owt-stack/issues/205)) ([d26c1be](https://github.com/onewaytek/owt-stack/commit/d26c1be55f2143f578c81f1dd04ad8f5cee65911))
* **templates:** env.sh makes the app's environment Secret ([#212](https://github.com/onewaytek/owt-stack/issues/212)) ([ed2f8b8](https://github.com/onewaytek/owt-stack/commit/ed2f8b89c7023e5f667747891ca01ed5016a539a))
* **test:** account fixtures and a client signed in without Argon2 ([#220](https://github.com/onewaytek/owt-stack/issues/220)) ([fd0f0eb](https://github.com/onewaytek/owt-stack/commit/fd0f0ebd3b14a0ce90c5c17dac4a4b336ab7a17a)), closes [#151](https://github.com/onewaytek/owt-stack/issues/151)
* **web:** a preference cookie read from an allowed set and always Secure ([#215](https://github.com/onewaytek/owt-stack/issues/215)) ([5a38e2e](https://github.com/onewaytek/owt-stack/commit/5a38e2e809485295b4ed4796b3531ae7c07769c7)), closes [#153](https://github.com/onewaytek/owt-stack/issues/153)
* **web:** apply the standard layer stack in the one correct order with Stack ([#214](https://github.com/onewaytek/owt-stack/issues/214)) ([734641a](https://github.com/onewaytek/owt-stack/commit/734641a4b3b70131944e9a2538345d7d824a10b3))
* **web:** serve static files from Assets with the cache policy, and define url() by macro ([#208](https://github.com/onewaytek/owt-stack/issues/208)) ([64ac2ac](https://github.com/onewaytek/owt-stack/commit/64ac2acb5c3c4018f240e93d13470bf86a43145c))
* **web:** text helpers for UTC dates, relative times, plurals and LIKE escaping ([#206](https://github.com/onewaytek/owt-stack/issues/206)) ([a52130f](https://github.com/onewaytek/owt-stack/commit/a52130f4b32c69538a10a2a6f37b73f784a417d2)), closes [#152](https://github.com/onewaytek/owt-stack/issues/152)


### Bug Fixes

* **ci:** requeue-rc re-runs a person's lost promotion before a bot's ([#210](https://github.com/onewaytek/owt-stack/issues/210)) ([69c54dd](https://github.com/onewaytek/owt-stack/commit/69c54dd33240919c8bac3ea99ec31a6353bb0ff7))
* **ci:** sync-rc releases rc when main brought code rc lacked ([#213](https://github.com/onewaytek/owt-stack/issues/213)) ([8c8d4af](https://github.com/onewaytek/owt-stack/commit/8c8d4af4a99615370083b08d21fa878c252500c6))
* **deps:** bump actions/download-artifact from 8.0.1 to 8.0.2 ([#193](https://github.com/onewaytek/owt-stack/issues/193)) ([4213c58](https://github.com/onewaytek/owt-stack/commit/4213c586eda45b09de27d4a8e219a6383a3fd11a))
* **deps:** bump actions/upload-artifact from 7.0.1 to 7.0.2 ([#194](https://github.com/onewaytek/owt-stack/issues/194)) ([671c227](https://github.com/onewaytek/owt-stack/commit/671c2271ba92c5aec6e4ad0d8be7797b82f8bd4e))
* **deps:** bump html-escape from 0.2.15 to 0.3.0 ([#196](https://github.com/onewaytek/owt-stack/issues/196)) ([0160897](https://github.com/onewaytek/owt-stack/commit/0160897d093948cc1c7ee486727b8f89e887bb03))
* **deps:** bump taiki-e/install-action from 2.87.27 to 2.87.29 ([#192](https://github.com/onewaytek/owt-stack/issues/192)) ([4ed1ee5](https://github.com/onewaytek/owt-stack/commit/4ed1ee5a45b70637ab0777982b3e1c840fd00661))
* **deps:** bump the patch-and-minor group with 4 updates ([#195](https://github.com/onewaytek/owt-stack/issues/195)) ([39f6b29](https://github.com/onewaytek/owt-stack/commit/39f6b29e2d872b258b0e345c294c7594597a4c52))
* **deps:** rustls-webpki and the webpki root bundles refuse the distrusted intermediates ([#223](https://github.com/onewaytek/owt-stack/issues/223)) ([67174d5](https://github.com/onewaytek/owt-stack/commit/67174d5c326c4d7dc9d37999cd7b0680d19e5ed3))
* **templates:** apply.sh passes parameters in a --param-file ([#204](https://github.com/onewaytek/owt-stack/issues/204)) ([c8cdad9](https://github.com/onewaytek/owt-stack/commit/c8cdad9a0e224a6b9473250ba30e9a95ec96d0ad))

## [0.8.1](https://github.com/onewaytek/owt-stack/compare/v0.8.0...v0.8.1) (2026-10-19)


### Behaviour changes

Nothing an app must change, but three things behave differently:

* **runtime:** `PoolConfig::connect` waits for an unreachable database instead of failing at once: it retries network errors, a timed-out attempt and Postgres starting or stopping, with backoff, for `db::STARTUP_PATIENCE` (60 s; about two minutes in the worst case with `acquire_timeout`), inside the template's five-minute startup probe. A refused password, a missing database or a certificate that does not verify still fails at once. `PoolConfig::connect_within(url, Duration::ZERO)` keeps the single attempt.
* **test:** `owt_test::Client` sends every request from a fixed peer, `owt_test::PEER` (192.0.2.1:40000), as axum's `MockConnectInfo`. A handler taking `ConnectInfo<SocketAddr>` or `ClientIp` that answered 500 under the client now answers; a test that asserted that 500 uses `Client::with_peer(None)`. A router's own `MockConnectInfo` or `Extension(ConnectInfo(..))` layer still decides.
* **templates:** the first apply of the new `app.yaml` sets the Route's `haproxy.router.openshift.io/timeout` to `ROUTE_TIMEOUT` (default `30s`): copy a timeout set on the Route by hand into `params.env` first, with its unit (`apply.sh` refuses one without). An app that copies the template `justfile` takes its `migrate` recipe, which refuses a shared `postgres` or `template1` database outside CI.


### Features

* **runtime:** PoolConfig::connect retries an unreachable database for a minute ([#187](https://github.com/onewaytek/owt-stack/issues/187)) ([0863746](https://github.com/onewaytek/owt-stack/commit/0863746b1cab202cf437ae06ecd5588bf0dc27d0))
* **templates:** RUST_LOG is a parameter of app.yaml and cronjob.yaml ([#181](https://github.com/onewaytek/owt-stack/issues/181)) ([b1c2605](https://github.com/onewaytek/owt-stack/commit/b1c2605a4891f769f5b16833fdb9e2a65d779270))
* **templates:** the Route's timeout is a parameter of app.yaml ([#182](https://github.com/onewaytek/owt-stack/issues/182)) ([acb0b1e](https://github.com/onewaytek/owt-stack/commit/acb0b1e52d7a02beca78f0aed8c7db0aa5aa1b36))
* **test:** owt_test::Client::get_page loads a page as a browser does ([#188](https://github.com/onewaytek/owt-stack/issues/188)) ([2ab36bd](https://github.com/onewaytek/owt-stack/commit/2ab36bd318511789b02dcc43f1ed7bcdd8e22c3b))
* **web:** ClientIp accepts MockConnectInfo, and owt_test::Client supplies a peer ([#186](https://github.com/onewaytek/owt-stack/issues/186)) ([8738334](https://github.com/onewaytek/owt-stack/commit/8738334eca5ebdecd28d924d74b1982a05f5af8e)), closes [#157](https://github.com/onewaytek/owt-stack/issues/157)
* **web:** ClientIp logs at debug how it chose an address ([#185](https://github.com/onewaytek/owt-stack/issues/185)) ([7588508](https://github.com/onewaytek/owt-stack/commit/7588508296f946aab01532a45dada37c77e6b826)), closes [#160](https://github.com/onewaytek/owt-stack/issues/160)
* **web:** Sessions::from_env keeps a key purpose of any shape ([#184](https://github.com/onewaytek/owt-stack/issues/184)) ([464b25e](https://github.com/onewaytek/owt-stack/commit/464b25e3ebb7a2b3792b3526b7adc5c6094f0f27)), closes [#155](https://github.com/onewaytek/owt-stack/issues/155)


### Bug Fixes

* **ci:** a commit subject may start with an upper-case code identifier ([#176](https://github.com/onewaytek/owt-stack/issues/176)) ([9a6a33a](https://github.com/onewaytek/owt-stack/commit/9a6a33a343ac798825e149924b506c6377dab626)), closes [#162](https://github.com/onewaytek/owt-stack/issues/162)
* **ci:** requeue-rc compares the run's attempt as well as its status ([#179](https://github.com/onewaytek/owt-stack/issues/179)) ([8a09a28](https://github.com/onewaytek/owt-stack/commit/8a09a28fd20916e95f591c9eafaae29ac0f17b6f)), closes [#120](https://github.com/onewaytek/owt-stack/issues/120)
* **templates:** dependabot ignores the stylesheet's git-tag dependency ([#174](https://github.com/onewaytek/owt-stack/issues/174)) ([6587e10](https://github.com/onewaytek/owt-stack/commit/6587e100c2c9cb67bb2666b130cad97fd28ffa08)), closes [#164](https://github.com/onewaytek/owt-stack/issues/164)
* **templates:** redis.yaml's egress policy omits the empty egress list ([#178](https://github.com/onewaytek/owt-stack/issues/178)) ([8fea82b](https://github.com/onewaytek/owt-stack/commit/8fea82bfecc46a906d23b1591ff721a0321d7f27)), closes [#177](https://github.com/onewaytek/owt-stack/issues/177)
* **templates:** the template's check migrates before anything compiles queries ([#175](https://github.com/onewaytek/owt-stack/issues/175)) ([3f1b156](https://github.com/onewaytek/owt-stack/commit/3f1b1560f26023adf1408c3c170d9ed0bf879b3c)), closes [#156](https://github.com/onewaytek/owt-stack/issues/156)

## [0.8.0](https://github.com/onewaytek/owt-stack/compare/v0.7.0...v0.8.0) (2026-10-19)


### ⚠ BREAKING CHANGES

* **ci:** image.yml needs `bin` (the Cargo binary) unless the call sets `builder: docker`, and builds on RUNS_ON (the ARC scale set by default). A template-shaped app adds `bin` (and `port` when not 8000) and passes the SCCACHE_REDIS_PASSWORD secret by name; an app with its own runtime stage maps it onto the inputs or keeps `builder: docker`. The image is a single linux/amd64 manifest without a build attestation, and carries the base's name and digest as labels.
* **ci:** release.yml's release job, promote-rc.yml, publish-rc.yml, requeue-rc.yml and conventional-commits.yml run on the arc-openshift-k8s scale set unless the `RUNS_ON` variable names other runners (a fork's pull request is checked GitHub-hosted). The release job runs only for a push or a workflow_dispatch, and promote-rc.yml, publish-rc.yml and requeue-rc.yml only for a push, a workflow_dispatch, a schedule or a same-repository pull_request; a caller on pull_request_target, workflow_run or another event moves to one of those. An app's `version-command` now runs in the ARC runner pod, which has git, curl, jq, tar, perl, Node and uv but no cargo or gh: install what it needs in the command, or set `RUNS_ON` to `"ubuntu-latest"`.

### Features

* **ci:** image.yml builds daemonless on the ARC scale set with crane ([#168](https://github.com/onewaytek/owt-stack/issues/168)) ([c0b116d](https://github.com/onewaytek/owt-stack/commit/c0b116d027957ee89456b3a506b2163f4c32ea78))
* **ci:** the release flow's light jobs run on the ARC scale set ([#166](https://github.com/onewaytek/owt-stack/issues/166)) ([e6e7dd5](https://github.com/onewaytek/owt-stack/commit/e6e7dd533730c6e1a237f96edb03c110adeb031e))

## [0.7.0](https://github.com/onewaytek/owt-stack/compare/v0.6.1...v0.7.0) (2026-10-18)


### ⚠ BREAKING CHANGES

* `owt_accounts::session::Data` has a `flashes: Vec<Flash>` field (serialized as `f`, absent when empty, so sealed cookies read both ways) and is no longer `Copy`: a struct literal adds `..Data::default()`, and a copy becomes a clone. An app whose own session type only added flashes uses `session::Data` or `social::Data`, which implement `HasFlashes`.
* **templates:** `redis.yaml`'s `IMAGE` and `MEMORY_LIMIT` parameters are `REDIS_IMAGE` and `REDIS_MEMORY_LIMIT`, apart from `app.yaml`'s, so one `params.env` serves every template through `deploy/openshift/apply.sh`; an apply that passed `-p IMAGE=` or `-p MEMORY_LIMIT=` to `redis.yaml` passes the new names (the defaults are unchanged). Keep the templates in `deploy/openshift/` with `apply.sh` and `params.env`, and drop the app's own process or apply script where the template's does the same.
* Every public enum that can grow is `#[non_exhaustive]`: a `match` in an app on `owt_web::Error`, `owt_web::client_ip::Source`, `owt_web::ui::Kind` (an Askama `{% match %}` included), `owt_accounts::Refused`, `owt_accounts::Error`, `owt_accounts::password::Problem`, `owt_accounts::identities::Arrival`, `owt_accounts::identities::RekeyError`, `owt_accounts::social::ConfigError`, `owt_auth::jwt::Error` or `owt_change::ConfigError` ends with a `_` arm, and `owt_web::ui::Item` is read by its fields, never built or destructured as a whole. Constructing and matching the variants by name is unchanged. A variant added later comes without a breaking release.
* **ci:** `rust-ci.yml` compiles through sccache over a shared Redis instead of a cargo cache volume at `/cache`. To use it, an app passes the one secret by name on its call of `rust-ci.yml` (`secrets: {SCCACHE_REDIS_PASSWORD: "${{ secrets.SCCACHE_REDIS_PASSWORD }}"}`), never `secrets: inherit`, which would hand the reusable workflow every secret the app holds. A workflow of the app's own that calls the one calling `rust-ci.yml` may use `secrets: inherit`, being the app's code. The app makes a secret `SCCACHE_REDIS_PASSWORD` visible to the repository: an organization secret, or a repository secret for a private repository on GitHub Free. An app on GitHub-hosted runners (`RUNS_ON`) passes `sccache-redis: ""`. Pin the reusable workflows by commit, with the tag in a comment, and let Dependabot's `github-actions` ecosystem move the pin. Remove the `/cache` volume mount from the runner pod template. Without the secret the checks pass, uncached.

### Features

* **accounts:** admin::Words, the admin's words in the app's language ([#141](https://github.com/onewaytek/owt-stack/issues/141)) ([b086b73](https://github.com/onewaytek/owt-stack/commit/b086b732ac973dacc9246772279cd6fb07e91abe))
* **accounts:** an app's chrome may await (AsyncChrome), for the admin and the policy pages ([#131](https://github.com/onewaytek/owt-stack/issues/131)) ([04b8d39](https://github.com/onewaytek/owt-stack/commit/04b8d39bf98d35444c4b8ef68461574b15abed60))
* **accounts:** example view models for an app's tests of its own admin templates ([#132](https://github.com/onewaytek/owt-stack/issues/132)) ([5b8ad40](https://github.com/onewaytek/owt-stack/commit/5b8ad408c87d63a40fe8bbe0a2599031b897d65b))
* **accounts:** password_sign_in, store::problems, and last_sign_in on every way in ([#143](https://github.com/onewaytek/owt-stack/issues/143)) ([4fb3da7](https://github.com/onewaytek/owt-stack/commit/4fb3da7c49a9f0aed076e877df47be81686f021a))
* **accounts:** policies::Views and social::Views, the pages an app draws itself ([#142](https://github.com/onewaytek/owt-stack/issues/142)) ([43a5fb7](https://github.com/onewaytek/owt-stack/commit/43a5fb71e662a69f677199f49b54630c8c3864ea))
* **ci:** compiled dependencies from sccache over a shared Redis, not a cache volume ([#116](https://github.com/onewaytek/owt-stack/issues/116)) ([94ec486](https://github.com/onewaytek/owt-stack/commit/94ec48674f971d0356d0e311b9cf6731fbd3425e))
* **ci:** conventional-commits.yml is callable from an app's pull-request workflow ([#137](https://github.com/onewaytek/owt-stack/issues/137)) ([c0b22d5](https://github.com/onewaytek/owt-stack/commit/c0b22d57ca7cd8cb7e2eb114e1c230dc6df34b65))
* every public enum that can grow is non_exhaustive ([#126](https://github.com/onewaytek/owt-stack/issues/126)) ([2477a68](https://github.com/onewaytek/owt-stack/commit/2477a682dccae6ed0482662e92253d4eb5ebc291))
* Sessions::from_env, and flash messages in session::Data ([#144](https://github.com/onewaytek/owt-stack/issues/144)) ([c333375](https://github.com/onewaytek/owt-stack/commit/c333375e13b507fdf7c8038bb946bc51eb9e6ce5))
* **templates:** apply.sh renders every template from the app's params.env ([#139](https://github.com/onewaytek/owt-stack/issues/139)) ([f545c04](https://github.com/onewaytek/owt-stack/commit/f545c04016ba71989f3cbb6dac32973b0d06ef0a))
* **templates:** dependabot.yml for an app ([#138](https://github.com/onewaytek/owt-stack/issues/138)) ([ea52b64](https://github.com/onewaytek/owt-stack/commit/ea52b6435cbbbfb6e6e62d57dcef971e097254bd))
* **templates:** egress.yaml bounds where an app's pods may connect; Redis connects to nothing ([#135](https://github.com/onewaytek/owt-stack/issues/135)) ([d32b5ff](https://github.com/onewaytek/owt-stack/commit/d32b5ffa397626b5d79e99bbbfcaa283eda84a64))
* **test:** Normalizer::asset_versions, and two adoption notes ([#130](https://github.com/onewaytek/owt-stack/issues/130)) ([b835dac](https://github.com/onewaytek/owt-stack/commit/b835dac5bc4953b9393779c90d11e6d45f9ed546))
* **web:** the ClientIp extractor, and Source::from_env ([#145](https://github.com/onewaytek/owt-stack/issues/145)) ([7d90c5b](https://github.com/onewaytek/owt-stack/commit/7d90c5b5a852d4301ce39c461406ca0a99b83587))


### Bug Fixes

* **accounts:** a boosted navigation is a page load for the policy gate ([#136](https://github.com/onewaytek/owt-stack/issues/136)) ([937c498](https://github.com/onewaytek/owt-stack/commit/937c4986a388ba5b695db4ce1e438263171b1683))
* **accounts:** every admin and policies response is no-store, the refusals included ([#128](https://github.com/onewaytek/owt-stack/issues/128)) ([88a84e8](https://github.com/onewaytek/owt-stack/commit/88a84e821975b0c82db5835b3b4627869548072e))
* **accounts:** LastWayIn reads neutrally, and the admin's notice has words of its own ([#127](https://github.com/onewaytek/owt-stack/issues/127)) ([4040282](https://github.com/onewaytek/owt-stack/commit/40402821c1178c44b88e8083b9ba7f365d9e85ad))
* **accounts:** the admin and the policy pages hand the chrome the page's own URI ([#129](https://github.com/onewaytek/owt-stack/issues/129)) ([98b941b](https://github.com/onewaytek/owt-stack/commit/98b941b6b2dd83cb0a6d48fe5e9ee5ac8f9249ff))
* **accounts:** the policy gate sends only document loads to the page that asks ([#133](https://github.com/onewaytek/owt-stack/issues/133)) ([23b8111](https://github.com/onewaytek/owt-stack/commit/23b811173c44a76e8ca5de030c1f840d716a2177))
* **change:** the change-request routes refuse a cross-origin POST themselves ([#124](https://github.com/onewaytek/owt-stack/issues/124)) ([5ffe22c](https://github.com/onewaytek/owt-stack/commit/5ffe22c19ac124c35a60e0a8dd2dcac6e7ece860))

## [0.6.1](https://github.com/onewaytek/owt-stack/compare/v0.6.0...v0.6.1) (2026-10-17)


### Features

* **templates:** backup instance and prune-image options; fix requeue and CI cache fallback ([#103](https://github.com/onewaytek/owt-stack/issues/103)) ([9df3790](https://github.com/onewaytek/owt-stack/commit/9df3790086082bd5ba0498c0eb2109edcd0d7c4b)), closes [#98](https://github.com/onewaytek/owt-stack/issues/98)


### Bug Fixes

* **ci:** requeue-rc reads the run's status instead of GitHub's refusal wording ([#117](https://github.com/onewaytek/owt-stack/issues/117)) ([81b4a27](https://github.com/onewaytek/owt-stack/commit/81b4a27477e55003008ada0013030a38b612aea4))

## [0.6.0](https://github.com/onewaytek/owt-stack/compare/v0.5.0...v0.6.0) (2026-10-17)


### ⚠ BREAKING CHANGES

* **accounts:** install owt_accounts::migrations::ALL[4] (owt_accounts_local, 0005_local_identities.sql) as the app's next unused migration version, and await owt_accounts::migrations::complete before serving as before (it validates the constraint 0005 adds); assert_installed expects every entry. It takes the table account_local_identities, the column accounts.password_sign_in and the constraint accounts_password_sign_in_hash. Refused has a new variant, NoPasswordSignIn: an exhaustive match on it needs an arm.
* Leases::new returns anyhow::Result<Leases>: add ?. Cache::connect and Leases::new refuse a prefix with characters other than ASCII letters, digits, _, . and -. An app whose prefix has a : or a space renames it. Its cache starts cold, and during that rollout a leased job may run on an old and a new replica at once.
* **auth:** oauth::Provider's scope is a Cow<'static, str>: scope: "openid email" becomes scope: "openid email".into(), and a configured scope is passed as a String (scope: configured.into()) instead of a leaked &'static str. oauth::Error is #[non_exhaustive]: a match on it adds a _ arm.
* **accounts:** install owt_accounts::migrations::ALL[3] (owt_accounts_policies, 0004_policies.sql) as the app's next unused migration version, whether or not the app uses site policies: assert_installed expects every entry. Its tables stay empty until the app wires policies::Policies.
* Pagination has a public words field. A Pagination written as a struct literal adds words: owt_web::ui::PagerWords::ENGLISH; one made with Pagination::new needs no change.

### Features

* **accounts:** a public username rule for sign-up forms ([#67](https://github.com/onewaytek/owt-stack/issues/67)) ([db53560](https://github.com/onewaytek/owt-stack/commit/db53560d2d2dc8fddc1d3887a802766dd5024788))
* **accounts:** an app draws the admin with its own templates ([#94](https://github.com/onewaytek/owt-stack/issues/94)) ([5c62816](https://github.com/onewaytek/owt-stack/commit/5c62816f880f3e7d4bb7faf813746ff227d011b3)), closes [#77](https://github.com/onewaytek/owt-stack/issues/77)
* **accounts:** local and system accounts, reached by an app's own key with no password ([#95](https://github.com/onewaytek/owt-stack/issues/95)) ([36b2ba6](https://github.com/onewaytek/owt-stack/commit/36b2ba660c237baa031c0e5869b15061719b46c1))
* **accounts:** name the tables the migrations take, and migrations::conflicts ([#85](https://github.com/onewaytek/owt-stack/issues/85)) ([03d0b63](https://github.com/onewaytek/owt-stack/commit/03d0b639ae6f20109b036009dfd4836abd8c6a32)), closes [#69](https://github.com/onewaytek/owt-stack/issues/69)
* **accounts:** read an app's extra about the viewer in the load query ([#93](https://github.com/onewaytek/owt-stack/issues/93)) ([e34c98c](https://github.com/onewaytek/owt-stack/commit/e34c98c8e80ded65d5aa9d5f67b43293962cefe8)), closes [#78](https://github.com/onewaytek/owt-stack/issues/78)
* **accounts:** run the app's code at each provider sign-in (SocialSignIn::on_arrival) ([#50](https://github.com/onewaytek/owt-stack/issues/50)) ([a335da6](https://github.com/onewaytek/owt-stack/commit/a335da64ff1459a9e97ab1b3427ebcdadd1ed1f0))
* **accounts:** the admin also searches the app's own columns ([#89](https://github.com/onewaytek/owt-stack/issues/89)) ([247c34a](https://github.com/onewaytek/owt-stack/commit/247c34a147ecbbf302c913893f35c122fb9286d2)), closes [#52](https://github.com/onewaytek/owt-stack/issues/52)
* **accounts:** the admin shows password sign-in off and an account's local identities ([#97](https://github.com/onewaytek/owt-stack/issues/97)) ([f47d5d4](https://github.com/onewaytek/owt-stack/commit/f47d5d43b937a6bd458d9a24cc7c6c1e80323ca8)), closes [#96](https://github.com/onewaytek/owt-stack/issues/96)
* **accounts:** the provider's tokens at each sign-in and connect, and arrive_in ([#92](https://github.com/onewaytek/owt-stack/issues/92)) ([541b62e](https://github.com/onewaytek/owt-stack/commit/541b62ee54a013840b34ccb139451fb3f77b1eef)), closes [#60](https://github.com/onewaytek/owt-stack/issues/60)
* **accounts:** track which version of each site policy an account accepted ([#56](https://github.com/onewaytek/owt-stack/issues/56)) ([a982a8a](https://github.com/onewaytek/owt-stack/commit/a982a8a7bc2e4a77dda3ff5a026b254da0d94585))
* **auth:** an owned oauth::Provider scope, and a non-exhaustive oauth::Error ([#80](https://github.com/onewaytek/owt-stack/issues/80)) ([97eb1d5](https://github.com/onewaytek/owt-stack/commit/97eb1d53274b3b352cb64a1fa82067ddca220737))
* **auth:** hand back the token set from a sign-in, refresh it, and get an app's own token ([#48](https://github.com/onewaytek/owt-stack/issues/48)) ([02bf671](https://github.com/onewaytek/owt-stack/commit/02bf671c98474ee712d1bdea90d188ac1f954480))
* **auth:** put owt_auth::jwt behind a default jwt feature ([#90](https://github.com/onewaytek/owt-stack/issues/90)) ([87883bd](https://github.com/onewaytek/owt-stack/commit/87883bd6177e7db2db6344eb6534b2988e56e3cf)), closes [#70](https://github.com/onewaytek/owt-stack/issues/70)
* **ci:** cache sqlx-cli, mirror the job image, requeue lost rc promotions ([#64](https://github.com/onewaytek/owt-stack/issues/64)) ([8fe2e77](https://github.com/onewaytek/owt-stack/commit/8fe2e77789c1978032636ffb3ca29edf4ae62ea1)), closes [#61](https://github.com/onewaytek/owt-stack/issues/61) [#62](https://github.com/onewaytek/owt-stack/issues/62)
* **runtime:** jobs that run at schedule boundaries (Every::aligned) ([#91](https://github.com/onewaytek/owt-stack/issues/91)) ([91df731](https://github.com/onewaytek/owt-stack/commit/91df731793e7f2e7785905ac054aff44bd1a0943)), closes [#76](https://github.com/onewaytek/owt-stack/issues/76)
* **templates:** app environment from a Secret, an optional Redis, and a CronJob template ([#86](https://github.com/onewaytek/owt-stack/issues/86)) ([a63eaaf](https://github.com/onewaytek/owt-stack/commit/a63eaaf9fb428ce4237cb7d19cc4ff1d604e9c27)), closes [#74](https://github.com/onewaytek/owt-stack/issues/74)
* **templates:** pin an existing cluster's Postgres major and document a major upgrade ([#83](https://github.com/onewaytek/owt-stack/issues/83)) ([9bc0fc4](https://github.com/onewaytek/owt-stack/commit/9bc0fc4e84e00a54d0faf97881d4abc7aa1f83af)), closes [#75](https://github.com/onewaytek/owt-stack/issues/75)
* the words owt's components write, in the page's language ([#57](https://github.com/onewaytek/owt-stack/issues/57)) ([07db751](https://github.com/onewaytek/owt-stack/commit/07db7511bf26fd1cd0017db14cb0e8f17c265772))
* **web:** Csp::allow_style_attributes for style="…" attributes ([#82](https://github.com/onewaytek/owt-stack/issues/82)) ([b5a7722](https://github.com/onewaytek/owt-stack/commit/b5a772295f8b5639a2e47d8bb943634bc646364f)), closes [#71](https://github.com/onewaytek/owt-stack/issues/71)
* **web:** Limits is a layer, so a route can have its own bounds ([#84](https://github.com/onewaytek/owt-stack/issues/84)) ([82c2a73](https://github.com/onewaytek/owt-stack/commit/82c2a73a97ee814d04606af650de1e2de063b691)), closes [#73](https://github.com/onewaytek/owt-stack/issues/73)
* **web:** try_trust refuses a bad trusted origin with an error naming it ([#66](https://github.com/onewaytek/owt-stack/issues/66)) ([9c3b892](https://github.com/onewaytek/owt-stack/commit/9c3b892ea224e37cdc9fbdb187fbdf57babb12d2)), closes [#53](https://github.com/onewaytek/owt-stack/issues/53)


### Bug Fixes

* **accounts:** a database failure in the provider callback still uses up the pending sign-in ([#88](https://github.com/onewaytek/owt-stack/issues/88)) ([7b57d76](https://github.com/onewaytek/owt-stack/commit/7b57d76ea0163210c38a130125f6058e5da781e2)), closes [#59](https://github.com/onewaytek/owt-stack/issues/59)
* **accounts:** the sign-in wall answers htmx with HX-Redirect ([#87](https://github.com/onewaytek/owt-stack/issues/87)) ([f229270](https://github.com/onewaytek/owt-stack/commit/f22927043e23cbe5589fa7151ba48fad416cea31)), closes [#72](https://github.com/onewaytek/owt-stack/issues/72)
* one prefix rule for the cache, leases and bus; owt-accounts optional in owt-change ([#81](https://github.com/onewaytek/owt-stack/issues/81)) ([5910c40](https://github.com/onewaytek/owt-stack/commit/5910c4043076bb638137da0ee549cc4ea113ace2))

## [0.5.0](https://github.com/onewaytek/owt-stack/compare/v0.4.4...v0.5.0) (2026-10-16)


### ⚠ BREAKING CHANGES

* **accounts:** apps install ALL[2] (0003) as their next unused migration version and await owt_accounts::migrations::complete (new) before serving; it returns Completed (renames, cleared emails and passwords, failures). Usernames that collide once normalized are renamed. store::create takes &PgPool; store::create_in takes a connection. links::MAX_TTL is 30 days. Refused has CurrentPassword and UsernameLookalike variants.
* **web:** CrossOrigin::trust panics on an entry that is not an http(s) origin. A 5xx response no longer carries session changes, except a sign-out. key_from_base64 and key_for refuse a secret with fewer than 8 distinct byte values. Moving from key_from_base64 to key_for signs everyone out unless the old key is kept with also_open_with for a while.
* Bus::redis errors on a prefix outside [A-Za-z0-9_.-] or a zero beat_every. CHANGE_REQUESTS_URL must be https except to localhost or a cluster service named absolutely (….svc.cluster.local., with the final dot). Cache keys move to <prefix>:c: (the cache starts cold once). The server does not answer h2c.
* **accounts:** install owt_accounts::migrations::ALL[1] (roles) as the app's next unused migration version; assert_installed fails until it is there. store::Account has a `roles` field (a struct literal adds `roles: Vec::new()`). Admin::routes() returns the routes at the base given to Admin::new; merge them instead of nesting. Role cannot be built with a struct literal, and `inactive` is a reserved role name.
* **accounts:** Welcome::match_verified_email and Arrival::Matched are gone; a person adds a provider by signing in first and calling identities::link from that session. identities::arrive, find and link take &oauth::Provider (and link takes the &Identity). oauth::oidc takes the issuer as its third argument, returns Result<Provider, oauth::Error>, and refuses a non-canonical issuer; Provider has an `issuer` field. oauth::Error has IdToken, Config and Redirected variants. identities::arrive returns Err(Refused::NoSubject) for an empty subject. Welcome has a record_email field, off by default, so created accounts no longer take the provider's email unless it is set. An app with OIDC identities stored under the provider's id moves them with identities::rekey.

### Features

* **accounts:** roles an app declares, and the staff accounts admin ([#40](https://github.com/onewaytek/owt-stack/issues/40)) ([a97307b](https://github.com/onewaytek/owt-stack/commit/a97307b9a83f46a85fb11ff402a63ad96e57df73))
* **accounts:** sign-in with a provider, as routes an app mounts ([#41](https://github.com/onewaytek/owt-stack/issues/41)) ([8fcfee6](https://github.com/onewaytek/owt-stack/commit/8fcfee62dc4ba84add9a0893fcf6d18ac306a439))


### Bug Fixes

* **accounts:** find provider identities by subject only, never by email ([#39](https://github.com/onewaytek/owt-stack/issues/39)) ([630a9fd](https://github.com/onewaytek/owt-stack/commit/630a9fd7512b8f4f899e7dc6fda0d9f2142eca38))
* **accounts:** no lookalike usernames, no sign-in outliving a password change ([#45](https://github.com/onewaytek/owt-stack/issues/45)) ([a8903f0](https://github.com/onewaytek/owt-stack/commit/a8903f0af40aeabfe2a0ef3bf0e386576ee23fd8))
* bound metric labels, request heads and drains; stop a singleton without its lock ([#42](https://github.com/onewaytek/owt-stack/issues/42)) ([316fcf7](https://github.com/onewaytek/owt-stack/commit/316fcf7f81c4556ca65928973ddf3d1653a5f437))
* **ci:** keep unreviewed rc code from configuring a release or a stable image ([#43](https://github.com/onewaytek/owt-stack/issues/43)) ([946d58a](https://github.com/onewaytek/owt-stack/commit/946d58a6b552899cdaaabc1aeb949879f0af1041))
* **web:** a key per app and environment; no session sealed into a 5xx; trusted origins checked ([#44](https://github.com/onewaytek/owt-stack/issues/44)) ([7653807](https://github.com/onewaytek/owt-stack/commit/76538075fed892180fbad27fac5ede3c0f76f2bb))

## [0.4.4](https://github.com/onewaytek/owt-stack/compare/v0.4.3...v0.4.4) (2026-10-14)


### Features

* **ci:** use the ARC cargo-cache volume when the job pod has one ([#32](https://github.com/onewaytek/owt-stack/issues/32)) ([b848c61](https://github.com/onewaytek/owt-stack/commit/b848c61101d4e9ce3948f265b38ed642c552b51f))


### Bug Fixes

* **deps:** bump actions/setup-node from 7.0.0 to 7.1.0 ([#34](https://github.com/onewaytek/owt-stack/issues/34)) ([7d36f6b](https://github.com/onewaytek/owt-stack/commit/7d36f6b45ffeb786d4aec2dfe8638db594ec7911))
* **deps:** bump astral-sh/setup-uv from 10.2.0 to 10.3.0 ([#35](https://github.com/onewaytek/owt-stack/issues/35)) ([968b14f](https://github.com/onewaytek/owt-stack/commit/968b14fc9a4dd6e8f3ab08f47f2dd2a5a7af6282))
* **deps:** bump rustls to 0.23.46 for RUSTSEC-2026-0346..0349 ([#37](https://github.com/onewaytek/owt-stack/issues/37)) ([103122d](https://github.com/onewaytek/owt-stack/commit/103122d4b62c2843c2d563767e01d9e5efe381a8))
* **deps:** bump taiki-e/install-action from 2.87.26 to 2.87.27 ([#33](https://github.com/onewaytek/owt-stack/issues/33)) ([58a8bea](https://github.com/onewaytek/owt-stack/commit/58a8beaa4ad345d0129a88f4289836779aa2a763))
* **deps:** bump the patch-and-minor group with 6 updates ([#36](https://github.com/onewaytek/owt-stack/issues/36)) ([decc49a](https://github.com/onewaytek/owt-stack/commit/decc49a8c6151a99117942d9f98b4b68d1acfa6c))

## [0.4.3](https://github.com/onewaytek/owt-stack/compare/v0.4.2...v0.4.3) (2026-10-12)


### Features

* **ci:** check the merge before rc moves ([#30](https://github.com/onewaytek/owt-stack/issues/30)) ([6c20eaa](https://github.com/onewaytek/owt-stack/commit/6c20eaa1955517faccb1b39a27a7044b7469aa36))

## [0.4.2](https://github.com/onewaytek/owt-stack/compare/v0.4.1...v0.4.2) (2026-10-09)


### Features

* **change:** change requests from a site's own pages ([#27](https://github.com/onewaytek/owt-stack/issues/27)) ([eb7b369](https://github.com/onewaytek/owt-stack/commit/eb7b369c55c066c6feadc148da945ad07d737b2f))
* **templates:** build every stage from Red Hat Hummingbird images ([#25](https://github.com/onewaytek/owt-stack/issues/25)) ([87c3ed1](https://github.com/onewaytek/owt-stack/commit/87c3ed1a9839b0980c13818efe10b34b6462c090))


### Bug Fixes

* **ci:** pull the service images through mirror.gcr.io ([#29](https://github.com/onewaytek/owt-stack/issues/29)) ([3fad97a](https://github.com/onewaytek/owt-stack/commit/3fad97a6a1dd740d11bb0a226e40b7b68e43694f))

## [0.4.1](https://github.com/onewaytek/owt-stack/compare/v0.4.0...v0.4.1) (2026-10-08)


### Features

* **web:** `Fragment::replace` rewrites the history entry instead of pushing ([#23](https://github.com/onewaytek/owt-stack/issues/23)) ([acf18bc](https://github.com/onewaytek/owt-stack/commit/acf18bcfdfcf23bb283f381db460631d5bd1012f))


### Bug Fixes

* **accounts:** the sign-in wall keeps a nest prefix in `?next=` ([#22](https://github.com/onewaytek/owt-stack/issues/22)) ([2b4db77](https://github.com/onewaytek/owt-stack/commit/2b4db77b4b6fb266482db84f75fa7902eab0b860))

## [0.4.0](https://github.com/onewaytek/owt-stack/compare/v0.3.0...v0.4.0) (2026-10-07)


### ⚠ BREAKING CHANGES

* **web:** `Fragment::page` takes `&RequestInfo` instead of `&str`. In a fragment handler, take `request: RequestInfo`, re-path it with `let request = request.for_page("/the/page")`, render from it, and pass `.page(&request)`. `RequestInfo::query_with` always returns `?...` again; a link that should drop to the bare path when the query empties uses `url_with` instead. `Pagination` hrefs are now root-relative (`/items?page=2`), which any test asserting `?page=2` must follow.

### Features

* **accounts:** the accounts table, credentials, epoch sessions, extractors, identities and links ([#19](https://github.com/onewaytek/owt-stack/issues/19)) ([588dd64](https://github.com/onewaytek/owt-stack/commit/588dd6434ade48a94514fe4bf23966cfc46c9271))
* public repository: no token to fetch, MIT or Apache-2.0 ([#16](https://github.com/onewaytek/owt-stack/issues/16)) ([0cb522d](https://github.com/onewaytek/owt-stack/commit/0cb522d772c97704449bfa8fa557e031bfff0a77))
* **templates:** nightly database backups with pruning; a monitoring template ([#11](https://github.com/onewaytek/owt-stack/issues/11)) ([615f3cf](https://github.com/onewaytek/owt-stack/commit/615f3cf00144066b12ba08ff65c5aa251a05a8b8))
* **web:** shared page components over semantic tokens ([#20](https://github.com/onewaytek/owt-stack/issues/20)) ([f8c79cd](https://github.com/onewaytek/owt-stack/commit/f8c79cd810a471d579ed65c8021e6b0a79ba9b7e))


### Bug Fixes

* **ci:** reach the test services by name off ARC ([#18](https://github.com/onewaytek/owt-stack/issues/18)) ([9373eff](https://github.com/onewaytek/owt-stack/commit/9373eff649540e756bbdf35bf4014c213304c96a))

## [0.3.0](https://github.com/onewaytek/owt-stack/compare/v0.2.0...v0.3.0) (2026-10-07)


### ⚠ BREAKING CHANGES

* **auth:** `owt_auth::password::verify` no longer accepts Django `pbkdf2_sha256` hashes, so an account whose stored hash is one cannot sign in. Such a hash cannot be turned into Argon2 without the plaintext password. An app that still stores some can stay on 0.2.x until each of those accounts has signed in once (0.2's `needs_rehash` flags the hash, and the app stores a fresh `hash`), check the Django hash in its own code before calling `verify`, or reset those accounts' passwords.

### Features

* **ci:** reusable release, image and rc workflows for apps; justfile and compose templates ([eea801e](https://github.com/onewaytek/owt-stack/commit/eea801e9a24a88f314129f724cfdad7d1ec471d5))
* **ci:** reusable release, image and rc workflows for apps; justfile and compose templates ([df7835e](https://github.com/onewaytek/owt-stack/commit/df7835eff6e535d189039f5c1447a0fc056a07e4))
* **runtime:** a redis read-through cache that never fails a request ([509af43](https://github.com/onewaytek/owt-stack/commit/509af43eec66de0800c4f95204ae2cf790408a03))
* **runtime:** background jobs on every replica, one at a time, or on a lease ([b5fb5af](https://github.com/onewaytek/owt-stack/commit/b5fb5afa09d0e8e47da0b36225b7992c0dc8ef99))
* **runtime:** background jobs on every replica, one at a time, or on a lease ([9573b2b](https://github.com/onewaytek/owt-stack/commit/9573b2b8e467d9d4e0e926df8a1c3363eb2fa684))
* **test:** the browser fetches nothing from another origin; vendored files match their pins ([79ae8b9](https://github.com/onewaytek/owt-stack/commit/79ae8b92922e5649e8a7a5da54787ad2d39ccb2c))
* **test:** the browser fetches nothing from another origin; vendored files match their pins ([86707c9](https://github.com/onewaytek/owt-stack/commit/86707c9061bffe6f803031c0ac137ed22ad2f3ad))
* typed cache policies and a fail-open redis read-through cache ([ead60e9](https://github.com/onewaytek/owt-stack/commit/ead60e90bf9d0e7dcbcaad8665c7d5fdf71a0d13))
* **web:** cache-control as a typed policy ([013fe28](https://github.com/onewaytek/owt-stack/commit/013fe28bdfb0e5ec653632b5ee340cd40483ff1d))


### Bug Fixes

* non-text Origin and X-Forwarded-For fail closed; a job whose closure panics keeps ticking ([115983b](https://github.com/onewaytek/owt-stack/commit/115983b0a9ed0971b0c7f47758e917e559359a27))
* non-text Origin and X-Forwarded-For fail closed; a job whose closure panics keeps ticking ([6522507](https://github.com/onewaytek/owt-stack/commit/65225077f4648d7140a33d2f64cf606b2ef7796f))
* **runtime:** bound every cache round trip, outages included ([71c17e8](https://github.com/onewaytek/owt-stack/commit/71c17e8613350eb0e486df4f0867335b286daaad))
* **test:** asset checks fail on nothing to check and catch wrapped tags ([ba5426e](https://github.com/onewaytek/owt-stack/commit/ba5426e2c0a9e137a4f95034354b2b708722662f))
* **web:** empty trust or bypass entries no longer weaken the origin check ([56c75b1](https://github.com/onewaytek/owt-stack/commit/56c75b10ce403baed5bba8f3e7892b83618a9e15))


### Code Refactoring

* **auth:** drop Django password hashes and compatibility shims ([934afdf](https://github.com/onewaytek/owt-stack/commit/934afdfd957b210fc757a0cd9481aa13994397ff))
