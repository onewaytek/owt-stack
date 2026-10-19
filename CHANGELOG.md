# Changelog

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
