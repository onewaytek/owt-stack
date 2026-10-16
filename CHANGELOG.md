# Changelog

## [0.5.0](https://github.com/onewaytek/owt-stack/compare/v0.4.4...v0.5.0) (2026-10-16)


### ⚠ BREAKING CHANGES

* **accounts:** apps install ALL[2] (0003) as their next unused migration version and await owt_accounts::migrations::complete before serving; it returns Completed (renames, cleared emails and passwords, failures) instead of a count. Usernames that collide once normalized are renamed. store::create takes &PgPool; store::create_in takes a connection. links::MAX_TTL is 30 days. Refused has CurrentPassword and UsernameLookalike variants.
* **web:** CrossOrigin::trust panics on an entry that is not an http(s) origin. A 5xx response no longer carries session changes, except a sign-out. key_from_base64 and key_for refuse a secret with fewer than 8 distinct byte values. Moving from key_from_base64 to key_for signs everyone out unless the old key is kept with also_open_with for a while.
* Bus::redis errors on a prefix outside [A-Za-z0-9_.-] or a zero beat_every. CHANGE_REQUESTS_URL must be https except to localhost or a cluster service named absolutely (….svc.cluster.local., with the final dot). Cache keys move to <prefix>:c: (the cache starts cold once). ServeOptions is non_exhaustive (start from default()). The server does not answer h2c.
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
