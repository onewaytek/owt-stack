# Changelog

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
