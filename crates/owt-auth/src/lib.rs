//! Authentication apps on owt-stack share.
//!
//! * [`password`]: Argon2id hashing off the async runtime, a bounded number at once.
//! * [`password::Policy`]: what a new password must satisfy (NIST SP 800-63B), with an
//!   offline breached-password check.
//! * [`totp`] and [`recovery`]: the second factor, a six-digit authenticator code and
//!   the single-use codes for a lost authenticator.
//! * [`throttle`]: budgets for sign-in attempts, by address and by account; with the
//!   `redis` feature, counted in Redis so they hold across replicas.
//! * [`bots`]: a guard for anonymous forms: a honeypot, Turnstile, and a budget per
//!   address, answering bots as if they were people.
//! * [`oauth`]: the authorization-code flow (with PKCE where the provider supports
//!   it) for signing people in with Google, Discord, Twitch or any OIDC provider.
//! * [`jwt`]: bearer tokens an identity provider issued, verified locally against
//!   its published keys: signature, issuer, audience, expiry. Behind the `jwt`
//!   feature (default), which brings `jsonwebtoken` and `rsa`.
//!
//! What a session remembers and how an account is stored stay with the app.

pub mod bots;
#[cfg(feature = "jwt")]
pub mod jwt;
pub mod oauth;
pub mod password;
pub mod recovery;
pub mod throttle;
pub mod totp;

/// `len` URL-safe random characters (RFC 3986 unreserved): states and verifiers.
pub(crate) fn random_token(len: usize) -> String {
    use rand::RngExt;
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    let mut rng = rand::rng();
    (0..len)
        .map(|_| A[rng.random_range(0..A.len())] as char)
        .collect()
}
