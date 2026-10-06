//! Authentication the onewaytek apps share.
//!
//! * [`password`]: Argon2id hashing off the async runtime; Django's
//!   `pbkdf2_sha256` hashes are accepted so accounts migrate on their next sign-in.
//! * [`throttle`]: budgets for sign-in attempts, by address and by account.
//! * [`oauth`]: the authorization-code flow (with PKCE where the provider supports
//!   it) for signing people in with Google, Discord, Twitch or any OIDC provider.
//! * [`jwt`]: bearer tokens an identity provider issued, verified locally against
//!   its published keys: signature, issuer, audience, expiry.
//!
//! What a session remembers and how an account is stored stay with the app.

pub mod jwt;
pub mod oauth;
pub mod password;
pub mod throttle;

/// `len` URL-safe random characters (RFC 3986 unreserved): states and verifiers.
pub(crate) fn random_token(len: usize) -> String {
    use rand::RngExt;
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    let mut rng = rand::rng();
    (0..len)
        .map(|_| A[rng.random_range(0..A.len())] as char)
        .collect()
}
