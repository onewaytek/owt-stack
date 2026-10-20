//! Account fixtures, and the session key that signs a [`Client`](crate::Client) in
//! without a password check.
//!
//! Everything here is for tests: [`test_key`] is a public constant of a key, and
//! [`Client::sign_in_as`](crate::Client::sign_in_as) seals a session for any account.
//! `owt-test` is a `[dev-dependencies]` entry of the app, so none of it is compiled
//! into the production binary.

use cookie::Key;
use owt_accounts::{Account, New, policies, store};
use sqlx::PgPool;

/// A fixed session key. Sessions built with it open one another's cookies, and the key
/// is public: never use it for a deployment.
#[must_use]
pub fn test_key() -> Key {
    let bytes: [u8; 64] = std::array::from_fn(|i| u8::try_from(i).expect("below 64"));
    Key::from(&bytes)
}

/// An account named `username` with no password and no email, as `store::create` makes
/// it. Nothing is hashed, so it costs no Argon2 round.
pub async fn create(pool: &PgPool, username: &str) -> Account {
    make(pool, username, None, false).await
}

/// [`create`] for a staff account.
pub async fn create_staff(pool: &PgPool, username: &str) -> Account {
    make(pool, username, None, true).await
}

/// [`create`] with a password, which is hashed as in production (one Argon2 round),
/// for a test of the sign-in form itself. A test that only needs a signed-in client
/// uses [`create`] and [`Client::sign_in_as`](crate::Client::sign_in_as).
pub async fn create_with_password(pool: &PgPool, username: &str, password: &str) -> Account {
    make(pool, username, Some(password), false).await
}

async fn make(pool: &PgPool, username: &str, password: Option<&str>, is_staff: bool) -> Account {
    let made = store::create(
        pool,
        New {
            username,
            email: "",
            password,
            is_staff,
        },
    )
    .await
    .expect("the account is created");
    // Re-read, so the row carries every column as the layer loads it.
    store::by_id(pool, made.id)
        .await
        .expect("the account is read")
        .expect("the account exists")
}

/// Record that `account` agreed to the current version of every published document, so
/// the policy gate lets it through.
pub async fn agree_to_current(pool: &PgPool, account: &Account) {
    policies::agree_to_current(pool, account.id)
        .await
        .expect("the agreement is recorded");
}
