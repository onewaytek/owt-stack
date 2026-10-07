//! Accounts and sign-in, for every app on the stack.
//!
//! [`owt_auth`] has the pieces (Argon2 hashing, the sign-in throttle, OAuth, JWT) and
//! [`owt_web::session`] the sealed cookie. Each app then wrote the same flows over
//! them: an `accounts` table with a session epoch, `authenticate` with the decoy
//! check and rehash, a sign-in extractor that walls a handler, sign-out everywhere.
//! This crate is that code, once.
//!
//! - [`migrations`]: the tables, as a file the app copies into its migrations.
//! - [`store`]: the account rows: create, authenticate, look up, change.
//! - [`password`]: the rules a new password meets.
//! - [`session`]: what the cookie carries, signing in and out, the validator.
//! - [`layer`]: the middleware that loads the signed-in account once per request,
//!   and the extractors ([`Signed`], [`Staff`], [`Maybe`]) a handler names.
//! - [`identities`]: provider identities (OAuth) linked to accounts.
//! - [`links`]: one-time sign-in links.
//!
//! What stays in the app: its pages (the sign-in form is an app's template, with
//! its look), its extra columns (`ALTER TABLE accounts ADD COLUMN …` in a
//! migration of its own) and anything that reads them, and the decision which
//! flows exist (self-signup or not, which providers, whether links are minted).

#![forbid(unsafe_code)]

pub mod identities;
pub mod layer;
pub mod links;
pub mod migrations;
pub mod password;
pub mod session;
pub mod store;

pub use layer::{Accounts, Maybe, Signed, Staff};
pub use store::{Account, New, normalize};

/// Why an account operation did not happen. Each message is written for the person
/// who filled the form.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Refused {
    /// The username is empty, too long, or has an `@`, whitespace or control
    /// characters.
    #[error("Enter a username: up to 150 characters, with no spaces and no “@”.")]
    Username,
    /// The email is not one address.
    #[error("Enter a valid email address.")]
    Email,
    /// Another account has that username.
    #[error("There is already an account named “{0}”.")]
    UsernameTaken(String),
    /// Another account has that email.
    #[error("An account already uses the email address “{0}”.")]
    EmailTaken(String),
    /// The password breaks a rule; every rule it breaks is listed.
    #[error("{}", password::describe(.0))]
    Password(Vec<password::Problem>),
    /// A provider identity is linked to another account.
    #[error("That account is already connected to a different user.")]
    IdentityTaken,
    /// Unlinking would leave the account with no way to sign in.
    #[error("Your account has no password, so its only connection cannot be removed.")]
    LastWayIn,
    /// A sign-in link that is unknown, used or expired.
    #[error("That sign-in link is not valid any more.")]
    Link,
}

/// What an account operation returns when it fails: a refusal the person can act
/// on, or a fault they cannot.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// See [`Refused`]. A handler shows the message and keeps the form.
    #[error(transparent)]
    Refused(#[from] Refused),
    /// The database.
    #[error(transparent)]
    Db(#[from] sqlx::Error),
    /// Hashing a password failed (it does not, short of exhaustion).
    #[error(transparent)]
    Hash(anyhow::Error),
}

impl From<Error> for owt_web::Error {
    /// A refusal is a 422 with its message; the faults keep their own mapping.
    fn from(e: Error) -> Self {
        match e {
            Error::Refused(r) => Self::Unprocessable(r.to_string().into()),
            Error::Db(e) => Self::Db(e),
            Error::Hash(e) => Self::Internal(e),
        }
    }
}

/// `Result` with this crate's [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;

impl Error {
    /// The refusal, if that is what this is.
    #[must_use]
    pub fn refused(&self) -> Option<&Refused> {
        match self {
            Self::Refused(r) => Some(r),
            _ => None,
        }
    }
}
