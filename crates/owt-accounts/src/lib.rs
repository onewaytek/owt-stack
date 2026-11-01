//! Accounts and sign-in, for every app on the stack.
//!
//! [`owt_auth`] has the pieces (Argon2 hashing, the sign-in throttle, OAuth, JWT) and
//! [`owt_web::session`] the sealed cookie. Every app needs the same flows over
//! them: an `accounts` table with a session epoch, `authenticate` with the decoy
//! check and rehash, a sign-in extractor that walls a handler, sign-out everywhere.
//! This crate holds those flows once.
//!
//! - [`migrations`]: the tables, which the library migrates into a ledger of its own.
//! - [`store`]: the account rows: create, authenticate, look up, change.
//! - [`password`]: the rules a new password meets.
//! - [`session`]: what the cookie carries, signing in and out, the validator.
//! - [`layer`]: the middleware that loads the signed-in account once per request,
//!   and the extractors ([`Signed`], [`Staff`], [`Maybe`]) a handler names.
//! - [`page`]: the context a full page is drawn with ([`PageCtx`]): viewer, request,
//!   messages shown once, nonce.
//! - [`identities`]: provider identities (OAuth) linked to accounts, and the app's
//!   own local ones.
//! - [`links`]: one-time sign-in links.
//! - [`mfa`]: a second factor (an authenticator app, recovery codes), the challenge
//!   after the password, a policy that requires it, and step-up re-authentication;
//!   [`mfa::pages`] mounts the pages for them.
//! - [`roles`]: user, staff, and the roles an app declares; the [`roles::Holds`]
//!   extractor.
//! - [`admin`]: the staff pages that find and change accounts.
//! - [`social`]: sign-in with a provider: the routes, their configuration, the
//!   buttons and the connections list.
//! - `cli` (feature `cli`): the operator's account commands as a clap subcommand.
//! - [`policies`]: the site's policies (terms, privacy notice) with versions, the
//!   gate that asks each account to agree to the current ones, and their pages.
//!
//! What stays in the app: its pages (the sign-in form is an app's template, with
//! its look), its extra columns (`ALTER TABLE accounts ADD COLUMN …` in a
//! migration of its own) and anything that reads them, and the decision which
//! flows exist (self-signup or not, which providers, whether links are minted).

#![forbid(unsafe_code)]

pub mod admin;
#[cfg(feature = "cli")]
pub mod cli;
pub mod identities;
pub mod layer;
pub mod links;
pub mod mfa;
pub mod migrations;
pub mod page;
pub mod password;
pub mod policies;
pub mod roles;
pub mod session;
pub mod social;
pub mod store;

pub use layer::{Accounts, Maybe, MaybeWith, Signed, SignedWith, Staff};
pub use page::PageCtx;
pub use store::{Account, New, normalize};

/// Why an account operation did not happen. Each message is written for the person
/// who filled the form. A refusal may be added without a breaking release, so a `match` on
/// it ends with a `_` arm (its `Display` is the sentence to show for any of them).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Refused {
    /// The username is empty, too long, or has an `@`, whitespace or control
    /// characters.
    #[error(
        "Enter a username: up to 150 letters and digits of one alphabet (plus - . _), starting with a letter or digit, with no spaces and no “@”."
    )]
    Username,
    /// The email is not one address.
    #[error("Enter a valid email address.")]
    Email,
    /// Another account has that username.
    #[error("There is already an account named “{0}”.")]
    UsernameTaken(String),
    /// The username is too like another account's to tell apart (see
    /// [`store::skeleton`]).
    #[error("“{0}” is too like an existing account's name to tell apart. Choose another.")]
    UsernameLookalike(String),
    /// Another account has that email.
    #[error("An account already uses the email address “{0}”.")]
    EmailTaken(String),
    /// The password breaks a rule; every rule it breaks is listed.
    #[error("{}", password::describe(.0))]
    Password(Vec<password::Problem>),
    /// A provider identity is linked to another account.
    #[error("That account is already connected to a different user.")]
    IdentityTaken,
    /// A provider identity with an empty subject: nobody in particular.
    #[error("That sign-in did not say who you are. Try again.")]
    NoSubject,
    /// The current password, asked for before a change, is not the account's.
    #[error("That is not your current password.")]
    CurrentPassword,
    /// The account does not sign in with a password (see
    /// [`store::set_password_sign_in`]), so none can be set on it.
    #[error("This account does not sign in with a password.")]
    NoPasswordSignIn,
    /// Unlinking would leave the account with no way to sign in. Read by the
    /// account's owner and by staff alike, so it names "the account", not "yours";
    /// the social routes and the admin each show words of their own for it.
    #[error(
        "This is the only way into the account, so it cannot be removed. Set a password or add another way in first."
    )]
    LastWayIn,
    /// A sign-in link that is unknown, used or expired.
    #[error("That sign-in link is not valid any more.")]
    Link,
    /// A sign-in link's landing page that is not a path on the site (see
    /// [`links::valid_next`]).
    #[error("Enter a page on this site, starting with a single “/”.")]
    Next,
}

/// What an account operation returns when it fails: a refusal the person can act
/// on, or a fault they cannot. A fault may be added without a breaking release, so a `match`
/// on it ends with a `_` arm.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
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
    /// Every permit of the password hasher stayed taken for its timeout
    /// ([`owt_auth::password::Busy`]): nothing was checked or hashed. A 503.
    #[error(transparent)]
    Busy(#[from] owt_auth::password::Busy),
}

impl Error {
    /// A failure of [`owt_auth::password::hash`]: [`Error::Busy`] when it found no
    /// permit, [`Error::Hash`] otherwise.
    pub(crate) fn hash(e: anyhow::Error) -> Self {
        match e.downcast::<owt_auth::password::Busy>() {
            Ok(busy) => Self::Busy(busy),
            Err(e) => Self::Hash(e),
        }
    }
}

impl From<Error> for owt_web::Error {
    /// A refusal is a 422 with its message, a busy hasher a 503 with `Retry-After`;
    /// the faults keep their own mapping.
    fn from(e: Error) -> Self {
        match e {
            Error::Refused(r) => Self::Unprocessable(r.to_string().into()),
            Error::Db(e) => Self::Db(e),
            Error::Hash(e) => Self::Internal(e),
            Error::Busy(b) => Self::unavailable(b.to_string()),
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
