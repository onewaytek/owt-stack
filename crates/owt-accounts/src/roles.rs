//! Who may do what: every account is a user, some are staff, and an app declares
//! any further roles it needs.
//!
//! | Tier | Held by | Extractor |
//! |---|---|---|
//! | user | every active, signed-in account | [`Signed`](crate::Signed) |
//! | staff | `accounts.is_staff` ([`store::set_staff`](crate::store::set_staff)) | [`Staff`](crate::Staff) |
//! | an app's [`Role`] | a row of `account_roles` ([`grant`]), or staff too when [`held_by_staff`](Role::held_by_staff) | [`Holds<R>`] |
//!
//! A role is a constant the app declares once, in code; the database holds only who
//! has it. The admin pages ([`crate::admin`]) list the app's roles as checkboxes.
//!
//! ```
//! use owt_accounts::roles::{Named, Role};
//!
//! /// May run a live session for players.
//! pub struct Host;
//! impl Named for Host {
//!     const ROLE: Role = Role::new("host", "Host", "May run a live session.").held_by_staff();
//! }
//! ```
//!
//! A role is read with the account on every request, so revoking one takes effect at
//! the holder's next request without signing them out (staff, the tier that can
//! change everyone else, still signs out on revocation).

use std::marker::PhantomData;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use owt_web::Error;
use sqlx::PgExecutor;

use crate::store::{Account, COLUMNS};
use crate::{Maybe, Signed};

/// A role an app defines. Declare it as a constant: [`Role::new`] checks the name at
/// compile time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Role {
    /// What the database stores: lower-case ASCII letters, digits and `_`, a letter
    /// first, at most 63 bytes, and neither `user` nor `staff` (the built-in tiers).
    pub name: &'static str,
    /// What the admin pages call it: `Host`.
    pub label: &'static str,
    /// A sentence on what it allows, for the admin pages.
    pub description: &'static str,
    /// Staff hold it without a grant.
    pub staff: bool,
}

impl Role {
    /// The role `name`, shown as `label`, explained by `description`.
    ///
    /// # Panics
    ///
    /// At compile time, in a constant, when `name` is not a valid role name (see
    /// [`Role::name`]).
    #[must_use]
    pub const fn new(name: &'static str, label: &'static str, description: &'static str) -> Self {
        assert!(
            valid_name(name),
            "a role name is lower-case ASCII letters, digits and `_`, a letter first, at most 63 bytes, and not `user` or `staff`"
        );
        Self {
            name,
            label,
            description,
            staff: false,
        }
    }

    /// Staff hold this role without being granted it, as when staff may do anything a
    /// host may.
    #[must_use]
    pub const fn held_by_staff(mut self) -> Self {
        self.staff = true;
        self
    }
}

const fn same(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// The rule the migration's `CHECK` also enforces, plus the reserved names.
const fn valid_name(name: &str) -> bool {
    let b = name.as_bytes();
    if b.is_empty() || b.len() > 63 || !b[0].is_ascii_lowercase() {
        return false;
    }
    if same(b, b"user") || same(b, b"staff") {
        return false;
    }
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_') {
            return false;
        }
        i += 1;
    }
    true
}

/// A type that names a role, so a handler can require it: [`Holds<Host>`](Holds).
pub trait Named: Send + Sync + 'static {
    /// The role.
    const ROLE: Role;
}

/// A signed-in account holding `R`'s role. Anyone else signed in gets a 403; an
/// anonymous visitor goes to the sign-in page, as with [`Signed`].
///
/// ```
/// # use owt_accounts::roles::{Holds, Named, Role};
/// # pub struct Host;
/// # impl Named for Host { const ROLE: Role = Role::new("host", "Host", "Runs sessions."); }
/// async fn start_session(Holds(me, _): Holds<Host>) -> String {
///     format!("{} is hosting", me.username)
/// }
/// ```
#[derive(Debug)]
pub struct Holds<R: Named>(pub Account, pub PhantomData<fn() -> R>);

impl<R: Named> Clone for Holds<R> {
    fn clone(&self) -> Self {
        Self(self.0.clone(), PhantomData)
    }
}

impl<R: Named, S: Send + Sync> FromRequestParts<S> for Holds<R> {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Signed(account) = Signed::from_request_parts(parts, state).await?;
        if account.holds(&R::ROLE) {
            Ok(Self(account, PhantomData))
        } else {
            Err(Error::Forbidden(
                format!("This page needs the {} role.", R::ROLE.label).into(),
            ))
        }
    }
}

/// Whether the request's signed-in account holds `role`; `false` when anonymous.
/// For page chrome that shows a link only to holders.
#[must_use]
pub fn signed_in_holds(extensions: &axum::http::Extensions, role: &Role) -> bool {
    Maybe::of(extensions).0.is_some_and(|a| a.holds(role))
}

/// Grant `role` to `account_id`, recording who granted it (`by`, when a person did).
/// `true` when it was granted now, `false` when it was held already.
pub async fn grant(
    db: impl PgExecutor<'_>,
    account_id: i64,
    role: &Role,
    by: Option<i64>,
) -> sqlx::Result<bool> {
    let done = sqlx::query(
        "INSERT INTO account_roles (account_id, role, granted_by) VALUES ($1, $2, $3)
         ON CONFLICT DO NOTHING",
    )
    .bind(account_id)
    .bind(role.name)
    .bind(by)
    .execute(db)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// Revoke `role` from `account_id`. `true` when it was held. Staff keep a role
/// [`held_by_staff`](Role::held_by_staff) whatever is revoked.
pub async fn revoke(db: impl PgExecutor<'_>, account_id: i64, role: &Role) -> sqlx::Result<bool> {
    let done = sqlx::query("DELETE FROM account_roles WHERE account_id = $1 AND role = $2")
        .bind(account_id)
        .bind(role.name)
        .execute(db)
        .await?;
    Ok(done.rows_affected() == 1)
}

/// The active accounts holding `role` (staff included when it is
/// [`held_by_staff`](Role::held_by_staff)), by username: a host picker, say.
pub async fn holders(db: impl PgExecutor<'_>, role: &Role) -> sqlx::Result<Vec<Account>> {
    sqlx::query_as::<_, Account>(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM accounts
         WHERE is_active AND (($2 AND is_staff)
            OR EXISTS (SELECT 1 FROM account_roles r WHERE r.account_id = accounts.id AND r.role = $1))
         ORDER BY username"
    )))
    .bind(role.name)
    .bind(role.staff)
    .fetch_all(db)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_names_are_what_the_column_accepts() {
        for ok in ["host", "a", "can_host", "tier2", &"a".repeat(63)] {
            assert!(valid_name(ok), "{ok}");
        }
        for bad in [
            "",
            "Host",
            "2fa",
            "_x",
            "has-dash",
            "has space",
            "user",
            "staff",
            "é",
            &"a".repeat(64),
        ] {
            assert!(!valid_name(bad), "{bad}");
        }
    }

    #[test]
    fn staff_hold_only_the_roles_that_say_so() {
        const HOST: Role = Role::new("host", "Host", "Runs sessions.").held_by_staff();
        const EDITOR: Role = Role::new("editor", "Editor", "Edits content.");
        let mut a = Account {
            id: 1,
            username: "ada".into(),
            email: String::new(),
            is_staff: true,
            is_active: true,
            session_epoch: 0,
            roles: Vec::new(),
        };
        assert!(a.holds(&HOST));
        assert!(!a.holds(&EDITOR));
        a.is_staff = false;
        assert!(!a.holds(&HOST));
        a.roles = vec!["editor".into()];
        assert!(a.holds(&EDITOR) && !a.holds(&HOST));
    }
}
