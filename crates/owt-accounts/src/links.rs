//! One-time sign-in links: the way in when the providers are down, a password is
//! lost, or an account was just made for someone. An operator mints one (a CLI
//! command, a staff page); the person opens it once, within its lifetime.
//!
//! The token travels in the URL and is stored only as its SHA-256, so the table
//! yields no usable link. Redeeming is one `UPDATE … WHERE used_at IS NULL`, so two
//! requests racing on one link admit one.
//!
//! A link may name where to land after signing in (`next`, a path on the app's own
//! site): [`mint_with`] stores it and [`redeem_with`] returns it, for the handler to
//! redirect to.

use std::time::Duration;

use base64::Engine;
use sha2::{Digest, Sha256};
use sqlx::PgExecutor;

use crate::store::{self, Account};
use crate::{Refused, Result};

/// A link just minted. The token is shown once and never stored, and its `Debug`
/// leaves it out, so a `?minted` in a log line does not publish a way in.
#[derive(Clone, PartialEq, Eq)]
pub struct Minted {
    /// What goes in the URL: 43 characters of base64url.
    pub token: String,
}

impl std::fmt::Debug for Minted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Minted").finish_non_exhaustive()
    }
}

fn digest(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

/// The longest a link lives: 30 days. A link is a bearer credential that may sit in
/// a mailbox, a chat log or a proxy's access log (it travels in the URL), so a
/// longer `ttl` is capped here.
pub const MAX_TTL: Duration = Duration::from_hours(30 * 24);

/// The longest `next`, in bytes.
pub const MAX_NEXT: usize = 2048;

/// Whether `next` is a path on the app's own site, safe to redirect to: it starts
/// with a single `/` (not `//host`, which a browser reads as another site, nor
/// `/\host`, which it reads the same), and holds no backslash, whitespace or control
/// character (a browser drops a tab or newline from a URL, so `/<tab>/host` is
/// `//host`). A scheme (`https:`, `javascript:`) cannot start with `/`. At most
/// [`MAX_NEXT`] bytes.
#[must_use]
pub fn valid_next(next: &str) -> bool {
    next.len() <= MAX_NEXT
        && next.starts_with('/')
        && !next.starts_with("//")
        && !next
            .chars()
            .any(|c| c == '\\' || c.is_whitespace() || c.is_control())
}

/// Mint a link for `account_id`, good for `ttl` (at most [`MAX_TTL`]), with `reason`
/// for the audit trail.
pub async fn mint(
    db: impl PgExecutor<'_>,
    account_id: i64,
    ttl: Duration,
    reason: &str,
) -> sqlx::Result<Minted> {
    insert(db, account_id, ttl, reason, None).await
}

/// [`mint`] with a page to land on after signing in: `next`, a path on the app's own
/// site ([`valid_next`]), returned by [`redeem_with`].
///
/// # Errors
///
/// [`Refused::Next`] when `next` is not a local path, or the database.
pub async fn mint_with(
    db: impl PgExecutor<'_>,
    account_id: i64,
    ttl: Duration,
    reason: &str,
    next: Option<&str>,
) -> Result<Minted> {
    if next.is_some_and(|n| !valid_next(n)) {
        return Err(Refused::Next.into());
    }
    Ok(insert(db, account_id, ttl, reason, next).await?)
}

async fn insert(
    db: impl PgExecutor<'_>,
    account_id: i64,
    ttl: Duration,
    reason: &str,
    next: Option<&str>,
) -> sqlx::Result<Minted> {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    sqlx::query(
        "INSERT INTO sign_in_links (token_sha256, account_id, expires_at, reason, next)
         VALUES ($1, $2, now() + $3 * interval '1 second', $4, $5)",
    )
    .bind(digest(&token))
    .bind(account_id)
    // At most `MAX_TTL`, so the cast is lossless.
    .bind(ttl.min(MAX_TTL).as_secs().cast_signed())
    .bind(reason)
    .bind(next)
    .execute(db)
    .await?;
    Ok(Minted { token })
}

/// Redeem `token` from `from` (the client's address, for the trail): the account it
/// signs in. [`Refused::Link`] when the token is unknown, used, expired, or its
/// account is deactivated. The account's `last_sign_in` is stamped in the same
/// transaction; the handler then calls [`crate::session::sign_in`].
pub async fn redeem(pool: &sqlx::PgPool, token: &str, from: &str) -> Result<Account> {
    Ok(redeem_with(pool, token, from).await?.account)
}

/// A link just redeemed.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Redeemed {
    /// The account it signs in.
    pub account: Account,
    /// The path the link named to land on ([`mint_with`]), a [`valid_next`] one:
    /// redirect there after [`crate::session::sign_in`]. None when it named none.
    pub next: Option<String>,
}

/// [`redeem`], also returning where the link said to land.
///
/// # Errors
///
/// As [`redeem`].
pub async fn redeem_with(pool: &sqlx::PgPool, token: &str, from: &str) -> Result<Redeemed> {
    // One transaction, the account read under a row lock: a revocation (which
    // voids this link and bumps the epoch in one statement) is either before it,
    // and the link is spent, or after it, and the session this signs in is revoked.
    // The account is locked before the link, the order a revocation takes them in,
    // so the two cannot deadlock.
    let mut tx = pool.begin().await?;
    let digest = digest(token);
    let Some((account_id, next)) = sqlx::query_as::<_, (i64, Option<String>)>(
        "SELECT account_id, next FROM sign_in_links WHERE token_sha256 = $1",
    )
    .bind(&digest)
    .fetch_optional(&mut *tx)
    .await?
    else {
        return Err(Refused::Link.into());
    };
    // Stamped here, under the row lock a revocation also takes: a refusal below
    // rolls the stamp back with the rest.
    let account = sqlx::query_as::<_, Account>(sqlx::AssertSqlSafe(format!(
        "UPDATE accounts SET last_sign_in = now() WHERE id = $1 AND is_active RETURNING {}",
        store::COLUMNS
    )))
    .bind(account_id)
    .fetch_optional(&mut *tx)
    .await?;
    let spent = sqlx::query(
        "UPDATE sign_in_links SET used_at = now(), used_from = $2
         WHERE token_sha256 = $1 AND used_at IS NULL AND expires_at > now()",
    )
    .bind(&digest)
    .bind(from)
    .execute(&mut *tx)
    .await?
    .rows_affected()
        == 1;
    let Some(account) = account.filter(|_| spent) else {
        return Err(Refused::Link.into());
    };
    tx.commit().await?;
    // Checked again on the way out: the column is the database's, not this crate's.
    let next = next.filter(|n| valid_next(n));
    Ok(Redeemed { account, next })
}

/// Void every unused link of an account (its password was reset another way, say).
pub async fn void_all(db: impl PgExecutor<'_>, account_id: i64) -> sqlx::Result<u64> {
    let done = sqlx::query(
        "UPDATE sign_in_links SET used_at = now(), used_from = 'voided'
         WHERE account_id = $1 AND used_at IS NULL",
    )
    .bind(account_id)
    .execute(db)
    .await?;
    Ok(done.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_is_a_path_on_this_site() {
        for ok in [
            "/",
            "/admin/",
            "/a/b?x=1&y=2#top",
            "/caf\u{e9}",
            "/a//b",
            "/%2F%2Fevil",
        ] {
            assert!(valid_next(ok), "{ok:?}");
        }
        for bad in [
            "",
            "admin",
            "//evil.example",
            "///evil.example",
            "/\\evil.example",
            "/a\\b",
            "https://evil.example/",
            "javascript:alert(1)",
            "/ evil",
            "/\t/evil.example",
            "/\n/evil.example",
            "/\r",
            "/\0",
            "/\u{a0}",
        ] {
            assert!(!valid_next(bad), "{bad:?}");
        }
        assert!(valid_next(&format!("/{}", "a".repeat(MAX_NEXT - 1))));
        assert!(!valid_next(&format!("/{}", "a".repeat(MAX_NEXT))));
    }
}
