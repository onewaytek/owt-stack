//! One-time sign-in links: the way in when the providers are down, a password is
//! lost, or an account was just made for someone. An operator mints one (a CLI
//! command, a staff page); the person opens it once, within its lifetime.
//!
//! The token travels in the URL and is stored only as its SHA-256, so the table
//! yields no usable link. Redeeming is one `UPDATE … WHERE used_at IS NULL`, so two
//! requests racing on one link admit one.

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
pub const MAX_TTL: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// Mint a link for `account_id`, good for `ttl` (at most [`MAX_TTL`]), with `reason`
/// for the audit trail.
pub async fn mint(
    db: impl PgExecutor<'_>,
    account_id: i64,
    ttl: Duration,
    reason: &str,
) -> sqlx::Result<Minted> {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    sqlx::query(
        "INSERT INTO sign_in_links (token_sha256, account_id, expires_at, reason)
         VALUES ($1, $2, now() + $3 * interval '1 second', $4)",
    )
    .bind(digest(&token))
    .bind(account_id)
    // A century of seconds fits an i64 many times over; the cast is lossless.
    .bind(ttl.min(MAX_TTL).as_secs().cast_signed())
    .bind(reason)
    .execute(db)
    .await?;
    Ok(Minted { token })
}

/// Redeem `token` from `from` (the client's address, for the trail): the account it
/// signs in. [`Refused::Link`] when the token is unknown, used, expired, or its
/// account is deactivated. The account's `last_sign_in` is stamped
/// ([`store::signed_in`]); the handler then calls [`crate::session::sign_in`].
pub async fn redeem(pool: &sqlx::PgPool, token: &str, from: &str) -> Result<Account> {
    // One transaction, the account read under a share lock: a revocation (which
    // voids this link and bumps the epoch in one statement) is either before it,
    // and the link is spent, or after it, and the session this signs in is revoked.
    // The account is locked before the link, the order a revocation takes them in,
    // so the two cannot deadlock.
    let mut tx = pool.begin().await?;
    let digest = digest(token);
    let Some(account_id) = sqlx::query_scalar::<_, i64>(
        "SELECT account_id FROM sign_in_links WHERE token_sha256 = $1",
    )
    .bind(&digest)
    .fetch_optional(&mut *tx)
    .await?
    else {
        return Err(Refused::Link.into());
    };
    let account = sqlx::query_as::<_, Account>(sqlx::AssertSqlSafe(format!(
        "SELECT {} FROM accounts WHERE id = $1 AND is_active FOR SHARE",
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
    // After the commit: inside, it would upgrade the share lock on the account, and
    // two links of one account redeemed at once would deadlock.
    store::signed_in(pool, account.id).await?;
    Ok(account)
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
