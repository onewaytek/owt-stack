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

/// A link just minted. The token is shown once and never stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Minted {
    /// What goes in the URL: 43 characters of base64url.
    pub token: String,
}

fn digest(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

/// Mint a link for `account_id`, good for `ttl`, with `reason` for the audit trail.
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
    .bind(i64::try_from(ttl.as_secs()).unwrap_or(i64::MAX))
    .bind(reason)
    .execute(db)
    .await?;
    Ok(Minted { token })
}

/// Redeem `token` from `from` (the client's address, for the trail): the account it
/// signs in. [`Refused::Link`] when the token is unknown, used, expired, or its
/// account is deactivated. The handler then calls [`crate::session::sign_in`].
pub async fn redeem(pool: &sqlx::PgPool, token: &str, from: &str) -> Result<Account> {
    let account_id = sqlx::query_scalar::<_, i64>(
        "UPDATE sign_in_links SET used_at = now(), used_from = $2
         WHERE token_sha256 = $1 AND used_at IS NULL AND expires_at > now()
         RETURNING account_id",
    )
    .bind(digest(token))
    .bind(from)
    .fetch_optional(pool)
    .await?;
    let Some(account_id) = account_id else {
        return Err(Refused::Link.into());
    };
    store::by_id(pool, account_id)
        .await?
        .ok_or_else(|| Refused::Link.into())
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
