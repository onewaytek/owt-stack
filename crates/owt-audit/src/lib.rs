//! Append-only, hash-chained audit events.
//!
//! Each [`Event`] records who ([`Event::actor`], [`ActorKind`]) did what
//! ([`Event::action`]) to which resource, for which tenant and data subject, why
//! ([`Event::purpose`]), with what [`Outcome`], and from where (IP address, user
//! agent, request id). [`Audit::record`] appends it to its tenant's chain in
//! `owt_audit_events`:
//!
//! * **Chains.** Every tenant has its own chain (events with no tenant share the
//!   chain `""`). An event's `seq` is one more than the previous event's, its `prev`
//!   is the previous event's hash (32 zero bytes for the first), and its `hash` is
//!   SHA-256 over a canonical encoding of every other field ([`canonical`]). The
//!   database assigns all of these as the row is inserted, whoever inserts it, so a
//!   role that may only insert cannot choose an event's place or fake its links.
//!   Appends to one chain are serialized by a transaction-scoped advisory lock;
//!   chains of different tenants never wait on each other.
//! * **Append-only.** Triggers refuse `UPDATE`, `DELETE` and `TRUNCATE` on the
//!   tables while they stand. The app's role is granted `INSERT` and `SELECT` only
//!   (see the README), so it cannot drop or disable them; the tables' owner could,
//!   which is what anchoring is for. A role that may insert can still record false
//!   events, as it can make false changes: the log shows what was recorded and that
//!   nothing recorded was altered since.
//! * **Verification.** [`verify`] walks a chain, recomputing every hash and link;
//!   any edited, removed or reordered event breaks it at that event.
//! * **Anchoring.** [`anchor::anchor`] writes a manifest of every chain's head to an
//!   [`anchor::Anchor`]: external write-once storage, out of reach of the database's
//!   owner. A chain rewritten from some event on, hashes recomputed, still verifies
//!   on its own, but no longer matches the heads anchored before the rewrite
//!   ([`verify_anchor`]).
//!
//! **No free text, no health data.** An event holds references: account ids, a
//! patient's record id, a resource's id, a code for the action and the purpose. Never
//! a name, a diagnosis, a note or a search term. The columns are short and the codes
//! constrained to `[a-z0-9_.:-]` to keep it so, and the log is kept for years, beyond
//! the reach of erasure.

pub mod anchor;
pub mod canonical;
#[cfg(feature = "cli")]
pub mod cli;
mod migrations;
mod verify;

use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sqlx::{PgConnection, PgPool};

pub use migrations::{LEDGER, LOCK_ID, migrate, migrator};
pub use verify::{Broken, Head, Verified, VerifyError, heads, verify, verify_anchor, verify_since};

/// The hash of an event, or of the nothing before a chain's first event (all zeros).
pub type Hash = [u8; 32];

/// The `prev` of a chain's first event.
pub const GENESIS: Hash = [0; 32];

/// Who acted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ActorKind {
    /// A signed-in account (staff, patient, anyone with an account id).
    Account,
    /// Another system acting with its own credentials (an integration, an API client).
    Service,
    /// The app itself (a scheduled job, a migration).
    System,
    /// Someone not signed in (a failed sign-in, a public form).
    Anonymous,
}

impl ActorKind {
    /// The stored form.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Account => "account",
            Self::Service => "service",
            Self::System => "system",
            Self::Anonymous => "anonymous",
        }
    }
}

/// How it went.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    /// Done.
    Success,
    /// Attempted and failed (an error, a wrong password).
    Failure,
    /// Refused by an access rule.
    Denied,
}

impl Outcome {
    /// The stored form.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Denied => "denied",
        }
    }
}

/// An event to record. Codes (`action`, `resource_type`, `purpose`) are 1 to 100 of
/// `[a-z0-9_.:-]`; the other text fields are references of at most 200 characters
/// (a user agent, 512). [`Audit::record`] refuses anything else.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Event {
    /// The actor's id: an account id, a service's name, `"system"`, or for an
    /// anonymous actor what identifies the attempt (the name tried, hashed if it may
    /// be personal).
    pub actor: String,
    /// What kind of actor.
    pub actor_kind: ActorKind,
    /// The tenant, whose chain the event joins; `None` for the chain `""`.
    pub tenant: Option<String>,
    /// The data subject's reference (a patient's record id), when the event concerns one.
    pub subject: Option<String>,
    /// What was done, as a code: `record.view`, `note.sign`, `session.sign_in`.
    pub action: String,
    /// The kind of resource acted on, as a code: `note`, `appointment`, `account`.
    pub resource_type: String,
    /// The resource's id.
    pub resource_id: Option<String>,
    /// The purpose of use, as a code: `treatment`, `payment`, `operations`,
    /// `emergency`.
    pub purpose: Option<String>,
    /// How it went.
    pub outcome: Outcome,
    /// The client's address.
    pub ip: Option<IpAddr>,
    /// The client's user agent, cut to 512 characters.
    pub user_agent: Option<String>,
    /// The request's id, to join the event to logs and traces.
    pub request_id: Option<String>,
}

impl Event {
    /// `actor` of `kind` did `action` to a `resource_type`, successfully; the rest
    /// unset.
    #[must_use]
    pub fn new(
        kind: ActorKind,
        actor: impl Into<String>,
        action: impl Into<String>,
        resource_type: impl Into<String>,
    ) -> Self {
        Self {
            actor: actor.into(),
            actor_kind: kind,
            tenant: None,
            subject: None,
            action: action.into(),
            resource_type: resource_type.into(),
            resource_id: None,
            purpose: None,
            outcome: Outcome::Success,
            ip: None,
            user_agent: None,
            request_id: None,
        }
    }

    /// The tenant.
    #[must_use]
    pub fn tenant(mut self, tenant: impl Into<String>) -> Self {
        self.tenant = Some(tenant.into());
        self
    }

    /// The data subject's reference.
    #[must_use]
    pub fn subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }

    /// The resource's id.
    #[must_use]
    pub fn resource_id(mut self, id: impl Into<String>) -> Self {
        self.resource_id = Some(id.into());
        self
    }

    /// The purpose of use.
    #[must_use]
    pub fn purpose(mut self, purpose: impl Into<String>) -> Self {
        self.purpose = Some(purpose.into());
        self
    }

    /// The outcome.
    #[must_use]
    pub fn outcome(mut self, outcome: Outcome) -> Self {
        self.outcome = outcome;
        self
    }

    /// The client: its address, user agent and the request's id.
    #[must_use]
    pub fn client(
        mut self,
        ip: Option<IpAddr>,
        user_agent: Option<&str>,
        request_id: Option<&str>,
    ) -> Self {
        self.ip = ip;
        self.user_agent = user_agent.map(|ua| ua.chars().take(MAX_USER_AGENT).collect());
        self.request_id = request_id.map(str::to_owned);
        self
    }

    /// Why it may not be recorded, if it may not.
    pub fn check(&self) -> Result<(), Invalid> {
        let code = |field: &'static str, v: &str| {
            let ok = (1..=100).contains(&v.len())
                && v.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_.:-".contains(&b));
            if ok { Ok(()) } else { Err(Invalid(field)) }
        };
        let reference = |field: &'static str, v: &str, empty_ok: bool| {
            let n = v.chars().count();
            if (n == 0 && !empty_ok) || n > 200 || v.chars().any(char::is_control) {
                Err(Invalid(field))
            } else {
                Ok(())
            }
        };
        reference("actor", &self.actor, false)?;
        if let Some(t) = &self.tenant {
            reference("tenant", t, false)?;
        }
        if let Some(s) = &self.subject {
            reference("subject", s, true)?;
        }
        code("action", &self.action)?;
        code("resource_type", &self.resource_type)?;
        if let Some(r) = &self.resource_id {
            reference("resource_id", r, true)?;
        }
        if let Some(p) = &self.purpose {
            code("purpose", p)?;
        }
        if let Some(ua) = &self.user_agent
            && (ua.chars().count() > MAX_USER_AGENT || ua.chars().any(char::is_control))
        {
            return Err(Invalid("user_agent"));
        }
        if let Some(r) = &self.request_id {
            reference("request_id", r, true)?;
        }
        Ok(())
    }
}

/// The longest user agent an event keeps.
pub const MAX_USER_AGENT: usize = 512;

/// An event that may not be recorded: the field at fault.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("an audit event's `{0}` is not a short reference or code")]
pub struct Invalid(pub &'static str);

/// Why [`Audit::record`] failed.
#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    /// The event was refused before anything was written.
    #[error(transparent)]
    Invalid(#[from] Invalid),
    /// The database.
    #[error("recording an audit event: {0}")]
    Db(#[from] sqlx::Error),
    /// The database hashed the event differently from the crate: the migration's
    /// trigger and this build disagree. The row is inserted in the caller's
    /// transaction: roll it back. ([`Audit::record`] does.)
    #[error("the database's audit hash differs from the crate's")]
    Mismatch,
}

/// An event as recorded: its place in its chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recorded {
    /// The event.
    pub event: Event,
    /// Its position in its tenant's chain, from 1.
    pub seq: i64,
    /// When, to the microsecond, by the database's clock.
    pub at: SystemTime,
    /// The previous event's hash.
    pub prev: Hash,
    /// Its hash.
    pub hash: Hash,
}

impl Recorded {
    /// The hash its fields give: equal to [`Recorded::hash`] for an untouched event.
    #[must_use]
    pub fn computed_hash(&self) -> Hash {
        canonical::hash(self)
    }
}

/// Records events. Cheap to clone.
#[derive(Clone, Debug)]
pub struct Audit {
    pool: PgPool,
}

impl Audit {
    /// Record into the `owt_audit_events` of `pool`'s schema ([`migrate`] first).
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Append `event` to its tenant's chain, in a transaction of its own.
    pub async fn record(&self, event: &Event) -> Result<Recorded, RecordError> {
        let mut tx = self.pool.begin().await?;
        let recorded = record_in(&mut tx, event).await?;
        tx.commit().await?;
        Ok(recorded)
    }

    /// The pool.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

/// Append `event` to its tenant's chain on `conn`. Inside a transaction (`&mut *tx`)
/// the event commits, or not, with the change it records, and the tenant's chain is
/// locked from here until that transaction ends, so record late in it. The
/// transaction must be READ COMMITTED (Postgres's default); the database refuses
/// others.
///
/// The database assigns the event's place, time and hash; this checks that its hash
/// is the one the crate's encoding gives, and fails ([`RecordError::Mismatch`])
/// otherwise.
pub async fn record_in(conn: &mut PgConnection, event: &Event) -> Result<Recorded, RecordError> {
    event.check()?;
    let tenant = event.tenant.as_deref().unwrap_or("");
    let e = event;
    let (seq, at_us, prev, hash): (i64, i64, Vec<u8>, Vec<u8>) = sqlx::query_as(
        "INSERT INTO owt_audit_events
             (tenant, actor, actor_kind, subject, action, resource_type, resource_id,
              purpose, outcome, ip, user_agent, request_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
         RETURNING seq, (extract(epoch FROM at) * 1000000)::int8, prev, hash",
    )
    .bind(tenant)
    .bind(&e.actor)
    .bind(e.actor_kind.as_str())
    .bind(&e.subject)
    .bind(&e.action)
    .bind(&e.resource_type)
    .bind(&e.resource_id)
    .bind(&e.purpose)
    .bind(e.outcome.as_str())
    .bind(e.ip.map(|ip| ip.to_string()))
    .bind(&e.user_agent)
    .bind(&e.request_id)
    .fetch_one(&mut *conn)
    .await?;
    let decode = || sqlx::Error::Decode("an audit hash is 32 bytes".into());
    let recorded = Recorded {
        event: event.clone(),
        seq,
        at: from_micros(at_us),
        prev: to_hash(&prev).ok_or_else(decode)?,
        hash: to_hash(&hash).ok_or_else(decode)?,
    };
    if recorded.computed_hash() != recorded.hash {
        return Err(RecordError::Mismatch);
    }
    Ok(recorded)
}

/// The first key of the advisory locks that serialize each chain's appends, taken by
/// the database as it inserts (the second is the tenant's `hashtext`); two tenants
/// whose hashes collide merely share a lock.
pub const CHAIN_LOCK_CLASS: i32 = 0x6f77_7461;

fn to_hash(bytes: &[u8]) -> Option<Hash> {
    bytes.try_into().ok()
}

fn from_micros(us: i64) -> SystemTime {
    if us >= 0 {
        UNIX_EPOCH + Duration::from_micros(us.unsigned_abs())
    } else {
        UNIX_EPOCH - Duration::from_micros(us.unsigned_abs())
    }
}

fn micros(at: SystemTime) -> i64 {
    match at.duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_micros()).unwrap_or(i64::MAX),
        Err(e) => -i64::try_from(e.duration().as_micros()).unwrap_or(i64::MAX),
    }
}

/// Lowercase hex, for printing hashes.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_hold_codes_and_short_references_only() {
        let ok = Event::new(ActorKind::Account, "17", "record.view", "chart")
            .tenant("practice-1")
            .subject("patient:42")
            .purpose("treatment");
        assert!(ok.check().is_ok());
        let bad = [
            (
                Event {
                    action: "Record View".into(),
                    ..ok.clone()
                },
                "action",
            ),
            (
                Event {
                    resource_type: String::new(),
                    ..ok.clone()
                },
                "resource_type",
            ),
            (
                Event {
                    purpose: Some("to treat Ann for depression".into()),
                    ..ok.clone()
                },
                "purpose",
            ),
            (
                Event {
                    actor: String::new(),
                    ..ok.clone()
                },
                "actor",
            ),
            (
                Event {
                    tenant: Some(String::new()),
                    ..ok.clone()
                },
                "tenant",
            ),
            (
                Event {
                    subject: Some("x".repeat(201)),
                    ..ok.clone()
                },
                "subject",
            ),
            (
                Event {
                    resource_id: Some("a\nb".into()),
                    ..ok.clone()
                },
                "resource_id",
            ),
        ];
        for (e, field) in bad {
            assert_eq!(e.check(), Err(Invalid(field)));
        }
        let long_ua = ok.clone().client(None, Some(&"u".repeat(600)), None);
        assert_eq!(long_ua.user_agent.unwrap().len(), MAX_USER_AGENT);
    }

    #[test]
    fn micros_round_trip() {
        for us in [0, 1, 1_761_000_000_123_456, -5] {
            assert_eq!(micros(from_micros(us)), us);
        }
    }
}
