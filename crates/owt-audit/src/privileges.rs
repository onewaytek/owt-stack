//! What the connected role may do to the audit tables.
//!
//! The append-only triggers bind every role but the tables' owner, who can disable
//! them, rewrite a chain and recompute its hashes. A process that serves requests
//! should therefore connect as a role that holds `SELECT` and `INSERT` on the events
//! and nothing that reaches the triggers. [`privileges`] reports, for the role a pool
//! connects as, whether that holds, so an app checks it at startup and warns, or
//! refuses to start in production.

use std::fmt;

use sqlx::PgPool;

/// The audit tables [`privileges`] inspects.
const TABLES: [&str; 2] = ["owt_audit_events", "owt_audit_anchors"];

/// What the connected role may do to the audit tables beyond appending and reading.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Privileges {
    /// The role the pool's connections act as (`current_user`).
    pub role: String,
    /// The role is a superuser, which bypasses every check.
    pub superuser: bool,
    /// The tables whose owner the role is, or is a member of (it can then disable
    /// their triggers).
    pub owns: Vec<&'static str>,
    /// `table: PRIVILEGE` for each `UPDATE`, `DELETE`, `TRUNCATE` or `TRIGGER` the
    /// role holds on a table it does not own.
    pub excess: Vec<String>,
    /// The tables not found on the role's `search_path` (migrations not run).
    pub missing: Vec<&'static str>,
}

impl Privileges {
    /// The role can append and read but cannot alter, remove or unprotect events.
    pub fn least(&self) -> bool {
        !self.superuser && self.owns.is_empty() && self.excess.is_empty() && self.missing.is_empty()
    }
}

impl fmt::Display for Privileges {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.least() {
            return write!(
                f,
                "role {} holds no more than append and read on the audit tables",
                self.role
            );
        }
        write!(f, "role {}", self.role)?;
        let mut parts = Vec::new();
        if self.superuser {
            parts.push("is a superuser".to_owned());
        }
        if !self.owns.is_empty() {
            parts.push(format!("owns {}", self.owns.join(", ")));
        }
        if !self.excess.is_empty() {
            parts.push(format!("holds {}", self.excess.join(", ")));
        }
        if !self.missing.is_empty() {
            parts.push(format!("cannot find {}", self.missing.join(", ")));
        }
        write!(f, " {}", parts.join("; "))
    }
}

/// Report what the role `pool` connects as may do to the audit tables.
///
/// ```no_run
/// # async fn demo(pool: sqlx::PgPool) -> anyhow::Result<()> {
/// let p = owt_audit::privileges(&pool).await?;
/// if !p.least() {
///     tracing::warn!(%p, "the audit log is not append-only for this role");
/// }
/// # Ok(()) }
/// ```
pub async fn privileges(pool: &PgPool) -> Result<Privileges, sqlx::Error> {
    let (role, superuser): (String, bool) = sqlx::query_as(
        "SELECT current_user::text, COALESCE((SELECT rolsuper FROM pg_roles \
         WHERE rolname = current_user), false)",
    )
    .fetch_one(pool)
    .await?;
    let mut p = Privileges {
        role,
        superuser,
        owns: Vec::new(),
        excess: Vec::new(),
        missing: Vec::new(),
    };
    for table in TABLES {
        let row: Option<(bool, bool, bool, bool, bool)> = sqlx::query_as(
            "SELECT pg_has_role(current_user, c.relowner, 'MEMBER'), \
             has_table_privilege(c.oid, 'UPDATE'), has_table_privilege(c.oid, 'DELETE'), \
             has_table_privilege(c.oid, 'TRUNCATE'), has_table_privilege(c.oid, 'TRIGGER') \
             FROM pg_class c WHERE c.oid = to_regclass($1)",
        )
        .bind(table)
        .fetch_optional(pool)
        .await?;
        let Some((owns, update, delete, truncate, trigger)) = row else {
            p.missing.push(table);
            continue;
        };
        if owns {
            p.owns.push(table);
            continue;
        }
        for (held, name) in [
            (update, "UPDATE"),
            (delete, "DELETE"),
            (truncate, "TRUNCATE"),
            (trigger, "TRIGGER"),
        ] {
            if held {
                p.excess.push(format!("{table}: {name}"));
            }
        }
    }
    Ok(p)
}
