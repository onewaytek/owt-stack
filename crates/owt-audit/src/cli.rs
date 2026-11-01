//! The verifier as operator commands. Nest [`AuditCommand`] under the app's own CLI
//! (`myapp audit verify`) and call [`run`] with the pool.

use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use clap::Subcommand;
use sqlx::PgPool;

use crate::anchor::Manifest;

/// The audit log's operator commands.
#[derive(Debug, Clone, Subcommand)]
pub enum AuditCommand {
    /// Verify every chain (or one tenant's), and that the anchored heads are still in
    /// them. Exits non-zero at the first break, naming the chain and event.
    Verify {
        /// Only this tenant's chain (`""` for events with no tenant).
        #[arg(long)]
        tenant: Option<String>,
        /// Check the heads of this manifest, fetched from the anchor store, instead of
        /// the latest one the database records.
        #[arg(long)]
        manifest: Option<PathBuf>,
        /// Fail when the latest anchor is older than this (`90m`, `2h`, `1d`; a bare
        /// number is seconds), or when nothing is anchored.
        #[arg(long, value_parser = parse_age)]
        max_age: Option<Duration>,
    },
    /// Print every chain's head: tenant, position and hash, tab-separated.
    Heads,
}

/// Run `cmd`, printing to stdout.
pub async fn run(pool: &PgPool, cmd: AuditCommand) -> anyhow::Result<()> {
    let mut out = std::io::stdout();
    match cmd {
        AuditCommand::Verify {
            tenant,
            manifest,
            max_age,
        } => {
            let tenants = match tenant {
                Some(t) => vec![t],
                None => crate::heads(pool)
                    .await?
                    .into_iter()
                    .map(|h| h.tenant)
                    .collect(),
            };
            let mut events = 0;
            for t in &tenants {
                events += crate::verify(pool, t).await?.events;
            }
            // The database's anchors must form an unbroken chain of manifests,
            // whichever one the heads are checked against.
            let history = crate::anchor::history(pool).await?;
            let anchored = match manifest {
                Some(path) => {
                    let bytes = std::fs::read(&path)
                        .with_context(|| format!("reading {}", path.display()))?;
                    let m = Manifest::from_bytes(&bytes).context("reading the manifest")?;
                    if !history.iter().any(|h| h.digest() == m.digest()) {
                        anyhow::bail!(
                            "the given manifest ({}) is not among the anchors the database records",
                            m.key()
                        );
                    }
                    crate::verify_anchor(pool, &m).await?;
                    format!(
                        "; {} heads anchored by the given manifest match",
                        m.heads.len()
                    )
                }
                None => match history.last() {
                    Some(m) => {
                        crate::verify_anchor(pool, m).await?;
                        format!(
                            "; {} anchors chain, and the {} heads of the latest match (pass \
                             --manifest with the store's copy for an independent check)",
                            history.len(),
                            m.heads.len()
                        )
                    }
                    None => "; nothing anchored yet".into(),
                },
            };
            if let Some(max) = max_age {
                let Some(latest) = history.last() else {
                    anyhow::bail!("nothing is anchored, and --max-age requires an anchor");
                };
                let now = crate::micros(std::time::SystemTime::now());
                let age = Duration::from_micros(u64::try_from(now - latest.at_us).unwrap_or(0));
                if age > max {
                    anyhow::bail!(
                        "the latest anchor is {}s old, over --max-age {}s: events since are unanchored",
                        age.as_secs(),
                        max.as_secs()
                    );
                }
            }
            writeln!(
                out,
                "{} chains, {events} events verified{anchored}",
                tenants.len()
            )?;
        }
        AuditCommand::Heads => {
            for h in crate::heads(pool).await? {
                writeln!(out, "{}\t{}\t{}", h.tenant, h.seq, h.hash)?;
            }
        }
    }
    Ok(())
}

fn parse_age(s: &str) -> Result<Duration, String> {
    let (digits, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let n: u64 = digits
        .parse()
        .map_err(|_| format!("{s:?}: expected a number with s, m, h or d"))?;
    let secs = match unit {
        "" | "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        _ => return Err(format!("{s:?}: the unit is s, m, h or d")),
    };
    n.checked_mul(secs)
        .map(Duration::from_secs)
        .ok_or_else(|| format!("{s:?}: too long"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ages_parse_with_a_unit() {
        assert_eq!(parse_age("90"), Ok(Duration::from_secs(90)));
        assert_eq!(parse_age("90m"), Ok(Duration::from_mins(90)));
        assert_eq!(parse_age("2h"), Ok(Duration::from_hours(2)));
        assert_eq!(parse_age("1d"), Ok(Duration::from_hours(24)));
        assert!(parse_age("").is_err());
        assert!(parse_age("2w").is_err());
        assert!(parse_age("h").is_err());
    }
}
