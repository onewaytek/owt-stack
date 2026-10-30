//! The verifier as operator commands. Nest [`AuditCommand`] under the app's own CLI
//! (`myapp audit verify`) and call [`run`] with the pool.

use std::io::Write;
use std::path::PathBuf;

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
    },
    /// Print every chain's head: tenant, position and hash, tab-separated.
    Heads,
}

/// Run `cmd`, printing to stdout.
pub async fn run(pool: &PgPool, cmd: AuditCommand) -> anyhow::Result<()> {
    let mut out = std::io::stdout();
    match cmd {
        AuditCommand::Verify { tenant, manifest } => {
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
            let from_store = manifest.is_some();
            let manifest = match manifest {
                Some(path) => {
                    let bytes = std::fs::read(&path)
                        .with_context(|| format!("reading {}", path.display()))?;
                    Some(Manifest::from_bytes(&bytes).context("reading the manifest")?)
                }
                None => crate::anchor::latest(pool).await?,
            };
            let anchored = match &manifest {
                Some(m) => {
                    crate::verify_anchor(pool, m).await?;
                    let from = if from_store {
                        "the given manifest"
                    } else {
                        "the database's latest manifest (pass --manifest with the store's copy for an independent check)"
                    };
                    format!("; {} heads anchored by {from} match", m.heads.len())
                }
                None => "; nothing anchored yet".into(),
            };
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
