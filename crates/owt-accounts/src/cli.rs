//! The operator's account commands: how an app with no staff, or a lost password, is
//! recovered from a shell. Nest [`AccountCommand`] under the app's own `Cli` and call
//! [`run`] with the pool.
//!
//! An app that wants its own command names or flags (a `create-user --host`, a
//! `login-link` with a shorter default lifetime) keeps its own clap enum instead:
//! `#[command(flatten)]` [`CreateArgs`] or [`LinkArgs`] into a variant beside the
//! app's flags and call [`create`] or [`link`] from its handler. [`create`] returns
//! the new [`Account`], so what the app adds (a flag's effect, a welcome) runs after
//! it exists.
//!
//! No secret rides in argv, where `ps` and shell history keep it. A password is
//! read from stdin when something is piped to it (one line, its newline dropped) and
//! generated otherwise (or when `--generate` says so); a generated password and a
//! sign-in link are printed once, to stdout, and logged nowhere. Failures carry no
//! secret either: they are the refusal's sentence or "the database".
//!
//! The futures are `Send`, and hold no lock on stdin or stdout across an `.await`
//! (each read and write locks for its own duration), so a log line another thread
//! writes while a command waits on the database or the hasher does not block.

use std::io::{self, BufRead, BufReader, IsTerminal, Read, Write};
use std::time::Duration;

use anyhow::{Context, bail};
use clap::{Args, Subcommand};
use sqlx::PgPool;

use crate::store::{self, Account, New};
use crate::{links, password};

/// The longest a link lives, in minutes: [`links::MAX_TTL`].
const MAX_MINUTES: i64 = (links::MAX_TTL.as_secs() / 60).cast_signed();

/// The lifetime of a link, in minutes, when `--minutes` is not given: what [`run`]
/// uses, and what [`link`] takes as its `default_minutes` to do the same.
pub const DEFAULT_MINUTES: u32 = 60;

/// The longest a link's `--reason`, in characters.
const MAX_REASON: usize = 200;

/// Parse `--next`: a local path ([`links::valid_next`]).
fn parse_next(text: &str) -> Result<String, String> {
    if links::valid_next(text) {
        Ok(text.to_owned())
    } else {
        Err("a path on this site, starting with a single `/` (no host, scheme, backslash or whitespace)".into())
    }
}

/// Parse `--reason`: a short line for the audit trail.
fn parse_reason(text: &str) -> Result<String, String> {
    if text.trim().is_empty()
        || text.chars().count() > MAX_REASON
        || text.chars().any(char::is_control)
    {
        Err(format!("one line of at most {MAX_REASON} characters"))
    } else {
        Ok(text.to_owned())
    }
}

/// The arguments of `create`, for an app to flatten into a command of its own.
#[derive(Clone, Debug, PartialEq, Eq, Args)]
pub struct CreateArgs {
    /// The new account's username.
    pub username: String,
    /// Its email.
    #[arg(long)]
    pub email: Option<String>,
    /// Make it staff.
    #[arg(long)]
    pub staff: bool,
    /// Generate the password even when stdin is piped.
    #[arg(long, conflicts_with = "no_password")]
    pub generate: bool,
    /// Give it no password: it is reached by a sign-in link (`link`) or a provider.
    #[arg(long)]
    pub no_password: bool,
}

/// The arguments of `link`, for an app to flatten into a command of its own.
#[derive(Clone, Debug, PartialEq, Eq, Args)]
pub struct LinkArgs {
    /// The account's username or email.
    pub login: String,
    /// How long it lives, in minutes (at most 30 days; 60 unless the app says
    /// otherwise).
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..=MAX_MINUTES))]
    pub minutes: Option<u32>,
    /// Why it was minted, kept with the link for the audit trail.
    #[arg(long, default_value = "cli", value_parser = parse_reason)]
    pub reason: String,
    /// A path on this site to land on after signing in, such as `/admin/`.
    #[arg(long, value_parser = parse_next)]
    pub next: Option<String>,
}

/// An account command. `login` is a username or an email.
#[derive(Clone, Debug, PartialEq, Eq, Subcommand)]
pub enum AccountCommand {
    /// Create an account. Its password is read from stdin when piped, else
    /// generated and printed once.
    Create(CreateArgs),
    /// Set an account's password, signing it out everywhere. Read from stdin when
    /// piped, else generated and printed once.
    SetPassword {
        /// The account's username or email.
        login: String,
        /// Generate the password even when stdin is piped.
        #[arg(long)]
        generate: bool,
    },
    /// Mint a one-time sign-in link, printed once.
    Link(LinkArgs),
    /// Make an account staff.
    Staff {
        /// The account's username or email.
        login: String,
    },
    /// Make an account no longer staff, signing it out everywhere.
    Unstaff {
        /// The account's username or email.
        login: String,
    },
    /// Print the Argon2 hash of a password read from stdin: the deployment-wide hash
    /// of `session::password_gate`, say. Touches no database.
    Hash {
        /// Generate the password too and print it once, with its hash.
        #[arg(long)]
        generate: bool,
    },
}

/// Run `command` against `pool`, reading a password from the process's stdin when it
/// is piped and writing to its stdout. `link_url` makes the URL a sign-in link
/// opens from its token: the app's route that calls [`links::redeem`], under its
/// public address.
///
/// A generated password or a link is written once, after the change it belongs to: if
/// the output then fails, the error says so (the account exists, or the password is
/// set, and `set-password --generate` makes another; an unseen link is only a row
/// that expires).
///
/// # Errors
///
/// A refusal ([`crate::Refused`], by its sentence), no such account, a stdin that
/// holds no password, the database, or the output.
pub async fn run(
    command: AccountCommand,
    pool: &PgPool,
    link_url: impl Fn(&str) -> String + Sync,
) -> anyhow::Result<()> {
    // `Stdin` and `Stdout` lock for each call, not for the command.
    let mut piped = (!io::stdin().is_terminal()).then(|| BufReader::new(io::stdin()));
    let piped = piped
        .as_mut()
        .map(|input| input as &mut (dyn BufRead + Send));
    run_with(command, pool, link_url, piped, &mut io::stdout()).await
}

/// [`run`] with the input and output given: `stdin` is where a password is read from
/// (`None` generates one), `out` where results are written.
///
/// # Errors
///
/// As [`run`].
pub async fn run_with(
    command: AccountCommand,
    pool: &PgPool,
    link_url: impl Fn(&str) -> String + Sync,
    stdin: Option<&mut (dyn BufRead + Send)>,
    out: &mut (dyn Write + Send),
) -> anyhow::Result<()> {
    match command {
        AccountCommand::Create(args) => {
            create(pool, stdin, out, &args).await?;
        }
        AccountCommand::SetPassword { login, generate } => {
            let account = find(pool, &login).await?;
            let like = [account.username.as_str(), account.email.as_str()];
            let (secret, generated) = password_from(stdin, generate, &like)?;
            if !store::set_password(pool, &account, &secret).await? {
                bail!("{} no longer exists", account.username);
            }
            let shown = writeln!(out, "set the password of {}", account.username).and_then(|()| {
                if generated {
                    show_once(out, "password", &secret)
                } else {
                    Ok(())
                }
            });
            shown.context(
                "the password was set, but the generated one was not shown; \
                 set another with set-password --generate",
            )?;
        }
        AccountCommand::Link(args) => link(pool, out, &args, DEFAULT_MINUTES, link_url).await?,
        AccountCommand::Staff { login } => set_staff(pool, out, &login, true).await?,
        AccountCommand::Unstaff { login } => set_staff(pool, out, &login, false).await?,
        AccountCommand::Hash { generate } => {
            let (secret, generated) = password_from(stdin, generate, &[])?;
            let hash = owt_auth::password::hash(&secret).await?;
            if generated {
                show_once(out, "password", &secret)?;
            }
            writeln!(out, "{hash}")?;
        }
    }
    Ok(())
}

/// The `create` command: make the account `args` names, reading its password from
/// `stdin` or generating one, and write the result to `out`. Returns the account, for
/// an app that does more once it exists.
///
/// # Errors
///
/// As [`run`]; a refusal ([`crate::Refused`]) is the sentence to show.
pub async fn create(
    pool: &PgPool,
    stdin: Option<&mut (dyn BufRead + Send)>,
    out: &mut (dyn Write + Send),
    args: &CreateArgs,
) -> anyhow::Result<Account> {
    let CreateArgs {
        username,
        email,
        staff,
        generate,
        no_password,
    } = args;
    let email = email.as_deref().unwrap_or_default();
    let (given, generated) = if *no_password {
        (None, false)
    } else {
        let like = [username.as_str(), email];
        let (secret, generated) = password_from(stdin, *generate, &like)?;
        (Some(secret), generated)
    };
    let account = store::create(
        pool,
        New {
            username,
            email,
            password: given.as_deref(),
            is_staff: *staff,
        },
    )
    .await?;
    let shown = writeln!(out, "created {} (id {})", account.username, account.id).and_then(|()| {
        match (generated, &given) {
            (true, Some(secret)) => show_once(out, "password", secret),
            _ => Ok(()),
        }
    });
    shown.context(
        "the account was created, but its generated password was not shown; \
         set another with set-password --generate",
    )?;
    Ok(account)
}

/// The `link` command: mint a one-time sign-in link for the account `args` names and
/// write its URL (`link_url` of the token) to `out`. The link lives `args.minutes`, or
/// `default_minutes` when none was given (at most 30 days).
///
/// # Errors
///
/// As [`run`].
pub async fn link(
    pool: &PgPool,
    out: &mut (dyn Write + Send),
    args: &LinkArgs,
    default_minutes: u32,
    link_url: impl Fn(&str) -> String + Sync,
) -> anyhow::Result<()> {
    let account = find(pool, &args.login).await?;
    if !account.is_active {
        bail!("{} is deactivated", account.username);
    }
    let minutes = args
        .minutes
        .unwrap_or(default_minutes)
        .clamp(1, u32::try_from(MAX_MINUTES)?);
    let ttl = Duration::from_secs(u64::from(minutes) * 60);
    let minted = links::mint_with(pool, account.id, ttl, &args.reason, args.next.as_deref())
        .await
        .context("minting the link")?;
    writeln!(
        out,
        "sign-in link for {}, once, {minutes} minutes:",
        account.username
    )
    .and_then(|()| writeln!(out, "{}", link_url(&minted.token)))
    .context("the link was minted but not shown; it expires unused")?;
    Ok(())
}

async fn set_staff(
    pool: &PgPool,
    out: &mut (dyn Write + Send),
    login: &str,
    staff: bool,
) -> anyhow::Result<()> {
    let account = find(pool, login).await?;
    store::set_staff(pool, account.id, staff).await?;
    let verb = if staff { "is now" } else { "is no longer" };
    writeln!(out, "{} {verb} staff", account.username)?;
    Ok(())
}

fn show_once(out: &mut (dyn Write + Send), what: &str, value: &str) -> io::Result<()> {
    writeln!(out, "{what} (shown once): {value}")
}

/// The account `login` names, by username or email, active or not: an operator
/// reaches an account that password sign-in is off for, too.
async fn find(pool: &PgPool, login: &str) -> anyhow::Result<Account> {
    let login = store::normalize(login);
    sqlx::query_as::<_, Account>(sqlx::AssertSqlSafe(format!(
        "SELECT {} FROM accounts
         WHERE username = $1 OR (email <> '' AND lower(email) = $1)",
        store::COLUMNS
    )))
    .bind(&login)
    .fetch_optional(pool)
    .await
    .context("reading the account")?
    .with_context(|| format!("no account is named {login}"))
}

/// The password to use and whether it was generated: `generate`, or no `stdin`, makes
/// one that passes the rules for `like`; otherwise the first line of `stdin`.
fn password_from(
    stdin: Option<&mut (dyn BufRead + Send)>,
    generate: bool,
    like: &[&str],
) -> anyhow::Result<(String, bool)> {
    match stdin {
        Some(input) if !generate => Ok((read_line(input)?, false)),
        _ => Ok((password::generate(like), true)),
    }
}

/// One line of `input` (its line ending dropped), at most [`password::MAX_BYTES`].
fn read_line(input: &mut (dyn BufRead + Send)) -> anyhow::Result<String> {
    let mut line = Vec::new();
    // One byte past the cap, so a line over it is seen rather than cut to fit. Bytes,
    // decoded after the length check: a cut inside a character is "too long".
    let limit = u64::try_from(password::MAX_BYTES + 2)?;
    input
        .take(limit)
        .read_until(b'\n', &mut line)
        .context("reading the password from stdin")?;
    if line.last() == Some(&b'\n') {
        line.pop();
    }
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    if line.is_empty() {
        bail!("stdin holds no password: pipe one line, or pass --generate");
    }
    if line.len() > password::MAX_BYTES {
        bail!("the password on stdin is too long");
    }
    // The error owns the bytes; it is dropped, not chained.
    String::from_utf8(line).map_err(|_| anyhow::anyhow!("the password on stdin is not valid UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_password_is_one_line_without_its_ending() {
        let read = |text: &str| read_line(&mut text.as_bytes());
        assert_eq!(read("correct horse\n").unwrap(), "correct horse");
        assert_eq!(read("correct horse\r\nmore\n").unwrap(), "correct horse");
        assert_eq!(read("no newline").unwrap(), "no newline");
        assert_eq!(read(" padded \n").unwrap(), " padded ");
        assert!(read("").is_err());
        assert!(read("\n").is_err());
        let long = "x".repeat(password::MAX_BYTES + 1);
        assert!(read(&format!("{long}\n")).is_err());
        // Cut inside a two-byte character at the cap: too long, not invalid UTF-8.
        let wide = "é".repeat(password::MAX_BYTES);
        let err = read(&format!("{wide}\n")).unwrap_err();
        assert!(err.to_string().contains("too long"), "{err}");
        assert!(read("caf\u{e9}\n").is_ok());
        let exact = "x".repeat(password::MAX_BYTES);
        assert_eq!(read(&format!("{exact}\n")).unwrap(), exact);
    }

    #[test]
    fn no_stdin_or_generate_makes_a_password() {
        let (p, generated) = password_from(None, false, &["ada"]).unwrap();
        assert!(generated && p.len() == 20);
        let mut piped: &[u8] = b"from stdin\n";
        let (p, generated) = password_from(Some(&mut piped), true, &[]).unwrap();
        assert!(generated && p != "from stdin");
        let mut piped: &[u8] = b"from stdin\n";
        assert_eq!(
            password_from(Some(&mut piped), false, &[]).unwrap(),
            ("from stdin".to_owned(), false)
        );
    }
}
