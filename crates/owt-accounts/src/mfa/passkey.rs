//! Passkeys (Web Authentication) as a second factor and as a step-up proof.
//!
//! A passkey is a key pair an authenticator (a phone, a laptop's platform authenticator,
//! a security key) makes for this site and keeps; the site stores the public half in
//! `account_passkeys` and checks a signature over a fresh challenge at each use. The
//! ceremonies are webauthn-rs's (`webauthn-rs` 0.6, on `RustCrypto`, with no `OpenSSL`).
//!
//! * **The site is named in configuration** ([`RelyingParty`]): the relying-party id (a
//!   domain, `example.com`) and the origins the browser may report
//!   (`https://example.com`). A passkey works only on the id it was made for, so
//!   choose it once. [`RelyingParty::from_env`] reads `PASSKEY_RP_ID`,
//!   `PASSKEY_ORIGIN` and `PASSKEY_RP_NAME`; [`Mfa::passkeys`](super::Mfa::passkeys)
//!   turns passkeys on.
//! * **Ceremony state stays on the server.** Beginning a registration or an
//!   authentication stores webauthn-rs's state in `account_passkey_ceremonies`, bound
//!   to the account, the purpose and the session that began it, and hands the browser
//!   the options and an opaque token ([`Ceremony`]). Finishing deletes the row as it
//!   reads it, so a challenge answers once, and only from the session that began it
//!   (a token carried to another browser is refused); it expires after five minutes.
//! * **A passkey is a factor like the authenticator app**: registering one needs a
//!   [`ChangeProof`](super::ChangeProof), the first factor of an account issues its
//!   recovery codes, removing one needs step-up, and the last factor of an account the
//!   policy requires cannot be removed. Every change moves the account's session epoch
//!   on and returns [`Event`](super::Event)s.
//! * **A counter that does not rise past the stored one is refused**
//!   ([`MfaError::PasskeyCloned`]), checked against the row as it stands when the
//!   answer arrives, not as it stood when the ceremony began: it means the credential
//!   may exist twice. (A synced passkey reports no counter, so this never applies to
//!   it.) The passkey is disabled there and then: it is no longer offered, accepted or
//!   counted as a factor, and the settings page shows it as a suspected copy until its
//!   owner removes it. The error carries an event for the audit log
//!   ([`MfaError::event`]), and the same event goes to the notifier
//!   ([`Mfa::on_security_event`](super::Mfa::on_security_event)) to tell the owner.

use std::time::Duration;

use base64::Engine;
use serde::Serialize;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use webauthn_rs::prelude::{
    Passkey, PasskeyAuthentication, PasskeyRegistration, Uuid, WebauthnError,
};
use webauthn_rs::{Webauthn, WebauthnBuilder};

pub use webauthn_rs::prelude::{
    CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse, Url,
};

use super::{ChangeProof, Confirmed, Event, EventKind, Factor, Mfa, MfaError, Next, state};
use crate::session;
use crate::store::{self, Account};

/// How long a begun ceremony waits for the browser: webauthn-rs's own timeout.
pub const CEREMONY_TTL: Duration = webauthn_rs::DEFAULT_AUTHENTICATOR_TIMEOUT;

/// The longest name a passkey may be given, in characters.
pub const NAME_MAX: usize = 64;

/// The site passkeys are made for: its relying-party id and the origins a browser may
/// report.
///
/// The id is a domain, without a scheme or port (`example.com`); each origin's host is
/// the id or a subdomain of it (`https://example.com`, `https://app.example.com`). An
/// origin is `https`, except `http://localhost` (with any port) for development,
/// which browsers treat as secure: locally, the id is `localhost` and the origin
/// `http://localhost:3000`. A passkey made for one id does not work on another, so
/// production and development keep separate passkeys.
#[derive(Clone)]
pub struct RelyingParty {
    id: String,
    name: String,
    origins: Vec<Url>,
    webauthn: std::sync::Arc<Webauthn>,
}

impl std::fmt::Debug for RelyingParty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelyingParty")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("origins", &self.origins)
            .finish_non_exhaustive()
    }
}

/// Why a [`RelyingParty`] could not be made: the configuration is wrong.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RelyingPartyError {
    /// `PASSKEY_RP_ID` is set and `PASSKEY_ORIGIN` is not.
    #[error(
        "PASSKEY_RP_ID is set but PASSKEY_ORIGIN is not: set the site's origin, such as https://example.com"
    )]
    MissingOrigin,
    /// The relying-party id is empty or holds a scheme, a port or a path.
    #[error("the passkey relying-party id {0:?} is not a bare domain such as example.com")]
    BadId(String),
    /// An origin does not parse as a URL with a host.
    #[error("the passkey origin {0:?} is not a URL such as https://example.com")]
    BadOrigin(String),
    /// An origin is plain `http` on a host other than `localhost`.
    #[error("the passkey origin {0} is not https (plain http is allowed for localhost only)")]
    Insecure(Url),
    /// An origin's host is neither the id nor a subdomain of it.
    #[error(
        "the passkey origin {origin} does not belong to the relying-party id {id:?}: its host must be {id} or end in .{id}"
    )]
    Mismatch {
        /// The relying-party id.
        id: String,
        /// The origin.
        origin: Url,
    },
    /// webauthn-rs refused the configuration.
    #[error("webauthn-rs refused the passkey configuration: {0}")]
    Refused(String),
}

impl RelyingParty {
    /// Passkeys for the relying-party `id`, used from `origin`. The name shown by the
    /// authenticator is the id until [`name`](Self::name) sets one.
    ///
    /// # Errors
    /// The id is not a bare domain, or the origin is not a secure origin of it.
    pub fn new(id: impl Into<String>, origin: &str) -> Result<Self, RelyingPartyError> {
        let id = id.into().trim().to_ascii_lowercase();
        if id.is_empty() || id.contains(['/', ':', ' ']) || id.starts_with('.') {
            return Err(RelyingPartyError::BadId(id));
        }
        let origin = Self::check_origin(&id, origin)?;
        let mut rp = Self {
            name: id.clone(),
            id,
            origins: vec![origin],
            webauthn: std::sync::Arc::new(Self::placeholder()?),
        };
        rp.rebuild()?;
        Ok(rp)
    }

    /// Accept `origin` too: another subdomain of the id that serves the same pages.
    ///
    /// # Errors
    /// The origin is not a secure origin of the id.
    pub fn also(mut self, origin: &str) -> Result<Self, RelyingPartyError> {
        let origin = Self::check_origin(&self.id, origin)?;
        if !self.origins.contains(&origin) {
            self.origins.push(origin);
            self.rebuild()?;
        }
        Ok(self)
    }

    /// The site's name, which an authenticator shows when a passkey is made.
    ///
    /// # Errors
    /// webauthn-rs refused it.
    pub fn name(mut self, name: impl Into<String>) -> Result<Self, RelyingPartyError> {
        self.name = name.into();
        self.rebuild()?;
        Ok(self)
    }

    /// The configuration from the environment, or `None` when `PASSKEY_RP_ID` is unset
    /// or empty (passkeys stay off):
    ///
    /// * `PASSKEY_RP_ID`: the relying-party id, `example.com` (`localhost` locally);
    /// * `PASSKEY_ORIGIN`: the origin, or several separated by commas, the first the
    ///   site's own (`https://example.com`; `http://localhost:3000` locally);
    /// * `PASSKEY_RP_NAME`: the name an authenticator shows (the id if unset).
    ///
    /// # Errors
    /// `PASSKEY_RP_ID` is set and the rest is missing or does not match it.
    pub fn from_env() -> Result<Option<Self>, RelyingPartyError> {
        let var = |name: &str| {
            std::env::var(name)
                .ok()
                .map(|v| v.trim().to_owned())
                .filter(|v| !v.is_empty())
        };
        let Some(id) = var("PASSKEY_RP_ID") else {
            return Ok(None);
        };
        let origins = var("PASSKEY_ORIGIN").ok_or(RelyingPartyError::MissingOrigin)?;
        let mut origins = origins.split(',').map(str::trim).filter(|o| !o.is_empty());
        let first = origins.next().ok_or(RelyingPartyError::MissingOrigin)?;
        let mut rp = Self::new(id, first)?;
        for origin in origins {
            rp = rp.also(origin)?;
        }
        if let Some(name) = var("PASSKEY_RP_NAME") {
            rp = rp.name(name)?;
        }
        Ok(Some(rp))
    }

    /// The relying-party id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The origins a browser may report.
    #[must_use]
    pub fn origins(&self) -> &[Url] {
        &self.origins
    }

    pub(crate) fn webauthn(&self) -> &Webauthn {
        &self.webauthn
    }

    fn check_origin(id: &str, origin: &str) -> Result<Url, RelyingPartyError> {
        let url = Url::parse(origin.trim())
            .map_err(|_| RelyingPartyError::BadOrigin(origin.to_owned()))?;
        let host = url
            .host_str()
            .ok_or_else(|| RelyingPartyError::BadOrigin(origin.to_owned()))?
            .to_ascii_lowercase();
        let local = host == "localhost" || host.ends_with(".localhost");
        match url.scheme() {
            "https" => {}
            "http" if local => {}
            "http" => return Err(RelyingPartyError::Insecure(url)),
            _ => return Err(RelyingPartyError::BadOrigin(origin.to_owned())),
        }
        if host != id && !host.ends_with(&format!(".{id}")) {
            return Err(RelyingPartyError::Mismatch {
                id: id.to_owned(),
                origin: url,
            });
        }
        // An origin is a scheme, a host and a port: no path.
        let mut bare = url;
        bare.set_path("");
        bare.set_query(None);
        bare.set_fragment(None);
        Ok(bare)
    }

    fn placeholder() -> Result<Webauthn, RelyingPartyError> {
        let origin = Url::parse("http://localhost")
            .map_err(|e| RelyingPartyError::Refused(e.to_string()))?;
        WebauthnBuilder::new("localhost", &origin)
            .and_then(WebauthnBuilder::build)
            .map_err(|e| RelyingPartyError::Refused(e.to_string()))
    }

    fn rebuild(&mut self) -> Result<(), RelyingPartyError> {
        let refused = |e: WebauthnError| RelyingPartyError::Refused(e.to_string());
        let mut builder = WebauthnBuilder::new(&self.id, &self.origins[0])
            .map_err(refused)?
            .rp_name(&self.name);
        for origin in &self.origins[1..] {
            builder = builder.append_allowed_origin(origin);
        }
        self.webauthn = std::sync::Arc::new(builder.build().map_err(refused)?);
        Ok(())
    }
}

/// A ceremony begun: the options for the browser's `navigator.credentials` call, and
/// the token that names the server-held state. Send both to the page; the token comes
/// back with the browser's answer.
#[derive(Debug)]
#[non_exhaustive]
pub struct Ceremony<O> {
    /// An opaque, random token: the state it names stays on the server.
    pub token: String,
    /// The options, which serialize to the JSON the browser expects
    /// (`{"publicKey": {...}}`, binary fields as base64url).
    pub options: O,
}

impl<O: Serialize> Ceremony<O> {
    /// The options as JSON.
    ///
    /// # Errors
    /// They do not serialize (never, for webauthn-rs's types).
    pub fn options_json(&self) -> Result<String, MfaError> {
        serde_json::to_string(&self.options).map_err(|e| MfaError::fault(e.into()))
    }
}

/// A passkey of an account, for its settings page.
#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow)]
#[non_exhaustive]
pub struct PasskeyInfo {
    /// Its row id, which rename and remove take.
    pub id: i64,
    /// The name the person gave it.
    pub name: String,
    /// When it was registered, in Unix seconds.
    pub created_at: i64,
    /// When it last signed in or re-authenticated, in Unix seconds.
    pub last_used_at: Option<i64>,
    /// The authenticator may sync it to other devices (a synced passkey).
    pub backup_eligible: bool,
    /// It is synced (backed up) now.
    pub backup_state: bool,
    /// When it was disabled as a suspected copy ([`MfaError::PasskeyCloned`]), in Unix
    /// seconds: a disabled passkey is no factor until it is removed.
    pub disabled_at: Option<i64>,
}

/// What a ceremony is for.
#[derive(Clone, Copy)]
enum Purpose {
    Register,
    Authenticate,
}

impl Purpose {
    fn as_str(self) -> &'static str {
        match self {
            Self::Register => "register",
            Self::Authenticate => "authenticate",
        }
    }
}

fn digest(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

/// A passkey name as given: trimmed, one to [`NAME_MAX`] characters, no control
/// characters.
fn clean_name(name: &str) -> Result<&str, MfaError> {
    let name = name.trim();
    let count = name.chars().count();
    if count == 0 || count > NAME_MAX || name.chars().any(char::is_control) {
        return Err(MfaError::BadName);
    }
    Ok(name)
}

/// The error a ceremony's refusal by webauthn-rs answers with; an origin or
/// relying-party mismatch is logged, as it is usually the configuration.
fn refused(e: &WebauthnError) -> MfaError {
    match e {
        WebauthnError::InvalidRPOrigin | WebauthnError::InvalidRPIDHash => {
            tracing::warn!(
                error = %e,
                "a passkey answer came from another origin or relying-party id than \
                 PASSKEY_ORIGIN and PASSKEY_RP_ID name"
            );
            MfaError::PasskeyOrigin
        }
        e => {
            tracing::debug!(error = %e, "a passkey answer was refused");
            MfaError::Invalid
        }
    }
}

async fn store_ceremony<T: state::MfaSession>(
    pool: &PgPool,
    session: &owt_web::session::Session<T>,
    account: i64,
    purpose: Purpose,
    state: &impl Serialize,
) -> Result<String, MfaError> {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let state = serde_json::to_value(state).map_err(|e| MfaError::fault(e.into()))?;
    sqlx::query("DELETE FROM account_passkey_ceremonies WHERE expires_at < now()")
        .execute(pool)
        .await?;
    sqlx::query(
        "INSERT INTO account_passkey_ceremonies
           (token_hash, account_id, purpose, session_hash, state, expires_at)
         VALUES ($1, $2, $3, $4, $5, now() + make_interval(secs => $6))",
    )
    .bind(digest(&token))
    .bind(account)
    .bind(purpose.as_str())
    .bind(digest(&session.ensure_id()))
    .bind(state)
    .bind(CEREMONY_TTL.as_secs_f64())
    .execute(pool)
    .await?;
    Ok(token)
}

/// The state `token` names, for `account`, `purpose` and the session `session`,
/// deleted as it is read: `None` when there is none, it expired, or it is another
/// account's or another session's.
async fn take_ceremony<S: DeserializeOwned, T: state::MfaSession>(
    pool: &PgPool,
    session: &owt_web::session::Session<T>,
    token: &str,
    account: i64,
    purpose: Purpose,
) -> Result<Option<S>, MfaError> {
    let row: Option<(i64, Vec<u8>, serde_json::Value, bool)> = sqlx::query_as(
        "DELETE FROM account_passkey_ceremonies WHERE token_hash = $1 AND purpose = $2
         RETURNING account_id, session_hash, state, expires_at > now()",
    )
    .bind(digest(token))
    .bind(purpose.as_str())
    .fetch_optional(pool)
    .await?;
    let this_session = session.id().map(|id| digest(&id));
    match row {
        Some((owner, began_in, state, true))
            if owner == account && this_session.as_deref() == Some(began_in.as_slice()) =>
        {
            serde_json::from_value(state)
                .map(Some)
                .map_err(|e| MfaError::fault(e.into()))
        }
        Some((owner, _, _, true)) if owner == account => {
            tracing::warn!(
                account,
                "a passkey ceremony was answered from another session"
            );
            Ok(None)
        }
        _ => Ok(None),
    }
}

/// The account's passkeys: every one, or only those not disabled.
async fn passkeys_of(
    db: impl sqlx::PgExecutor<'_>,
    account: i64,
    usable_only: bool,
) -> Result<Vec<(i64, Passkey)>, MfaError> {
    let rows: Vec<(i64, serde_json::Value)> = sqlx::query_as(
        "SELECT id, passkey FROM account_passkeys
         WHERE account_id = $1 AND (NOT $2 OR disabled_at IS NULL) ORDER BY id",
    )
    .bind(account)
    .bind(usable_only)
    .fetch_all(db)
    .await?;
    rows.into_iter()
        .map(|(id, v)| {
            serde_json::from_value(v)
                .map(|p| (id, p))
                .map_err(|e| MfaError::fault(e.into()))
        })
        .collect()
}

impl Mfa {
    /// Offer passkeys, for the site `rp` names. Without it, the passkey functions answer
    /// [`MfaError::PasskeysOff`] and the pages show none.
    #[must_use]
    pub fn passkeys(mut self, rp: RelyingParty) -> Self {
        self.passkeys = Some(rp);
        self
    }

    /// The relying party passkeys are made for, if they are on.
    #[must_use]
    pub fn relying_party(&self) -> Option<&RelyingParty> {
        self.passkeys.as_ref()
    }

    fn rp(&self) -> Result<&RelyingParty, MfaError> {
        self.passkeys.as_ref().ok_or(MfaError::PasskeysOff)
    }

    /// Begin registering a passkey for `account`: the options for
    /// `navigator.credentials.create()`, which exclude the passkeys it has. The
    /// registration is finished by
    /// [`finish_passkey_registration`](Self::finish_passkey_registration) with the
    /// token, from this `session`: the ceremony is bound to it.
    ///
    /// # Errors
    /// [`MfaError::PasskeysOff`], [`MfaError::NoChallenge`] for another account's
    /// proof, or a fault.
    pub async fn begin_passkey_registration<T: state::MfaSession>(
        &self,
        pool: &PgPool,
        session: &owt_web::session::Session<T>,
        account: &Account,
        proof: &ChangeProof,
    ) -> Result<Ceremony<CreationChallengeResponse>, MfaError> {
        let rp = self.rp()?;
        Self::proof_for(proof, account)?;
        let handle: String = sqlx::query_scalar(
            "INSERT INTO account_webauthn_users (account_id, user_handle) VALUES ($1, $2::uuid)
             ON CONFLICT (account_id) DO UPDATE SET account_id = EXCLUDED.account_id
             RETURNING user_handle::text",
        )
        .bind(account.id)
        .bind(Uuid::new_v4().to_string())
        .fetch_one(pool)
        .await?;
        let handle = Uuid::parse_str(&handle).map_err(|e| MfaError::fault(e.into()))?;
        let exclude = passkeys_of(pool, account.id, false)
            .await?
            .into_iter()
            .map(|(_, p)| p.cred_id().clone())
            .collect::<Vec<_>>();
        let user = if account.email.is_empty() {
            &account.username
        } else {
            &account.email
        };
        let (options, state) = rp
            .webauthn()
            .start_passkey_registration(handle, user, &account.username, Some(exclude))
            .map_err(|e| MfaError::fault(anyhow::anyhow!("passkey registration: {e}")))?;
        let token = store_ceremony(pool, session, account.id, Purpose::Register, &state).await?;
        Ok(Ceremony { token, options })
    }

    /// Finish registering a passkey with the browser's answer, under `name` (one to
    /// [`NAME_MAX`] characters). As with [`confirm_totp`](Self::confirm_totp): the
    /// account's session epoch moves on (its other sessions end), this session is
    /// resealed (or, for a pending enrollment, signed in) with a second factor
    /// recorded now, and recovery codes are issued when this is the account's first
    /// factor (an account that has one keeps its codes, and
    /// [`Confirmed::recovery_codes`] is empty).
    ///
    /// # Errors
    /// [`MfaError::BadName`], [`MfaError::PasskeyExpired`] (no such ceremony, it
    /// expired or was used, or another session began it), [`MfaError::PasskeyOrigin`], [`MfaError::Invalid`] (the
    /// answer does not verify), [`MfaError::PasskeyTaken`] (the credential is
    /// registered already, to any account), [`MfaError::NoChallenge`], or a fault.
    #[allow(clippy::too_many_arguments)] // each is a separate input of the ceremony
    pub async fn finish_passkey_registration<T: state::MfaSession>(
        &self,
        pool: &PgPool,
        session: &owt_web::session::Session<T>,
        account: &Account,
        proof: &ChangeProof,
        token: &str,
        name: &str,
        credential: &RegisterPublicKeyCredential,
    ) -> Result<Confirmed, MfaError> {
        let rp = self.rp()?;
        Self::proof_for(proof, account)?;
        let name = clean_name(name)?;
        let state: PasskeyRegistration =
            take_ceremony(pool, session, token, account.id, Purpose::Register)
                .await?
                .ok_or(MfaError::PasskeyExpired)?;
        let passkey = rp
            .webauthn()
            .finish_passkey_registration(credential, &state)
            .map_err(|e| refused(&e))?;
        let stored = serde_json::to_value(&passkey).map_err(|e| MfaError::fault(e.into()))?;
        let (eligible, backed_up) = backup_flags(&stored);

        let first = !self.factors(pool, account.id).await?.any();
        let codes = if first {
            super::recovery::generate(self.recovery_codes)
                .await
                .map_err(MfaError::fault)?
        } else {
            Vec::new()
        };
        let now = std::time::SystemTime::now();
        let mut tx = pool.begin().await?;
        lock_account(&mut tx, account.id).await?;
        let had = factor_count(&mut tx, account.id).await? > 0;
        let id: Option<i64> = sqlx::query_scalar(
            "INSERT INTO account_passkeys
               (account_id, credential_id, passkey, name, counter, backup_eligible, backup_state)
             VALUES ($1, $2, $3, $4, 0, $5, $6)
             ON CONFLICT (credential_id) DO NOTHING RETURNING id",
        )
        .bind(account.id)
        .bind(passkey.cred_id().as_slice())
        .bind(&stored)
        .bind(name)
        .bind(eligible)
        .bind(backed_up)
        .fetch_optional(&mut *tx)
        .await?;
        let id = id.ok_or(MfaError::PasskeyTaken)?;
        // Codes made for a first factor are dropped when another factor arrived meanwhile.
        let codes = if had { Vec::new() } else { codes };
        if !codes.is_empty() {
            super::replace_codes(&mut tx, account.id, &codes).await?;
        }
        let epoch = super::bump_epoch(&mut tx, account.id, account.session_epoch).await?;
        tx.commit().await?;

        let account_now = Account {
            session_epoch: epoch,
            ..account.clone()
        };
        if proof.pending {
            session::sign_in(session, &account_now);
            state::record(session, &account_now, true, now);
            store::signed_in(pool, account.id).await?;
        } else {
            state::reseal(session, &account_now, account.session_epoch, true, now);
        }
        let event = |kind| Event {
            while_pending: proof.pending,
            passkey: Some(id),
            ..Event::new(account.id, kind)
        };
        let mut events = vec![event(EventKind::Enrolled(Factor::Passkey))];
        if !codes.is_empty() {
            events.push(Event {
                passkey: None,
                ..event(EventKind::RecoveryCodesIssued)
            });
        }
        Ok(Confirmed {
            recovery_codes: codes,
            next: Next::Done,
            events,
        })
    }

    /// Begin a passkey authentication for `account`: the options for
    /// `navigator.credentials.get()`, listing its passkeys (not the disabled ones), or
    /// `None` when it has none or passkeys are off. The ceremony is bound to this
    /// `session`, and is answered from it only. [`challenge_passkey`](Self::challenge_passkey) finishes it.
    /// Begin it for the account a pending sign-in or re-authentication is for, or the
    /// one the session is signed in as (a re-authentication page shown before the
    /// password is checked): the answer counts only for the pending account.
    ///
    /// # Errors
    /// A fault.
    pub async fn begin_passkey_challenge<T: state::MfaSession>(
        &self,
        pool: &PgPool,
        session: &owt_web::session::Session<T>,
        account: &Account,
    ) -> Result<Option<Ceremony<RequestChallengeResponse>>, MfaError> {
        let Some(rp) = self.passkeys.as_ref() else {
            return Ok(None);
        };
        let passkeys: Vec<Passkey> = passkeys_of(pool, account.id, true)
            .await?
            .into_iter()
            .map(|(_, p)| p)
            .collect();
        if passkeys.is_empty() {
            return Ok(None);
        }
        let (options, state) = rp
            .webauthn()
            .start_passkey_authentication(&passkeys)
            .map_err(|e| MfaError::fault(anyhow::anyhow!("passkey authentication: {e}")))?;
        let token =
            store_ceremony(pool, session, account.id, Purpose::Authenticate, &state).await?;
        Ok(Some(Ceremony { token, options }))
    }

    /// Check a passkey's answer for `account`, in the session that began the ceremony;
    /// the passkey's row id. The counter and backup state are updated, and the last use
    /// stamped. A suspected copy disables the passkey and tells the notifier.
    pub(super) async fn check_passkey<T: state::MfaSession>(
        &self,
        pool: &PgPool,
        session: &owt_web::session::Session<T>,
        account: &Account,
        token: &str,
        credential: &PublicKeyCredential,
    ) -> Result<i64, MfaError> {
        let rp = self.rp()?;
        let state: PasskeyAuthentication =
            take_ceremony(pool, session, token, account.id, Purpose::Authenticate)
                .await?
                .ok_or(MfaError::PasskeyExpired)?;
        // Only this account's passkeys that are not disabled: another account's
        // credential is not looked at. The row stays held until the counter is stored,
        // so two answers of one credential are checked one after the other.
        let mut tx = pool.begin().await?;
        let row: Option<(i64, serde_json::Value, i64)> = sqlx::query_as(
            "SELECT id, passkey, counter FROM account_passkeys
             WHERE credential_id = $1 AND account_id = $2 AND disabled_at IS NULL
             FOR UPDATE",
        )
        .bind(credential.get_credential_id())
        .bind(account.id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((id, stored, held)) = row else {
            return Err(MfaError::Invalid);
        };
        let mut passkey: Passkey =
            serde_json::from_value(stored).map_err(|e| MfaError::fault(e.into()))?;
        let result = match rp
            .webauthn()
            .finish_passkey_authentication(credential, &state)
        {
            Ok(result) => result,
            Err(WebauthnError::CredentialPossibleCompromise) => {
                return Err(self.disable_cloned(tx, account.id, id).await);
            }
            Err(e) => return Err(refused(&e)),
        };
        if result.cred_id() != passkey.cred_id() {
            return Err(MfaError::Invalid);
        }
        // webauthn-rs compares the counter with the one the ceremony began with; another
        // answer may have stored a higher one since. A counter in use (either side above
        // zero) must rise past the stored one, as webauthn-rs's own check requires.
        let counter = i64::from(result.counter());
        if (counter > 0 || held > 0) && counter <= held {
            return Err(self.disable_cloned(tx, account.id, id).await);
        }
        passkey.update_credential(&result);
        let stored = serde_json::to_value(&passkey).map_err(|e| MfaError::fault(e.into()))?;
        let (eligible, backed_up) = backup_flags(&stored);
        sqlx::query(
            "UPDATE account_passkeys
             SET passkey = $2, counter = $3, backup_eligible = $4, backup_state = $5,
                 last_used_at = now()
             WHERE id = $1",
        )
        .bind(id)
        .bind(&stored)
        .bind(counter)
        .bind(eligible)
        .bind(backed_up)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(id)
    }

    /// Disable the passkey `id` of `account`, whose answer suggests a copy, in `tx`
    /// (which holds its row), and tell the notifier: the error to answer with, which is
    /// [`MfaError::PasskeyCloned`] unless the passkey could not be disabled.
    async fn disable_cloned(
        &self,
        mut tx: sqlx::Transaction<'_, sqlx::Postgres>,
        account: i64,
        id: i64,
    ) -> MfaError {
        let disabled = async {
            sqlx::query("UPDATE account_passkeys SET disabled_at = now() WHERE id = $1")
                .bind(id)
                .execute(&mut *tx)
                .await?;
            tx.commit().await
        }
        .await;
        if let Err(e) = disabled {
            return e.into();
        }
        tracing::warn!(
            account,
            passkey = id,
            "a passkey suspected of being copied was disabled"
        );
        let error = MfaError::PasskeyCloned { passkey: id };
        if let Some(event) = error.event(account) {
            self.notify(&event).await;
        }
        error
    }

    /// The account's passkeys, oldest first, the disabled ones included.
    ///
    /// # Errors
    /// A database fault.
    pub async fn list_passkeys(
        &self,
        pool: &PgPool,
        account: i64,
    ) -> sqlx::Result<Vec<PasskeyInfo>> {
        sqlx::query_as(
            "SELECT id, name, EXTRACT(EPOCH FROM created_at)::bigint AS created_at,
                    EXTRACT(EPOCH FROM last_used_at)::bigint AS last_used_at,
                    backup_eligible, backup_state,
                    EXTRACT(EPOCH FROM disabled_at)::bigint AS disabled_at
             FROM account_passkeys WHERE account_id = $1 ORDER BY id",
        )
        .bind(account)
        .fetch_all(pool)
        .await
    }

    /// Rename one of the account's passkeys. A name is a label, so this needs no
    /// step-up; it needs the account (the one signed in).
    ///
    /// # Errors
    /// [`MfaError::BadName`], [`MfaError::NotEnrolled`] when the account has no such
    /// passkey, or a fault.
    pub async fn rename_passkey(
        &self,
        pool: &PgPool,
        account: &Account,
        passkey: i64,
        name: &str,
    ) -> Result<Event, MfaError> {
        let name = clean_name(name)?;
        let done =
            sqlx::query("UPDATE account_passkeys SET name = $3 WHERE id = $1 AND account_id = $2")
                .bind(passkey)
                .bind(account.id)
                .bind(name)
                .execute(pool)
                .await?;
        if done.rows_affected() == 0 {
            return Err(MfaError::NotEnrolled);
        }
        Ok(Event {
            passkey: Some(passkey),
            ..Event::new(account.id, EventKind::Renamed(Factor::Passkey))
        })
    }

    /// Remove one of the account's passkeys. As with [`remove_totp`](Self::remove_totp):
    /// it needs a [`ChangeProof`] from a signed-in session, the account's last factor
    /// cannot be removed when the policy requires one ([`MfaError::LastFactor`]), the
    /// last factor takes the recovery codes with it, and the session epoch moves on.
    ///
    /// # Errors
    /// [`MfaError::NotEnrolled`] when the account has no such passkey,
    /// [`MfaError::LastFactor`], [`MfaError::NoChallenge`], or a fault.
    pub async fn remove_passkey<T: state::MfaSession>(
        &self,
        pool: &PgPool,
        session: &owt_web::session::Session<T>,
        account: &Account,
        proof: &ChangeProof,
        passkey: i64,
    ) -> Result<Event, MfaError> {
        Self::proof_for(proof, account)?;
        if proof.pending {
            return Err(MfaError::NotEnrolled);
        }
        let mut tx = pool.begin().await?;
        lock_account(&mut tx, account.id).await?;
        let usable: Option<bool> = sqlx::query_scalar(
            "SELECT disabled_at IS NULL FROM account_passkeys WHERE id = $1 AND account_id = $2",
        )
        .bind(passkey)
        .bind(account.id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(usable) = usable else {
            return Err(MfaError::NotEnrolled);
        };
        // A disabled passkey is no factor, so removing it is never removing the last
        // one; the codes go when no passkey or authenticator of any kind is left.
        let count = factor_count(&mut tx, account.id).await?;
        if usable && count <= 1 && self.requires(account) {
            return Err(MfaError::LastFactor);
        }
        let last = count + disabled_count(&mut tx, account.id).await? <= 1;
        sqlx::query("DELETE FROM account_passkeys WHERE id = $1")
            .bind(passkey)
            .execute(&mut *tx)
            .await?;
        if last {
            sqlx::query("DELETE FROM account_recovery_codes WHERE account_id = $1")
                .bind(account.id)
                .execute(&mut *tx)
                .await?;
        }
        let epoch = super::bump_epoch(&mut tx, account.id, account.session_epoch).await?;
        tx.commit().await?;
        let account_now = Account {
            session_epoch: epoch,
            ..account.clone()
        };
        state::reseal(
            session,
            &account_now,
            account.session_epoch,
            false,
            std::time::SystemTime::now(),
        );
        Ok(Event {
            passkey: Some(passkey),
            ..Event::new(account.id, EventKind::Removed(Factor::Passkey))
        })
    }
}

/// The backup-eligible and backup-state flags of a serialized passkey.
fn backup_flags(stored: &serde_json::Value) -> (bool, bool) {
    let flag = |name: &str| {
        stored
            .pointer(&format!("/cred/{name}"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
    };
    (flag("backup_eligible"), flag("backup_state"))
}

/// Hold the account's row for the rest of the transaction, so two changes to its
/// factors (removing the last two at once, say) are made one after the other.
pub(super) async fn lock_account(
    tx: &mut sqlx::PgConnection,
    account: i64,
) -> Result<(), MfaError> {
    let held: Option<i64> = sqlx::query_scalar("SELECT id FROM accounts WHERE id = $1 FOR UPDATE")
        .bind(account)
        .fetch_optional(tx)
        .await?;
    held.map(|_| ()).ok_or(MfaError::NoChallenge)
}

/// How many passkeys of the account are disabled.
async fn disabled_count(tx: &mut sqlx::PgConnection, account: i64) -> Result<i64, MfaError> {
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM account_passkeys WHERE account_id = $1 AND disabled_at IS NOT NULL",
    )
    .bind(account)
    .fetch_one(tx)
    .await?;
    Ok(n)
}

/// How many factors the account has: a confirmed authenticator and its passkeys that
/// are not disabled.
pub(super) async fn factor_count(
    tx: &mut sqlx::PgConnection,
    account: i64,
) -> Result<i64, MfaError> {
    let n: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM account_totp
                 WHERE account_id = $1 AND confirmed_at IS NOT NULL)
              + (SELECT count(*) FROM account_passkeys
                 WHERE account_id = $1 AND disabled_at IS NULL)",
    )
    .bind(account)
    .fetch_one(tx)
    .await?;
    Ok(n)
}
