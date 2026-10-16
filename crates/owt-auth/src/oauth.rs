//! Signing people in with an OAuth 2 provider: the authorization-code flow.
//!
//! 1. [`Client::begin`] builds the redirect to the provider and a [`Pending`] login
//!    (state, and the PKCE verifier where the provider supports it) for the app to keep
//!    in the person's session.
//! 2. The provider redirects back with `code` and `state`. [`Client::complete`] takes
//!    both: it refuses a state that is not the pending login's, or a pending login
//!    begun with another provider, before it trades the code for a token and the token
//!    for the [`Identity`] the provider vouches for.
//!    [`Client::complete_with_tokens`] does the same and also hands back the
//!    [`Tokens`], for an app that calls the provider's APIs as the person.
//! 3. [`Client::refresh`] trades a refresh token for fresh [`Tokens`];
//!    [`Client::client_credentials`] gets the app a token of its own.
//!
//! [`discover`] builds an [`oidc`] provider from its issuer's discovery document.
//!
//! Make the HTTP client with [`http_client`]: it gives up on a provider that stalls
//! and follows no redirects, so the client secret goes only where it was addressed.
//!
//! A [`Provider`] is data: endpoints, scope, and how to read its user-info response.
//! [`google`], [`discord`] and [`twitch`] are presets; [`oidc`] covers any `OpenID`
//! Connect provider (Keycloak, say) from its issuer and that issuer's endpoints.
//! Endpoints are plain fields, so a test can point a preset at a fake server.
//!
//! A person is the pair ([`Provider::key`], [`Identity::uid`]), never their email: a
//! provider lets people change the address, and an address can pass to someone else
//! (a recycled workplace mailbox, a lapsed domain), so the same email is not the same
//! person, at one provider or across two.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// An OAuth 2 provider.
#[derive(Clone, Debug)]
pub struct Provider {
    /// Stable id, in URLs and in the pending login: `google`.
    pub id: &'static str,
    /// The `OpenID` Connect issuer whose subjects these are, for [`oidc`]; `None` for
    /// a preset, whose subjects are scoped by the preset itself.
    pub issuer: Option<String>,
    /// For buttons: `Google`.
    pub name: &'static str,
    /// Where the person is sent to consent.
    pub authorize_url: String,
    /// Where the code is traded for a token.
    pub token_url: String,
    /// Who the token belongs to.
    pub userinfo_url: String,
    /// Space-separated scopes.
    pub scope: &'static str,
    /// Send a PKCE challenge (S256).
    pub pkce: bool,
    /// Send `Client-Id: <client id>` with the user-info request (Twitch's Helix API).
    pub client_id_header: bool,
    /// Read the user-info response.
    pub identity: fn(Value) -> Option<Identity>,
}

impl Provider {
    /// The namespace its subjects are unique in, as stored with an account's linked
    /// identities: the issuer for [`oidc`], else the [`id`](Self::id). Re-pointing an
    /// id at another issuer therefore cannot sign that issuer's `sub` into the
    /// account of the old issuer's person with the same `sub`.
    #[must_use]
    pub fn key(&self) -> &str {
        self.issuer.as_deref().unwrap_or(self.id)
    }
}

/// Who a provider vouches for.
#[derive(Clone, Debug)]
pub struct Identity {
    /// The provider's id for the person: stable, never reassigned. With
    /// [`Provider::key`], the only thing that identifies them.
    pub uid: String,
    /// Their email, if the provider shared one. Contact data, not identity: it can
    /// change, and the same address can belong to someone else later.
    pub email: Option<String>,
    /// The provider checked the person controls that email, now. Says nothing about
    /// who held it before.
    pub email_verified: bool,
    /// What they call themselves there.
    pub display_name: Option<String>,
    /// The whole user-info response, for anything else an app keeps.
    pub extra: Value,
}

fn s(v: &Value, k: &str) -> Option<String> {
    v[k].as_str().map(str::to_owned)
}

/// A subject: present and not empty, or there is no identity.
fn id(v: &Value, k: &str) -> Option<String> {
    s(v, k).filter(|u| !u.is_empty())
}

/// Google, with PKCE.
#[must_use]
pub fn google() -> Provider {
    Provider {
        id: "google",
        name: "Google",
        issuer: None,
        authorize_url: "https://accounts.google.com/o/oauth2/v2/auth".into(),
        token_url: "https://oauth2.googleapis.com/token".into(),
        userinfo_url: "https://openidconnect.googleapis.com/v1/userinfo".into(),
        scope: "profile email",
        pkce: true,
        client_id_header: false,
        identity: oidc_identity,
    }
}

/// Discord, with PKCE.
#[must_use]
pub fn discord() -> Provider {
    Provider {
        id: "discord",
        name: "Discord",
        issuer: None,
        authorize_url: "https://discord.com/api/oauth2/authorize".into(),
        token_url: "https://discord.com/api/oauth2/token".into(),
        userinfo_url: "https://discord.com/api/users/@me".into(),
        scope: "identify email",
        pkce: true,
        client_id_header: false,
        identity: |info| {
            Some(Identity {
                uid: id(&info, "id")?,
                email: s(&info, "email"),
                email_verified: info["verified"].as_bool().unwrap_or(false),
                display_name: s(&info, "global_name").or_else(|| s(&info, "username")),
                extra: info,
            })
        },
    }
}

/// Twitch.
#[must_use]
pub fn twitch() -> Provider {
    Provider {
        id: "twitch",
        name: "Twitch",
        issuer: None,
        authorize_url: "https://id.twitch.tv/oauth2/authorize".into(),
        token_url: "https://id.twitch.tv/oauth2/token".into(),
        userinfo_url: "https://api.twitch.tv/helix/users".into(),
        scope: "user:read:email",
        pkce: false,
        client_id_header: true,
        identity: |info| {
            let user = info["data"][0].clone();
            Some(Identity {
                uid: id(&user, "id")?,
                email: s(&user, "email"),
                // Twitch only returns a verified email.
                email_verified: user["email"].is_string(),
                display_name: s(&user, "display_name"),
                extra: user,
            })
        },
    }
}

/// Any `OpenID` Connect provider, from its issuer (`https://sso.example/realms/x`) and
/// the endpoints its discovery document names. Linked identities are keyed by the
/// issuer (see [`Provider::key`]), so `id` only names it in URLs.
///
/// The issuer is operator configuration, never input from a tenant or a visitor: it
/// is the namespace the provider's subjects are trusted in. [`Client::complete`]
/// therefore holds the provider to it, refusing an ID token whose `iss` is another
/// issuer's, whose `aud` is not this client, or whose `sub` is not the user-info
/// response's.
///
/// # Errors
///
/// [`Error::Config`] when the issuer or an endpoint is not an absolute `https` URL
/// (`http` is allowed for `localhost`, `127.0.0.1` and `[::1]`, for development),
/// carries credentials or a fragment, or (the issuer) a query, and when the issuer
/// is not written in its canonical form (a lower-case host, no default port, as
/// the issuer itself writes its `iss`): `https://SSO.example:443/realms/x` would
/// match no token, and would be a second key for the same people. A trailing `/`
/// on the issuer is dropped, so `…/realms/x` and `…/realms/x/` are one key.
///
/// An issuer whose `iss` varies (a multi-tenant endpoint that writes each tenant's
/// own issuer) refuses every sign-in: configure one provider per tenant.
pub fn oidc(
    id: &'static str,
    name: &'static str,
    issuer: &str,
    authorize: &str,
    token: &str,
    userinfo: &str,
) -> Result<Provider, Error> {
    let issuer = issuer.trim_end_matches('/');
    let parsed = checked_url("issuer", issuer)?;
    if parsed.query().is_some() {
        return Err(Error::Config(format!("the issuer {issuer:?} has a query")));
    }
    let canonical = parsed.as_str().trim_end_matches('/');
    if canonical != issuer {
        return Err(Error::Config(format!(
            "the issuer {issuer:?} is not in canonical form: write {canonical:?}"
        )));
    }
    for (what, url) in [
        ("authorize", authorize),
        ("token", token),
        ("userinfo", userinfo),
    ] {
        checked_url(what, url)?;
    }
    Ok(Provider {
        id,
        name,
        issuer: Some(issuer.into()),
        authorize_url: authorize.into(),
        token_url: token.into(),
        userinfo_url: userinfo.into(),
        scope: "openid profile email",
        pkce: true,
        client_id_header: false,
        identity: oidc_identity,
    })
}

/// An [`oidc`] provider read from its issuer's discovery document, and where it
/// signs people out.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Discovered {
    /// The provider, held to the same rules as one [`oidc`] builds.
    pub provider: Provider,
    /// `end_session_endpoint` (RP-Initiated Logout), if the issuer has one.
    pub end_session: Option<String>,
}

/// Build an [`oidc`] provider from `<issuer>/.well-known/openid-configuration`.
///
/// `http` is [`http_client`]: the document is fetched without following a redirect,
/// as the endpoints it names will be. The document must be the issuer's own
/// (`OpenID` Connect Discovery §4.3; a trailing `/` aside, as [`oidc`] drops it), and
/// name authorization, token and user-info endpoints.
///
/// # Errors
///
/// [`Error::Http`] if the document cannot be fetched or read, [`Error::Redirected`]
/// if it is somewhere else, and [`Error::Config`] if it names another issuer, lacks
/// an endpoint, or names one [`oidc`] refuses (`end_session_endpoint` included).
pub async fn discover(
    http: &reqwest::Client,
    id: &'static str,
    name: &'static str,
    issuer: &str,
) -> Result<Discovered, Error> {
    let issuer = issuer.trim_end_matches('/');
    checked_url("issuer", issuer)?;
    let url = format!("{issuer}/.well-known/openid-configuration");
    let res = http
        .get(&url)
        .header("accept", "application/json")
        .send()
        .await?;
    let doc: Value = not_redirected(res, &url)?
        .error_for_status()?
        .json()
        .await?;
    if doc["issuer"].as_str().map(|i| i.trim_end_matches('/')) != Some(issuer) {
        return Err(Error::Config(format!(
            "the discovery document at {url:?} is not {issuer:?}'s"
        )));
    }
    let endpoint = |k: &str| {
        doc[k]
            .as_str()
            .ok_or_else(|| Error::Config(format!("the discovery document has no {k}")))
    };
    let provider = oidc(
        id,
        name,
        issuer,
        endpoint("authorization_endpoint")?,
        endpoint("token_endpoint")?,
        endpoint("userinfo_endpoint")?,
    )?;
    let end_session = match doc["end_session_endpoint"].as_str() {
        Some(u) => Some(checked_url("end_session", u)?.into()),
        None => None,
    };
    Ok(Discovered {
        provider,
        end_session,
    })
}

/// An absolute `https` URL (or `http` on the loopback host) with no credentials and
/// no fragment.
fn checked_url(what: &str, raw: &str) -> Result<url::Url, Error> {
    let bad = |why: &str| Error::Config(format!("the {what} URL {raw:?} {why}"));
    let url = url::Url::parse(raw).map_err(|_| bad("is not an absolute URL"))?;
    let loopback = match url.host() {
        None => return Err(bad("has no host")),
        Some(url::Host::Domain(d)) => d == "localhost",
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
    };
    match url.scheme() {
        "https" => {}
        "http" if loopback => {}
        _ => return Err(bad("is not https")),
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(bad("carries credentials"));
    }
    if url.fragment().is_some() {
        return Err(bad("has a fragment"));
    }
    Ok(url)
}

/// The standard claims of an OIDC user-info response.
fn oidc_identity(info: Value) -> Option<Identity> {
    Some(Identity {
        uid: id(&info, "sub")?,
        email: s(&info, "email"),
        email_verified: info["email_verified"].as_bool().unwrap_or(false),
        display_name: s(&info, "name").or_else(|| s(&info, "preferred_username")),
        extra: info,
    })
}

/// A sign-in waiting for its callback. Keep it in the person's session; it is useless
/// to anyone else. Its `Debug` leaves out the state and the verifier.
#[derive(Clone, Serialize, Deserialize)]
pub struct Pending {
    /// The [`Provider::id`] it was begun with: a callback for one provider cannot
    /// complete a login begun with another (the mix-up attack).
    pub provider: String,
    /// The `state` sent out, to be returned unchanged.
    pub state: String,
    /// The PKCE verifier, if a challenge was sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier: Option<String>,
}

impl Pending {
    /// The callback's `state` is the one sent out (compared in constant time).
    #[must_use]
    pub fn matches(&self, state: &str) -> bool {
        bool::from(self.state.as_bytes().ct_eq(state.as_bytes()))
    }
}

/// What a token endpoint granted. Its `Debug` leaves out every token.
///
/// Lifetimes are as the endpoint sent them, relative to when it answered: turn them
/// into instants as soon as the call returns.
#[derive(Clone)]
#[non_exhaustive]
pub struct Tokens {
    /// The bearer token for the provider's APIs.
    pub access: String,
    /// `expires_in`, if the response gave it (see [`Tokens::access_lifetime`]).
    pub expires_in: Option<std::time::Duration>,
    /// A refresh token, if one was issued. A refresh may answer without one, which
    /// means the one already held stays good (RFC 6749 §6).
    pub refresh: Option<String>,
    /// `refresh_expires_in` (Keycloak's), if the response gave one other than `0`;
    /// `None` is "no schedule given", not "never".
    pub refresh_expires_in: Option<std::time::Duration>,
    /// The scopes granted, if the response says (RFC 6749 §5.1).
    pub scope: Option<String>,
    /// The ID token as sent, already held to the issuer, client and subject for an
    /// [`oidc`] provider: for `id_token_hint` at sign-out.
    pub id_token: Option<String>,
}

impl Tokens {
    /// The lifetime assumed when a response gives no `expires_in`: short, so the
    /// worst case is a refresh sooner than needed.
    pub const ASSUMED_LIFETIME: std::time::Duration = std::time::Duration::from_secs(300);

    /// An access token alone, the other fields to be set as needed: for a test, or
    /// a token that came from elsewhere.
    #[must_use]
    pub fn bearer(access: impl Into<String>) -> Self {
        Self {
            access: access.into(),
            expires_in: None,
            refresh: None,
            refresh_expires_in: None,
            scope: None,
            id_token: None,
        }
    }

    /// How long the access token lasts: `expires_in`, or [`Self::ASSUMED_LIFETIME`].
    #[must_use]
    pub fn access_lifetime(&self) -> std::time::Duration {
        self.expires_in.unwrap_or(Self::ASSUMED_LIFETIME)
    }

    /// Read a token response.
    fn read(v: &Value) -> Result<Self, Error> {
        // A lifetime as RFC 6749 writes it (a number of seconds), or as some
        // endpoints do (a numeric string); a negative one has already run out.
        let secs = |k: &str| -> Option<std::time::Duration> {
            let n = match &v[k] {
                Value::Number(n) => n.as_i64(),
                Value::String(s) => s.trim().parse::<i64>().ok(),
                _ => None,
            }?;
            Some(std::time::Duration::from_secs(n.max(0).cast_unsigned()))
        };
        let access = v["access_token"]
            .as_str()
            .filter(|a| !a.is_empty())
            .ok_or(Error::NoToken)?;
        Ok(Self {
            access: access.to_owned(),
            expires_in: secs("expires_in"),
            refresh: s(v, "refresh_token").filter(|r| !r.is_empty()),
            refresh_expires_in: secs("refresh_expires_in").filter(|d| !d.is_zero()),
            scope: s(v, "scope"),
            id_token: s(v, "id_token"),
        })
    }
}

impl std::fmt::Debug for Tokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tokens")
            .field("expires_in", &self.expires_in)
            .field("refresh", &self.refresh.is_some())
            .field("refresh_expires_in", &self.refresh_expires_in)
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

/// A provider with this app's registration at it.
#[derive(Clone)]
pub struct Client {
    /// The provider.
    pub provider: Provider,
    /// The app's client id there.
    pub client_id: String,
    /// The app's client secret there.
    pub client_secret: String,
    /// This app's callback URL, exactly as registered.
    pub redirect_uri: String,
}

impl std::fmt::Debug for Pending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pending")
            .field("provider", &self.provider)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for Client {
    /// Without the secret: a `{:?}` in a log line must not publish it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("provider", &self.provider.id)
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .finish_non_exhaustive()
    }
}

/// An HTTP client for talking to providers: ten seconds for a whole exchange, five to
/// connect, and no redirects followed (a token endpoint that redirects would be sent
/// the client secret again, wherever it pointed).
pub fn http_client() -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .connect_timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
}

/// Why a sign-in failed.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The callback's `state` is not the pending login's: not this browser's sign-in.
    #[error("the callback's state does not match the sign-in that was begun")]
    State,
    /// The pending login was begun with another provider.
    #[error("the sign-in was begun with another provider")]
    Provider,
    /// The provider could not be reached or refused the exchange.
    #[error("talking to the provider: {0}")]
    Http(#[from] reqwest::Error),
    /// The token response carried no access token.
    #[error("the token response had no access_token")]
    NoToken,
    /// The user-info response carried no id.
    #[error("the user-info response had no id")]
    NoIdentity,
    /// An `OpenID` Connect provider's ID token is missing, unreadable, or not for this
    /// issuer, this client and the user-info response's subject.
    #[error("the ID token is not this issuer's, for this client and subject: {0}")]
    IdToken(&'static str),
    /// A provider's configuration is unusable (see [`oidc`]).
    #[error("provider configuration: {0}")]
    Config(String),
    /// A configured URL is not a URL.
    #[error("bad provider URL: {0}")]
    Url(#[from] url::ParseError),
    /// The token or user-info endpoint answered with a redirect, or the client
    /// followed one: use [`http_client`], which follows none.
    #[error("the provider's endpoint redirected")]
    Redirected,
}

/// The response, unless it is a redirect or the end of one.
fn not_redirected(res: reqwest::Response, asked: &str) -> Result<reqwest::Response, Error> {
    let same = url::Url::parse(asked).is_ok_and(|u| &u == res.url());
    if res.status().is_redirection() || !same {
        return Err(Error::Redirected);
    }
    Ok(res)
}

impl Error {
    /// The provider answered and said no: a 4xx other than 408 or 429 (an expired,
    /// revoked or unknown grant answers `400 invalid_grant`), or a token response
    /// with no access token. For a refresh, that means the person signs in again; an
    /// outage, a timeout or a throttle is not this, and the grant may still be good.
    #[must_use]
    pub fn is_rejected(&self) -> bool {
        match self {
            Self::NoToken => true,
            Self::Http(e) => e.status().is_some_and(|s| {
                s.is_client_error()
                    && s != reqwest::StatusCode::REQUEST_TIMEOUT
                    && s != reqwest::StatusCode::TOO_MANY_REQUESTS
            }),
            _ => false,
        }
    }
}

impl Client {
    /// The URL to send the person to, and the login to remember until they return.
    pub fn begin(&self) -> Result<(String, Pending), Error> {
        let state = crate::random_token(32);
        let mut url = url::Url::parse(&self.provider.authorize_url)?;
        url.query_pairs_mut()
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", &self.redirect_uri)
            .append_pair("response_type", "code")
            .append_pair("scope", self.provider.scope)
            .append_pair("state", &state);
        let verifier = self.provider.pkce.then(|| crate::random_token(64));
        if let Some(v) = &verifier {
            let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(v.as_bytes()));
            url.query_pairs_mut()
                .append_pair("code_challenge", &challenge)
                .append_pair("code_challenge_method", "S256");
        }
        let provider = self.provider.id.to_owned();
        Ok((
            url.into(),
            Pending {
                provider,
                state,
                verifier,
            },
        ))
    }

    /// Trade the callback's `code` for the person's identity, if its `state` is the
    /// pending login's and that login was begun with this provider.
    ///
    /// `http` is [`http_client`] or one built like it, following no redirects: a
    /// client that follows one re-sends the client secret wherever it points, and an
    /// ID token is trusted for having come straight from the token endpoint. A
    /// redirect, followed or not, is [`Error::Redirected`].
    pub async fn complete(
        &self,
        http: &reqwest::Client,
        pending: &Pending,
        state: &str,
        code: &str,
    ) -> Result<Identity, Error> {
        self.complete_with_tokens(http, pending, state, code)
            .await
            .map(|(who, _)| who)
    }

    /// [`complete`](Self::complete), also handing back what the token endpoint
    /// granted: for an app that calls the provider's APIs as the person. Every check
    /// `complete` makes is made first; the tokens are only ever a signed-in person's.
    pub async fn complete_with_tokens(
        &self,
        http: &reqwest::Client,
        pending: &Pending,
        state: &str,
        code: &str,
    ) -> Result<(Identity, Tokens), Error> {
        if pending.provider != self.provider.id {
            return Err(Error::Provider);
        }
        self.checked_provider()?;
        if !pending.matches(state) {
            return Err(Error::State);
        }
        let mut form: Vec<(&str, &str)> = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &self.redirect_uri),
        ];
        if let Some(v) = &pending.verifier {
            form.push(("code_verifier", v));
        }
        let tokens = self.token_request(http, &form).await?;
        let id_token = match &self.provider.issuer {
            Some(issuer) => Some(
                self.id_token_claims(
                    issuer,
                    tokens
                        .id_token
                        .as_deref()
                        .ok_or(Error::IdToken("the token response has none"))?,
                )?,
            ),
            None => None,
        };
        let mut req = http
            .get(&self.provider.userinfo_url)
            .bearer_auth(&tokens.access);
        if self.provider.client_id_header {
            req = req.header("Client-Id", &self.client_id);
        }
        let res = req.send().await?;
        let info: Value = not_redirected(res, &self.provider.userinfo_url)?
            .error_for_status()?
            .json()
            .await?;
        let identity = (self.provider.identity)(info).ok_or(Error::NoIdentity)?;
        // OIDC Core 5.3.2: the user-info `sub` must be the ID token's.
        if let Some(claims) = id_token
            && claims["sub"].as_str() != Some(identity.uid.as_str())
        {
            return Err(Error::IdToken("its sub is not the user-info response's"));
        }
        Ok((identity, tokens))
    }

    /// Trade a refresh token for fresh [`Tokens`], for the person whose
    /// [`Identity::uid`] is `subject`.
    ///
    /// An [`oidc`] provider need not send an ID token with a refresh; one it sends is
    /// held to the issuer and this client like a sign-in's, and must be about
    /// `subject` (OIDC Core 12.2). The answer may carry no refresh token: keep the
    /// one held. [`Error::is_rejected`] says whether the grant is gone, so the person
    /// signs in again, or the provider is just unavailable.
    pub async fn refresh(
        &self,
        http: &reqwest::Client,
        refresh_token: &str,
        subject: &str,
    ) -> Result<Tokens, Error> {
        self.checked_provider()?;
        let tokens = self
            .token_request(
                http,
                &[
                    ("grant_type", "refresh_token"),
                    ("refresh_token", refresh_token),
                ],
            )
            .await?;
        if let (Some(issuer), Some(raw)) = (&self.provider.issuer, tokens.id_token.as_deref()) {
            let claims = self.id_token_claims(issuer, raw)?;
            if claims["sub"].as_str() != Some(subject) {
                return Err(Error::IdToken("its sub is not the signed-in person's"));
            }
        }
        Ok(tokens)
    }

    /// A token for the app itself (the `client_credentials` grant), with `scope`, or
    /// the client's default scopes for `None`. There is no person, so no identity,
    /// and an ID token in the answer is ignored.
    pub async fn client_credentials(
        &self,
        http: &reqwest::Client,
        scope: Option<&str>,
    ) -> Result<Tokens, Error> {
        self.checked_provider()?;
        let mut form = vec![("grant_type", "client_credentials")];
        if let Some(scope) = scope {
            form.push(("scope", scope));
        }
        let mut tokens = self.token_request(http, &form).await?;
        tokens.id_token = None;
        Ok(tokens)
    }

    /// An OIDC provider's ID token is trusted for having come straight from its
    /// token endpoint over verified TLS: hold a provider built or changed by hand to
    /// what [`oidc`] checks, before anything is sent.
    fn checked_provider(&self) -> Result<(), Error> {
        if let Some(issuer) = &self.provider.issuer {
            if issuer.is_empty() || issuer.ends_with('/') || !issuer.contains("://") {
                return Err(Error::Config(format!(
                    "the issuer {issuer:?} is not oidc()'s"
                )));
            }
            checked_url("issuer", issuer)?;
            checked_url("token", &self.provider.token_url)?;
            checked_url("userinfo", &self.provider.userinfo_url)?;
        }
        Ok(())
    }

    /// POST `form` and this client's credentials to the token endpoint, and read
    /// the answer.
    async fn token_request(
        &self,
        http: &reqwest::Client,
        form: &[(&str, &str)],
    ) -> Result<Tokens, Error> {
        let mut form = form.to_vec();
        form.push(("client_id", &self.client_id));
        form.push(("client_secret", &self.client_secret));
        let res = http
            .post(&self.provider.token_url)
            .header("accept", "application/json")
            .form(&form)
            .send()
            .await?;
        let token: Value = not_redirected(res, &self.provider.token_url)?
            .error_for_status()?
            .json()
            .await?;
        Tokens::read(&token)
    }

    /// The claims of the token response's ID token, once its `iss` is `issuer`, its
    /// `aud` names this client, and it has not expired. The token came straight from
    /// the token endpoint over TLS (no redirects followed), which OIDC Core 3.1.3.7
    /// accepts in place of checking its signature.
    fn id_token_claims(&self, issuer: &str, raw: &str) -> Result<Value, Error> {
        let mut parts = raw.split('.');
        let (Some(_), Some(payload), Some(_), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(Error::IdToken("it is not a JWT"));
        };
        let claims: Value = URL_SAFE_NO_PAD
            .decode(payload.trim_end_matches('='))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .ok_or(Error::IdToken("its claims are unreadable"))?;
        if claims["iss"].as_str().map(|i| i.trim_end_matches('/')) != Some(issuer) {
            return Err(Error::IdToken("its iss is another issuer"));
        }
        let (for_us, several) = match &claims["aud"] {
            Value::String(a) => (*a == self.client_id, false),
            Value::Array(all) => (
                all.iter().any(|a| a.as_str() == Some(&self.client_id)),
                all.len() > 1,
            ),
            _ => (false, false),
        };
        if !for_us {
            return Err(Error::IdToken("its aud is not this client"));
        }
        // OIDC Core 3.1.3.7: a token for several audiences names the one it was
        // issued to, and an `azp` that is present is this client.
        match claims["azp"].as_str() {
            Some(azp) if azp != self.client_id => {
                return Err(Error::IdToken("its azp is another client"));
            }
            None if several => {
                return Err(Error::IdToken("it has several audiences and no azp"));
            }
            _ => {}
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        // A minute's leeway for clock skew.
        if claims["exp"]
            .as_u64()
            .is_none_or(|exp| exp.saturating_add(60) < now)
        {
            return Err(Error::IdToken("it has expired"));
        }
        Ok(claims)
    }
}

#[cfg(test)]
mod tests {
    use axum::Json;
    use axum::routing::{get, post};

    use super::*;

    fn client(provider: Provider) -> Client {
        Client {
            provider,
            client_id: "cid".into(),
            client_secret: "s".into(),
            redirect_uri: "https://example.com/auth/google/callback".into(),
        }
    }

    #[test]
    fn begin_sends_state_and_a_pkce_challenge() {
        let (url, pending) = client(google()).begin().unwrap();
        assert!(url.starts_with("https://accounts.google.com/o/oauth2/v2/auth?client_id=cid"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("redirect_uri=https%3A%2F%2Fexample.com%2Fauth%2Fgoogle%2Fcallback"));
        let parsed = url::Url::parse(&url).unwrap();
        let state = parsed
            .query_pairs()
            .find(|(k, _)| k == "state")
            .unwrap()
            .1
            .into_owned();
        assert!(pending.matches(&state));
        assert!(!pending.matches("other"));
        assert!(pending.verifier.is_some());
        assert_eq!(pending.provider, "google");
        assert!(client(discord()).begin().unwrap().1.verifier.is_some());
        assert!(client(twitch()).begin().unwrap().1.verifier.is_none());
    }

    /// A stored pending login without the provider it was begun with does not load
    /// as "any provider": the mix-up check needs the field, so a
    /// session carrying such a value has no pending login and begins again.
    #[test]
    fn a_stored_pending_login_without_its_provider_does_not_load() {
        let (_, pending) = client(google()).begin().unwrap();
        let whole = serde_json::to_value(&pending).unwrap();
        assert!(serde_json::from_value::<Pending>(whole.clone()).is_ok());
        for field in ["provider", "state"] {
            let mut partial = whole.clone();
            partial.as_object_mut().unwrap().remove(field);
            assert!(
                serde_json::from_value::<Pending>(partial).is_err(),
                "a pending login loaded without {field}"
            );
        }
    }

    #[tokio::test]
    async fn complete_trades_the_code_for_an_identity() {
        let fake = axum::Router::new()
            .route(
                "/token",
                post(|body: String| async move {
                    assert!(
                        body.contains("code=abc") && body.contains("code_verifier="),
                        "{body}"
                    );
                    Json(serde_json::json!({"access_token": "t"}))
                }),
            )
            .route(
                "/userinfo",
                get(|| async {
                    Json(serde_json::json!({"sub": "42", "email": "a@b.c", "email_verified": true}))
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, fake).await });
        let c = client(Provider {
            token_url: format!("{base}/token"),
            userinfo_url: format!("{base}/userinfo"),
            ..google()
        });
        let (_, pending) = c.begin().unwrap();
        let http = http_client().unwrap();
        assert!(matches!(
            c.complete(&http, &pending, "not-the-state", "abc").await,
            Err(Error::State)
        ));
        let elsewhere = client(discord()).begin().unwrap().1;
        assert!(matches!(
            c.complete(&http, &elsewhere, &elsewhere.state, "abc").await,
            Err(Error::Provider)
        ));
        let who = c
            .complete(&http, &pending, &pending.state, "abc")
            .await
            .unwrap();
        assert_eq!(
            (who.uid.as_str(), who.email.as_deref(), who.email_verified),
            ("42", Some("a@b.c"), true)
        );
    }

    #[test]
    fn identities_are_keyed_by_the_issuer_where_there_is_one() {
        assert_eq!(google().key(), "google");
        let sso = oidc(
            "sso",
            "SSO",
            "https://sso.example/realms/x/",
            "https://sso.example/a",
            "https://sso.example/t",
            "https://sso.example/u",
        )
        .unwrap();
        assert_eq!(sso.key(), "https://sso.example/realms/x");
        let (_, pending) = client(sso).begin().unwrap();
        assert_eq!(pending.provider, "sso");
    }

    /// An issuer is an https URL, so no OIDC key can be a preset's (`google`), empty,
    /// or another scheme's; endpoints are https too, so the token's TLS vouches for it.
    #[test]
    fn an_issuer_or_endpoint_that_is_not_an_https_url_is_refused() {
        let ok = "https://sso.example/x";
        let with = |issuer: &str, token: &str| oidc("sso", "SSO", issuer, ok, token, ok);
        for issuer in [
            "",
            "google",
            "discord",
            "/",
            "sso.example",
            "http://sso.example",
            "ftp://sso.example",
            "https://user:pw@sso.example",
            "https://sso.example/x?tenant=1",
            "https://sso.example/x#f",
            "https://SSO.example/x",
            "https://sso.example:443/x",
            "https://sso.example/a/../x",
        ] {
            assert!(
                matches!(with(issuer, ok), Err(Error::Config(_))),
                "issuer {issuer:?}"
            );
        }
        for token in ["http://sso.example/t", "//sso.example/t", "t"] {
            assert!(with(ok, token).is_err(), "token {token:?}");
        }
        for dev in [
            "http://localhost:8080/realms/x",
            "http://127.0.0.1:8080/x",
            "http://[::1]/x",
        ] {
            assert!(with(dev, dev).is_ok(), "{dev}");
        }
        assert!(with("http://localhost.evil.example/x", ok).is_err());
    }

    #[test]
    fn a_preset_refuses_an_empty_subject() {
        for (provider, info) in [
            (google(), serde_json::json!({"sub": ""})),
            (google(), serde_json::json!({"email": "a@b.c"})),
            (discord(), serde_json::json!({"id": ""})),
            (twitch(), serde_json::json!({"data": [{"id": ""}]})),
            (twitch(), serde_json::json!({"data": []})),
        ] {
            assert!((provider.identity)(info).is_none(), "{}", provider.id);
        }
        assert!((discord().identity)(serde_json::json!({"id": "7"})).is_some());
    }

    fn jwt(claims: &Value) -> String {
        let part = |v: &Value| URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap());
        format!(
            "{}.{}.sig",
            part(&serde_json::json!({"alg": "RS256"})),
            part(claims)
        )
    }

    /// A provider built by hand with an issuer `oidc` would refuse is refused at
    /// the exchange, before any request.
    #[tokio::test]
    async fn a_hand_built_oidc_provider_is_held_to_oidcs_rules() {
        let http = http_client().unwrap();
        for (issuer, token) in [
            ("google", "https://sso.example/t"),
            ("https://sso.example/x/", "https://sso.example/t"),
            ("https://sso.example/x", "http://sso.example/t"),
        ] {
            let c = client(Provider {
                issuer: Some(issuer.into()),
                token_url: token.into(),
                ..google()
            });
            let (_, pending) = c.begin().unwrap();
            assert!(
                matches!(
                    c.complete(&http, &pending, &pending.state, "abc").await,
                    Err(Error::Config(_))
                ),
                "{issuer} {token}"
            );
        }
    }

    /// An OIDC provider is held to its issuer: an ID token from another issuer, for
    /// another client, about another subject, or stale, refuses the sign-in.
    #[tokio::test]
    async fn an_oidc_sign_in_needs_the_issuers_id_token_for_this_client_and_subject() {
        use std::sync::{Arc, Mutex};
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let good = serde_json::json!({
            "iss": "https://sso.example/realms/x", "aud": ["cid", "other"], "azp": "cid",
            "sub": "42", "exp": now + 300,
        });
        let id_token: Arc<Mutex<Option<String>>> = Arc::default();
        let served = id_token.clone();
        let fake = axum::Router::new()
            .route(
                "/token",
                post(move || {
                    let t = served.lock().unwrap().clone();
                    async move { Json(serde_json::json!({"access_token": "t", "id_token": t})) }
                }),
            )
            .route(
                "/userinfo",
                get(|| async { Json(serde_json::json!({"sub": "42"})) }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, fake).await });
        let c = client(
            oidc(
                "sso",
                "SSO",
                "https://sso.example/realms/x",
                "https://sso.example/a",
                &format!("{base}/token"),
                &format!("{base}/userinfo"),
            )
            .unwrap(),
        );
        let http = http_client().unwrap();
        let attempt = |token: Option<String>| {
            *id_token.lock().unwrap() = token;
            let (c, http) = (c.clone(), http.clone());
            async move {
                let (_, pending) = c.begin().unwrap();
                c.complete_with_tokens(&http, &pending, &pending.state, "abc")
                    .await
                    .map(|(who, _)| who)
            }
        };
        assert_eq!(attempt(Some(jwt(&good))).await.unwrap().uid, "42");
        let mut slash = good.clone();
        slash["iss"] = "https://sso.example/realms/x/".into();
        assert!(attempt(Some(jwt(&slash))).await.is_ok());
        // The far future does not overflow the leeway.
        let mut far = good.clone();
        far["exp"] = u64::MAX.into();
        assert!(attempt(Some(jwt(&far))).await.is_ok());
        assert!(matches!(attempt(None).await, Err(Error::IdToken(_))));
        assert!(matches!(
            attempt(Some("not-a-jwt".into())).await,
            Err(Error::IdToken(_))
        ));
        for (claim, value) in [
            ("iss", serde_json::json!("https://evil.example/realms/x")),
            ("iss", Value::Null),
            ("aud", serde_json::json!("other")),
            ("aud", serde_json::json!(["other"])),
            ("sub", serde_json::json!("43")),
            ("exp", serde_json::json!(now - 3600)),
            ("exp", Value::Null),
            ("azp", serde_json::json!("other")),
            ("azp", Value::Null),
        ] {
            let mut bad = good.clone();
            bad[claim] = value.clone();
            assert!(
                matches!(attempt(Some(jwt(&bad))).await, Err(Error::IdToken(_))),
                "{claim} = {value}"
            );
        }
    }

    #[test]
    fn debug_output_keeps_the_secret() {
        let mut c = client(google());
        c.client_secret = "hunter2-secret".into();
        assert!(!format!("{c:?}").contains("hunter2"));
    }

    #[test]
    fn debug_output_still_says_which() {
        let c = client(google());
        let shown = format!("{c:?}");
        assert!(shown.contains("google") && shown.contains("cid"), "{shown}");
        let (_, pending) = c.begin().unwrap();
        let shown = format!("{pending:?}");
        assert!(shown.contains("google"), "{shown}");
        assert!(!shown.contains(&pending.state));
        assert!(!shown.contains(pending.verifier.as_deref().unwrap()));
    }

    /// A token endpoint that redirects would be sent the client secret again,
    /// wherever it pointed: the client must not follow.
    #[tokio::test]
    async fn the_exchange_follows_no_redirect() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        let followed = Arc::new(AtomicUsize::new(0));
        let f = followed.clone();
        let fake = axum::Router::new()
            .route(
                "/token",
                post(|| async { axum::response::Redirect::temporary("/elsewhere") }),
            )
            .route(
                "/elsewhere",
                post(move |body: String| {
                    f.fetch_add(1, Ordering::SeqCst);
                    async move {
                        assert!(!body.contains("client_secret"), "the secret followed");
                        Json(serde_json::json!({"access_token": "t"}))
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, fake).await });
        let c = client(Provider {
            token_url: format!("{base}/token"),
            userinfo_url: format!("{base}/userinfo"),
            ..google()
        });
        let (_, pending) = c.begin().unwrap();
        let outcome = c
            .complete(&http_client().unwrap(), &pending, &pending.state, "abc")
            .await;
        assert!(outcome.is_err());
        assert_eq!(followed.load(Ordering::SeqCst), 0);
    }

    /// A provider that never answers costs ten seconds, not a connection for ever.
    #[tokio::test]
    async fn the_exchange_gives_up_on_a_silent_provider() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        // Accepts and says nothing.
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((socket, _)) = listener.accept().await {
                held.push(socket);
            }
        });
        let c = client(Provider {
            token_url: format!("{base}/token"),
            ..google()
        });
        let (_, pending) = c.begin().unwrap();
        let started = std::time::Instant::now();
        let outcome = c
            .complete(&http_client().unwrap(), &pending, &pending.state, "abc")
            .await;
        assert!(matches!(outcome, Err(Error::Http(e)) if e.is_timeout()));
        assert!(started.elapsed() < std::time::Duration::from_secs(15));
    }

    async fn serve(fake: axum::Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, fake).await });
        base
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    const ISSUER: &str = "https://sso.example/realms/x";

    fn sso(base: &str) -> Client {
        client(
            oidc(
                "sso",
                "SSO",
                ISSUER,
                "https://sso.example/a",
                &format!("{base}/token"),
                &format!("{base}/userinfo"),
            )
            .unwrap(),
        )
    }

    fn id_token(sub: &str) -> Value {
        serde_json::json!({"iss": ISSUER, "aud": "cid", "sub": sub, "exp": now() + 300})
    }

    #[tokio::test]
    async fn complete_with_tokens_hands_back_the_token_set() {
        let token = jwt(&id_token("42"));
        let served = token.clone();
        let base = serve(
            axum::Router::new()
                .route(
                    "/token",
                    post(move || {
                        let t = served.clone();
                        async move {
                            Json(serde_json::json!({
                                "access_token": "at", "expires_in": 900, "refresh_token": "rt",
                                "refresh_expires_in": 0, "scope": "openid api", "id_token": t,
                            }))
                        }
                    }),
                )
                .route(
                    "/userinfo",
                    get(|| async { Json(serde_json::json!({"sub": "42"})) }),
                ),
        )
        .await;
        let c = sso(&base);
        let http = http_client().unwrap();
        let (_, pending) = c.begin().unwrap();
        let (who, tokens) = c
            .complete_with_tokens(&http, &pending, &pending.state, "abc")
            .await
            .unwrap();
        assert_eq!(who.uid, "42");
        assert_eq!(tokens.access, "at");
        assert_eq!(tokens.expires_in, Some(std::time::Duration::from_secs(900)));
        assert_eq!(tokens.refresh.as_deref(), Some("rt"));
        assert_eq!(tokens.refresh_expires_in, None);
        assert_eq!(tokens.scope.as_deref(), Some("openid api"));
        assert_eq!(tokens.id_token.as_deref(), Some(token.as_str()));
        let (_, pending) = c.begin().unwrap();
        let alone = c.complete(&http, &pending, &pending.state, "abc").await;
        assert_eq!(alone.unwrap().uid, "42");
    }

    #[test]
    fn lifetimes_are_read_as_providers_write_them() {
        use std::time::Duration;
        let read = |v: Value| Tokens::read(&v);
        let t = read(serde_json::json!({"access_token": "a", "expires_in": 900})).unwrap();
        assert_eq!(t.access_lifetime(), Duration::from_secs(900));
        let t = read(serde_json::json!({"access_token": "a", "expires_in": "900"})).unwrap();
        assert_eq!(t.expires_in, Some(Duration::from_secs(900)));
        let t = read(serde_json::json!({"access_token": "a", "expires_in": -5})).unwrap();
        assert_eq!(t.expires_in, Some(Duration::ZERO));
        let t = read(serde_json::json!({"access_token": "a"})).unwrap();
        assert_eq!(
            (t.expires_in, t.access_lifetime()),
            (None, Tokens::ASSUMED_LIFETIME)
        );
        assert_eq!(t.refresh, None);
        let t = read(serde_json::json!({
            "access_token": "a", "refresh_token": "r", "refresh_expires_in": 1800,
        }))
        .unwrap();
        assert_eq!(t.refresh_expires_in, Some(Duration::from_secs(1800)));
        let t = read(serde_json::json!({"access_token": "a", "refresh_expires_in": 0})).unwrap();
        assert_eq!(t.refresh_expires_in, None);
        for bad in [
            serde_json::json!({}),
            serde_json::json!({"access_token": ""}),
            serde_json::json!({"access_token": 7}),
        ] {
            assert!(matches!(read(bad), Err(Error::NoToken)));
        }
    }

    /// The refresh grant: what it sends, and an ID token in the answer held to the
    /// issuer, this client, and the person it was asked for.
    #[tokio::test]
    async fn refresh_trades_the_refresh_token_for_the_same_person() {
        use std::sync::{Arc, Mutex};
        let answer: Arc<Mutex<Value>> = Arc::default();
        let served = answer.clone();
        let base = serve(axum::Router::new().route(
            "/token",
            post(move |body: String| {
                let a = served.lock().unwrap().clone();
                async move {
                    assert!(
                        body.contains("grant_type=refresh_token")
                            && body.contains("refresh_token=rt")
                            && body.contains("client_id=cid")
                            && body.contains("client_secret=s"),
                        "{body}"
                    );
                    Json(a)
                }
            }),
        ))
        .await;
        let c = sso(&base);
        let http = http_client().unwrap();
        let refresh = |v: Value| {
            *answer.lock().unwrap() = v;
            let (c, http) = (c.clone(), http.clone());
            async move { c.refresh(&http, "rt", "42").await }
        };
        let t = refresh(serde_json::json!({"access_token": "at2"}))
            .await
            .unwrap();
        assert_eq!((t.access.as_str(), t.refresh), ("at2", None));
        let t = refresh(serde_json::json!({
            "access_token": "at3", "refresh_token": "rt2", "id_token": jwt(&id_token("42")),
        }))
        .await
        .unwrap();
        assert_eq!(t.refresh.as_deref(), Some("rt2"));
        let mut expired = id_token("42");
        expired["exp"] = (now() - 3600).into();
        let mut elsewhere = id_token("42");
        elsewhere["iss"] = "https://evil.example".into();
        let mut other_client = id_token("42");
        other_client["aud"] = "other".into();
        for bad in [id_token("43"), expired, elsewhere, other_client] {
            let outcome = refresh(serde_json::json!({"access_token": "a", "id_token": jwt(&bad)}));
            assert!(matches!(outcome.await, Err(Error::IdToken(_))), "{bad}");
        }
        // A preset has no issuer to hold an ID token to, and ignores one.
        let preset = client(Provider {
            token_url: format!("{base}/token"),
            ..google()
        });
        *answer.lock().unwrap() =
            serde_json::json!({"access_token": "a", "id_token": jwt(&id_token("43"))});
        assert!(preset.refresh(&http, "rt", "42").await.is_ok());
    }

    #[tokio::test]
    async fn client_credentials_sends_its_scope_and_wants_no_person() {
        let base = serve(axum::Router::new().route(
            "/token",
            post(|body: String| async move {
                assert!(body.contains("grant_type=client_credentials"), "{body}");
                let scope = body.contains("scope=");
                Json(serde_json::json!({
                    "access_token": if scope { "scoped" } else { "default" },
                    "id_token": "not-even-a-jwt",
                }))
            }),
        ))
        .await;
        let c = sso(&base);
        let http = http_client().unwrap();
        let t = c.client_credentials(&http, Some("api")).await.unwrap();
        assert_eq!((t.access.as_str(), t.id_token), ("scoped", None));
        let t = c.client_credentials(&http, None).await.unwrap();
        assert_eq!(t.access, "default");
    }

    /// The other grants are held to what a sign-in is: no redirect, and no provider
    /// built by hand that `oidc` would refuse.
    #[tokio::test]
    async fn the_other_grants_follow_no_redirect_and_need_a_sound_provider() {
        let base = serve(axum::Router::new().route(
            "/token",
            post(|| async { axum::response::Redirect::temporary("/elsewhere") }),
        ))
        .await;
        let c = sso(&base);
        let http = http_client().unwrap();
        assert!(matches!(
            c.refresh(&http, "rt", "42").await,
            Err(Error::Redirected)
        ));
        assert!(matches!(
            c.client_credentials(&http, None).await,
            Err(Error::Redirected)
        ));
        let hand_built = client(Provider {
            issuer: Some("https://sso.example/x".into()),
            token_url: "http://sso.example/t".into(),
            ..google()
        });
        assert!(matches!(
            hand_built.refresh(&http, "rt", "42").await,
            Err(Error::Config(_))
        ));
        assert!(matches!(
            hand_built.client_credentials(&http, None).await,
            Err(Error::Config(_))
        ));
    }

    /// A refused grant is told apart from a provider that is merely unavailable, so
    /// an app drops a refresh token only when it is really gone.
    #[tokio::test]
    async fn a_refused_grant_is_rejected_and_an_outage_is_not() {
        use axum::extract::Path;
        use axum::http::StatusCode;
        let base = serve(axum::Router::new().route(
            "/{status}/token",
            post(|Path(status): Path<u16>| async move {
                (
                    StatusCode::from_u16(status).unwrap(),
                    Json(serde_json::json!({"error": "invalid_grant"})),
                )
            }),
        ))
        .await;
        let http = http_client().unwrap();
        for (status, rejected) in [
            (400, true),
            (401, true),
            (403, true),
            (408, false),
            (429, false),
            (500, false),
            (503, false),
        ] {
            let c = client(Provider {
                token_url: format!("{base}/{status}/token"),
                ..google()
            });
            let e = c.refresh(&http, "rt", "42").await.unwrap_err();
            assert_eq!(e.is_rejected(), rejected, "{status}: {e}");
        }
        assert!(Error::NoToken.is_rejected());
        assert!(!Error::Redirected.is_rejected());
    }

    #[test]
    fn tokens_debug_output_keeps_every_token() {
        let mut t = Tokens::bearer("access-secret");
        t.refresh = Some("refresh-secret".into());
        t.id_token = Some("id-secret".into());
        let shown = format!("{t:?}");
        assert!(!shown.contains("secret"), "{shown}");
        assert!(shown.contains("refresh: true"), "{shown}");
    }

    #[tokio::test]
    async fn discover_reads_the_issuers_own_document() {
        use std::sync::{Arc, Mutex};
        let doc: Arc<Mutex<Value>> = Arc::default();
        let served = doc.clone();
        let base = serve(
            axum::Router::new()
                .route(
                    "/realms/x/.well-known/openid-configuration",
                    get(move || {
                        let d = served.lock().unwrap().clone();
                        async move { Json(d) }
                    }),
                )
                .route(
                    "/moved/.well-known/openid-configuration",
                    get(|| async {
                        axum::response::Redirect::temporary(
                            "/realms/x/.well-known/openid-configuration",
                        )
                    }),
                ),
        )
        .await;
        let issuer = format!("{base}/realms/x");
        let good = serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/auth"),
            "token_endpoint": format!("{issuer}/token"),
            "userinfo_endpoint": format!("{issuer}/userinfo"),
            "end_session_endpoint": format!("{issuer}/logout"),
        });
        let http = http_client().unwrap();
        let find = |d: Value, at: String| {
            *doc.lock().unwrap() = d;
            let http = http.clone();
            async move { discover(&http, "sso", "SSO", &at).await }
        };
        let found = find(good.clone(), format!("{issuer}/")).await.unwrap();
        assert_eq!(found.provider.key(), issuer);
        assert_eq!(found.provider.token_url, format!("{issuer}/token"));
        assert_eq!(found.end_session, Some(format!("{issuer}/logout")));
        let mut none = good.clone();
        none.as_object_mut().unwrap().remove("end_session_endpoint");
        assert_eq!(find(none, issuer.clone()).await.unwrap().end_session, None);
        let mut slash = good.clone();
        slash["issuer"] = format!("{issuer}/").into();
        assert!(find(slash, issuer.clone()).await.is_ok());
        for (field, value) in [
            ("issuer", serde_json::json!("https://evil.example/realms/x")),
            ("issuer", Value::Null),
            ("token_endpoint", Value::Null),
            (
                "token_endpoint",
                serde_json::json!("http://sso.example/token"),
            ),
            (
                "end_session_endpoint",
                serde_json::json!("http://sso.example/out"),
            ),
        ] {
            let mut bad = good.clone();
            bad[field] = value.clone();
            assert!(
                matches!(find(bad, issuer.clone()).await, Err(Error::Config(_))),
                "{field} = {value}"
            );
        }
        assert!(matches!(
            find(good.clone(), format!("{base}/moved")).await,
            Err(Error::Redirected)
        ));
        assert!(matches!(
            find(good, "http://sso.example/realms/x".into()).await,
            Err(Error::Config(_))
        ));
    }
}
