//! Signing people in with an OAuth 2 provider: the authorization-code flow.
//!
//! 1. [`Client::begin`] builds the redirect to the provider and a [`Pending`] login
//!    (state, and the PKCE verifier where the provider supports it) for the app to keep
//!    in the person's session.
//! 2. The provider redirects back with `code` and `state`. [`Client::complete`] takes
//!    both: it refuses a state that is not the pending login's, or a pending login
//!    begun with another provider, before it trades the code for a token and the token
//!    for the [`Identity`] the provider vouches for.
//!
//! Make the HTTP client with [`http_client`]: it gives up on a provider that stalls
//! and follows no redirects, so the client secret goes only where it was addressed.
//!
//! A [`Provider`] is data: endpoints, scope, and how to read its user-info response.
//! [`google`], [`discord`] and [`twitch`] are presets; [`oidc`] covers any `OpenID`
//! Connect provider (Keycloak, say) from its issuer's endpoints. Endpoints are plain
//! fields, so a test can point a preset at a fake server.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// An OAuth 2 provider.
#[derive(Clone, Debug)]
pub struct Provider {
    /// Stable id, in URLs and stored account links: `google`.
    pub id: &'static str,
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

/// Who a provider vouches for.
#[derive(Clone, Debug)]
pub struct Identity {
    /// The provider's id for the person: stable, never reassigned.
    pub uid: String,
    /// Their email, if the provider shared one.
    pub email: Option<String>,
    /// The provider checked the person controls that email.
    pub email_verified: bool,
    /// What they call themselves there.
    pub display_name: Option<String>,
    /// The whole user-info response, for anything else an app keeps.
    pub extra: Value,
}

fn s(v: &Value, k: &str) -> Option<String> {
    v[k].as_str().map(str::to_owned)
}

/// Google, with PKCE.
#[must_use]
pub fn google() -> Provider {
    Provider {
        id: "google",
        name: "Google",
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
        authorize_url: "https://discord.com/api/oauth2/authorize".into(),
        token_url: "https://discord.com/api/oauth2/token".into(),
        userinfo_url: "https://discord.com/api/users/@me".into(),
        scope: "identify email",
        pkce: true,
        client_id_header: false,
        identity: |info| {
            Some(Identity {
                uid: s(&info, "id")?,
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
        authorize_url: "https://id.twitch.tv/oauth2/authorize".into(),
        token_url: "https://id.twitch.tv/oauth2/token".into(),
        userinfo_url: "https://api.twitch.tv/helix/users".into(),
        scope: "user:read:email",
        pkce: false,
        client_id_header: true,
        identity: |info| {
            let user = info["data"][0].clone();
            Some(Identity {
                uid: s(&user, "id")?,
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
/// the endpoints its discovery document names.
#[must_use]
pub fn oidc(
    id: &'static str,
    name: &'static str,
    authorize: &str,
    token: &str,
    userinfo: &str,
) -> Provider {
    Provider {
        id,
        name,
        authorize_url: authorize.into(),
        token_url: token.into(),
        userinfo_url: userinfo.into(),
        scope: "openid profile email",
        pkce: true,
        client_id_header: false,
        identity: oidc_identity,
    }
}

/// The standard claims of an OIDC user-info response.
fn oidc_identity(info: Value) -> Option<Identity> {
    Some(Identity {
        uid: s(&info, "sub")?,
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
    /// A configured URL is not a URL.
    #[error("bad provider URL: {0}")]
    Url(#[from] url::ParseError),
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
    pub async fn complete(
        &self,
        http: &reqwest::Client,
        pending: &Pending,
        state: &str,
        code: &str,
    ) -> Result<Identity, Error> {
        if pending.provider != self.provider.id {
            return Err(Error::Provider);
        }
        if !pending.matches(state) {
            return Err(Error::State);
        }
        let mut form: Vec<(&str, &str)> = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &self.redirect_uri),
            ("client_id", &self.client_id),
            ("client_secret", &self.client_secret),
        ];
        if let Some(v) = &pending.verifier {
            form.push(("code_verifier", v));
        }
        let token: Value = http
            .post(&self.provider.token_url)
            .header("accept", "application/json")
            .form(&form)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let access = token["access_token"].as_str().ok_or(Error::NoToken)?;
        let mut req = http.get(&self.provider.userinfo_url).bearer_auth(access);
        if self.provider.client_id_header {
            req = req.header("Client-Id", &self.client_id);
        }
        let info: Value = req.send().await?.error_for_status()?.json().await?;
        (self.provider.identity)(info).ok_or(Error::NoIdentity)
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
    fn debug_output_keeps_the_secret() {
        let mut c = client(google());
        c.client_secret = "hunter2-secret".into();
        assert!(!format!("{c:?}").contains("hunter2"));
    }
}
