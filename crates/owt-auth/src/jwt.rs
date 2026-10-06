//! Bearer tokens an identity provider issued, verified locally.
//!
//! For machine clients (agents, services) arriving with a `client_credentials` token.
//! Verification is strict and needs no call to the provider beyond fetching its keys:
//!
//! * the signature, against a key from the provider's JWKS, chosen by `kid`;
//! * the algorithm, which must be asymmetric (a token cannot pick `HS256` and sign
//!   with the public key);
//! * `iss` against the configured issuer;
//! * `aud` against the configured audience: what stops a token minted for another
//!   service being replayed here;
//! * `exp` (and `nbf`), with a small leeway for clock skew.
//!
//! Keys are cached. An unknown `kid` refetches the set (the provider rotated), at most
//! once per [`Verifier::min_refresh`], so a stream of forged `kid`s cannot turn into a
//! stream of requests to the provider.

use std::sync::Arc;
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::de::DeserializeOwned;
use tokio::sync::RwLock;

/// Why a token was refused.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Not a JWT, a bad signature, the wrong issuer or audience, expired, ...
    #[error("invalid token: {0}")]
    Invalid(#[from] jsonwebtoken::errors::Error),
    /// The token names no key, or a key the provider does not publish.
    #[error("unknown signing key")]
    UnknownKey,
    /// The token asks for a symmetric algorithm.
    #[error("algorithm {0:?} is not accepted")]
    Algorithm(Algorithm),
    /// The keys could not be fetched.
    #[error("fetching the provider's keys: {0}")]
    Keys(#[from] reqwest::Error),
}

/// Verifies tokens from one issuer for one audience. Cheap to clone.
#[derive(Clone)]
pub struct Verifier(Arc<Inner>);

struct Inner {
    issuer: String,
    audience: String,
    jwks_uri: String,
    leeway: u64,
    min_refresh: Duration,
    http: reqwest::Client,
    keys: RwLock<Option<(JwkSet, Instant)>>,
}

/// The claims every verified token has; deserialize your own type for more.
#[derive(Clone, Debug, serde::Deserialize)]
pub struct Claims {
    /// Who the token is for: the client or account at the provider.
    pub sub: String,
}

impl Verifier {
    /// Tokens from `issuer` for `audience`, with keys at `jwks_uri`.
    #[must_use]
    pub fn new(http: reqwest::Client, issuer: &str, audience: &str, jwks_uri: &str) -> Self {
        Self(Arc::new(Inner {
            issuer: issuer.to_owned(),
            audience: audience.to_owned(),
            jwks_uri: jwks_uri.to_owned(),
            leeway: 5,
            min_refresh: Duration::from_secs(60),
            http,
            keys: RwLock::new(None),
        }))
    }

    /// Like [`Verifier::new`], finding the keys through the issuer's `OpenID` discovery
    /// document (`<issuer>/.well-known/openid-configuration`).
    pub async fn discover(
        http: reqwest::Client,
        issuer: &str,
        audience: &str,
    ) -> Result<Self, Error> {
        #[derive(serde::Deserialize)]
        struct Discovery {
            jwks_uri: String,
        }
        let url = format!(
            "{}/.well-known/openid-configuration",
            issuer.trim_end_matches('/')
        );
        let d: Discovery = http
            .get(url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(Self::new(http, issuer, audience, &d.jwks_uri))
    }

    /// The least time between two refetches of the key set.
    #[must_use]
    pub fn min_refresh(&self) -> Duration {
        self.0.min_refresh
    }

    async fn fetch(&self) -> Result<JwkSet, Error> {
        Ok(self
            .0
            .http
            .get(&self.0.jwks_uri)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    /// The key `kid`, refetching the set if it is unknown and the last fetch is old
    /// enough.
    async fn key(&self, kid: &str) -> Result<DecodingKey, Error> {
        {
            let keys = self.0.keys.read().await;
            if let Some((set, fetched)) = keys.as_ref() {
                if let Some(jwk) = set.find(kid) {
                    return Ok(DecodingKey::from_jwk(jwk)?);
                }
                if fetched.elapsed() < self.0.min_refresh {
                    return Err(Error::UnknownKey);
                }
            }
        }
        let mut keys = self.0.keys.write().await;
        // Another caller may have refreshed while this one waited for the lock.
        let stale = keys
            .as_ref()
            .is_none_or(|(_, at)| at.elapsed() >= self.0.min_refresh);
        if stale {
            *keys = Some((self.fetch().await?, Instant::now()));
        }
        let (set, _) = keys.as_ref().expect("just filled");
        let jwk = set.find(kid).ok_or(Error::UnknownKey)?;
        Ok(DecodingKey::from_jwk(jwk)?)
    }

    /// Verify `token` and read its claims as `C`.
    pub async fn verify<C: DeserializeOwned>(&self, token: &str) -> Result<C, Error> {
        let header = jsonwebtoken::decode_header(token)?;
        if matches!(
            header.alg,
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512
        ) {
            return Err(Error::Algorithm(header.alg));
        }
        let kid = header.kid.ok_or(Error::UnknownKey)?;
        let key = self.key(&kid).await?;
        let mut v = Validation::new(header.alg);
        v.leeway = self.0.leeway;
        v.set_issuer(&[&self.0.issuer]);
        v.set_audience(&[&self.0.audience]);
        v.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        Ok(jsonwebtoken::decode::<C>(token, &key, &v)?.claims)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::Json;
    use axum::routing::get;
    use base64::Engine;
    use jsonwebtoken::{EncodingKey, Header};
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::traits::PublicKeyParts;

    use super::*;

    struct Idp {
        base: String,
        key: EncodingKey,
        fetches: Arc<AtomicUsize>,
    }

    async fn idp() -> Idp {
        let private = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).unwrap();
        let b64 = |b: Vec<u8>| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
        let jwks = serde_json::json!({"keys": [{
            "kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig",
            "n": b64(private.n().to_bytes_be()), "e": b64(private.e().to_bytes_be()),
        }]});
        let fetches = Arc::new(AtomicUsize::new(0));
        let f = fetches.clone();
        let app = axum::Router::new().route(
            "/jwks",
            get(move || {
                f.fetch_add(1, Ordering::SeqCst);
                let jwks = jwks.clone();
                async move { Json(jwks) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await });
        let key = EncodingKey::from_rsa_der(private.to_pkcs1_der().unwrap().as_bytes());
        Idp { base, key, fetches }
    }

    fn token(idp: &Idp, kid: &str, aud: &str, exp_in: i64) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = serde_json::json!({
            "sub": "agent-7", "iss": "https://idp.test", "aud": aud,
            "exp": now.cast_signed() + exp_in,
        });
        let mut h = Header::new(Algorithm::RS256);
        h.kid = Some(kid.into());
        jsonwebtoken::encode(&h, &claims, &idp.key).unwrap()
    }

    #[tokio::test]
    async fn verifies_signature_issuer_audience_and_expiry() {
        let idp = idp().await;
        let v = Verifier::new(
            reqwest::Client::new(),
            "https://idp.test",
            "kynestro",
            &format!("{}/jwks", idp.base),
        );
        let claims: Claims = v.verify(&token(&idp, "k1", "kynestro", 60)).await.unwrap();
        assert_eq!(claims.sub, "agent-7");
        assert!(matches!(
            v.verify::<Claims>(&token(&idp, "k1", "other", 60)).await,
            Err(Error::Invalid(_))
        ));
        assert!(matches!(
            v.verify::<Claims>(&token(&idp, "k1", "kynestro", -60))
                .await,
            Err(Error::Invalid(_))
        ));
        assert!(v.verify::<Claims>("not.a.token").await.is_err());
    }

    #[tokio::test]
    async fn unknown_keys_refetch_at_most_once_per_interval() {
        let idp = idp().await;
        let v = Verifier::new(
            reqwest::Client::new(),
            "https://idp.test",
            "kynestro",
            &format!("{}/jwks", idp.base),
        );
        v.verify::<Claims>(&token(&idp, "k1", "kynestro", 60))
            .await
            .unwrap();
        for _ in 0..5 {
            assert!(matches!(
                v.verify::<Claims>(&token(&idp, "forged", "kynestro", 60))
                    .await,
                Err(Error::UnknownKey)
            ));
        }
        assert_eq!(idp.fetches.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn symmetric_algorithms_are_refused() {
        let mut h = Header::new(Algorithm::HS256);
        h.kid = Some("k1".into());
        let t = jsonwebtoken::encode(
            &h,
            &serde_json::json!({"sub": "x"}),
            &EncodingKey::from_secret(b"pub"),
        )
        .unwrap();
        let v = Verifier::new(reqwest::Client::new(), "i", "a", "http://127.0.0.1:9/jwks");
        assert!(matches!(
            v.verify::<Claims>(&t).await,
            Err(Error::Algorithm(Algorithm::HS256))
        ));
    }
}
