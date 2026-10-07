//! Properties of the authentication pieces: what must hold for every input.

use std::collections::HashMap;
use std::net::IpAddr;

use owt_auth::oauth::{self, Pending};
use owt_auth::throttle::{Budgets, Throttle};
use owt_auth::{jwt, password};
use proptest::prelude::*;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// A stored value that is nearly a hash: the shapes a corrupted row, a hostile import
/// or a half-migrated account could hold.
fn nearly_a_hash() -> impl Strategy<Value = String> {
    let b64 = "[A-Za-z0-9+/]{0,48}={0,2}";
    prop_oneof![
        any::<String>(),
        ("[0-9a-z-]{0,12}", "[a-zA-Z0-9]{0,16}", b64)
            .prop_map(|(n, salt, digest)| format!("pbkdf2_sha256${n}${salt}${digest}")),
        ("[0-9]{0,6}", "[0-9]{0,3}", "[0-9]{0,3}", b64, b64).prop_map(|(m, t, p, salt, hash)| {
            format!("$argon2id$v=19$m={m},t={t},p={p}${salt}${hash}")
        }),
        "\\$argon2(id|i|d)?\\$[ -~]{0,40}",
        "pbkdf2_sha256\\$[ -~]{0,40}",
    ]
}

#[derive(Clone, Debug)]
enum Call {
    Attempt(u8),
    SignIn(u8, u8),
}

fn calls() -> impl Strategy<Value = Vec<Call>> {
    let call = prop_oneof![
        (0u8..4).prop_map(Call::Attempt),
        (0u8..4, 0u8..4).prop_map(|(a, n)| Call::SignIn(a, n)),
    ];
    prop::collection::vec(call, 0..120)
}

fn address(n: u8) -> IpAddr {
    IpAddr::from([203, 0, 113, n])
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(300))]

    /// Nothing stored that is not a real hash of the password verifies it, and
    /// nothing stored makes the check panic or run away. (A random string matching
    /// would be a 2^-128 event; a failure here is a parsing bug.)
    #[test]
    fn a_malformed_stored_hash_matches_nothing(given in any::<String>(), stored in nearly_a_hash()) {
        // Memory-hard parameters a hostile row could ask for are argon2's to bound;
        // keep the generated ones small enough to run.
        prop_assume!(!stored.starts_with("$argon2") || !stored.contains("m=") || {
            let m = stored.split("m=").nth(1).and_then(|r| r.split(',').next()).and_then(|m| m.parse::<u32>().ok());
            m.is_none_or(|m| m <= 65_536)
        });
        let started = std::time::Instant::now();
        let matched = runtime().block_on(password::verify(&given, &stored));
        prop_assert!(!matched, "{given:?} verified against {stored:?}");
        prop_assert!(started.elapsed() < std::time::Duration::from_secs(20));
        // Deciding whether to rehash never panics either.
        let _ = password::needs_rehash(&stored);
    }

    /// The throttle against a model of it: an address's attempts, then its sign-ins,
    /// then the account's, each charged only if the one before allowed it. No
    /// sequence of calls lets through more than the model does.
    #[test]
    fn the_throttle_allows_exactly_what_its_budgets_say(
        calls in calls(),
        attempts in 1u32..12,
        per_address in 1u32..8,
        per_account in 1u32..6,
    ) {
        let throttle = Throttle::new(Budgets {
            attempts_per_address: attempts,
            sign_ins_per_address: per_address,
            sign_ins_per_account: per_account,
        });
        let (mut a, mut s, mut n) = (HashMap::new(), HashMap::new(), HashMap::new());
        let spend = |map: &mut HashMap<u8, u32>, key: u8, budget: u32| {
            let spent = map.entry(key).or_insert(0);
            *spent < budget && { *spent += 1; true }
        };
        for call in calls {
            match call {
                Call::Attempt(addr) => {
                    let expected = spend(&mut a, addr, attempts);
                    prop_assert_eq!(throttle.attempt(address(addr)), expected);
                }
                Call::SignIn(addr, name) => {
                    let expected = spend(&mut a, addr, attempts)
                        && spend(&mut s, addr, per_address)
                        && spend(&mut n, name, per_account);
                    // Variants of one name are one account.
                    let spelled = if addr % 2 == 0 { format!("User{name}") } else { format!(" user{name} ") };
                    prop_assert_eq!(throttle.sign_in(address(addr), &spelled), expected);
                }
            }
        }
    }

    /// An account name of any length and content is counted, and never unbounded.
    #[test]
    fn any_account_name_can_be_throttled(name in prop_oneof![any::<String>(), "[\u{130}ßA-Z]{0,400}"]) {
        let throttle = Throttle::new(Budgets { attempts_per_address: 100, sign_ins_per_address: 100, sign_ins_per_account: 1 });
        prop_assert!(throttle.sign_in(address(1), &name));
        prop_assert!(!throttle.sign_in(address(2), &name));
    }

    /// Only the state that was sent out completes a sign-in.
    #[test]
    fn only_the_state_sent_out_matches(state in "[A-Za-z0-9._~-]{1,40}", other in any::<String>()) {
        let pending = Pending { provider: "google".into(), state: state.clone(), verifier: None };
        prop_assert!(pending.matches(&state));
        prop_assert_eq!(pending.matches(&other), other == state);
        let shown = format!("{pending:?}");
        prop_assert!(!shown.contains(&state) || state.len() < 8, "{}", shown);
    }

    /// A callback whose state or provider is wrong is refused before anything is
    /// sent to the provider (whose endpoints here accept no connection).
    #[test]
    fn a_wrong_callback_never_reaches_the_provider(state in any::<String>(), code in any::<String>()) {
        let client = oauth::Client {
            provider: oauth::Provider {
                token_url: "http://127.0.0.1:9/token".into(),
                userinfo_url: "http://127.0.0.1:9/userinfo".into(),
                ..oauth::google()
            },
            client_id: "id".into(),
            client_secret: "secret".into(),
            redirect_uri: "https://app.example/cb".into(),
        };
        let (_, pending) = client.begin().unwrap();
        prop_assume!(state != pending.state);
        let http = oauth::http_client().unwrap();
        let outcome = runtime().block_on(client.complete(&http, &pending, &state, &code));
        prop_assert!(matches!(outcome, Err(oauth::Error::State)));
        let elsewhere = Pending { provider: "discord".into(), ..pending.clone() };
        let outcome = runtime().block_on(client.complete(&http, &elsewhere, &pending.state, &code));
        prop_assert!(matches!(outcome, Err(oauth::Error::Provider)));
    }

    /// Every sign-in begun carries a fresh state and, with PKCE, a challenge that is
    /// the S256 of its verifier.
    #[test]
    fn a_begun_sign_in_is_well_formed(client_id in "[ -~]{1,30}", redirect in "https://[a-z]{1,8}\\.example/[a-z/]{0,12}") {
        use base64::Engine;
        use sha2::Digest;
        let client = oauth::Client {
            provider: oauth::google(),
            client_id: client_id.clone(),
            client_secret: "s".into(),
            redirect_uri: redirect.clone(),
        };
        let (url, pending) = client.begin().unwrap();
        let (_, again) = client.begin().unwrap();
        prop_assert_ne!(&pending.state, &again.state);
        let url = url::Url::parse(&url).unwrap();
        let q: HashMap<_, _> = url.query_pairs().into_owned().collect();
        prop_assert_eq!(&q["client_id"], &client_id);
        prop_assert_eq!(&q["redirect_uri"], &redirect);
        prop_assert_eq!(&q["state"], &pending.state);
        prop_assert!(pending.state.len() >= 32);
        let verifier = pending.verifier.unwrap();
        prop_assert!((43..=128).contains(&verifier.len()), "RFC 7636 §4.1");
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(verifier.as_bytes()));
        prop_assert_eq!(&q["code_challenge"], &challenge);
        prop_assert_eq!(&q["code_challenge_method"], "S256");
    }

    /// Nothing that is not a token verifies, or panics, whatever shape it has.
    #[test]
    fn garbage_is_never_a_token(token in prop_oneof![
        any::<String>(),
        "[A-Za-z0-9_-]{0,60}\\.[A-Za-z0-9_-]{0,60}\\.[A-Za-z0-9_-]{0,60}",
        "eyJhbGciOiJub25lIn0\\.[A-Za-z0-9_-]{0,40}\\.",
        "eyJhbGciOiJIUzI1NiIsImtpZCI6ImsxIn0\\.[A-Za-z0-9_-]{0,40}\\.[A-Za-z0-9_-]{0,43}",
    ]) {
        // Keys that cannot be fetched: a token that got as far as asking for them
        // still fails.
        let verifier = jwt::Verifier::new(reqwest::Client::new(), "https://idp.example", "app", "http://127.0.0.1:9/jwks");
        let outcome = runtime().block_on(verifier.verify::<jwt::Claims>(&token));
        prop_assert!(outcome.is_err());
    }
}
