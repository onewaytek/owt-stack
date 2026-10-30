//! The sign-in throttle counted in Redis, so its budgets hold across replicas.
//! Behind the `redis` feature.
//!
//! It mirrors [`Throttle`](super::Throttle): the same three budgets ([`Budgets`]) on
//! the same keys (an address, counted by its /64 for IPv6; an account, trimmed and
//! lower case), charged in the same order and *before* the password is checked, with
//! an address over its own budget spending nothing from an account's. The differences:
//!
//! * **Calls are async and return a [`Refusal`]**, not a `bool`, so a caller can tell a
//!   spent budget from an unreachable Redis.
//! * **Fixed windows.** Each budget is a counter that `INCR`s and expires a window after
//!   its first hit, in one Lua script, so concurrent replicas cannot race. A fixed
//!   window allows up to twice its budget across a boundary; the in-process throttle
//!   refills evenly instead. Refused attempts count too, so a client that keeps
//!   hammering keeps its window shut until it stops for a whole window.
//! * **Nothing readable is stored.** An account's key is the SHA-256 of its name, so an
//!   email address (a patient's, perhaps) never sits in Redis; an address is stored as
//!   itself, which is the same data the access log holds.
//!
//! # When Redis fails
//!
//! By default the throttle **fails closed** ([`FailMode::Closed`]): if Redis cannot be
//! reached (or answers with an error), the sign-in is refused with
//! [`Refusal::Unavailable`], and the password is not checked. Sign-in throttling is the
//! only thing bounding online password guessing; failing open lets anyone who can make
//! Redis slow or unreachable (or just wait for an outage) guess without bound, and for a
//! system holding health records, an outage that keeps people out for minutes is the
//! better failure than one that lets an attacker in. Map `Unavailable` to a 503 page,
//! not to "too many attempts", and alert on it. An app that weighs the other way (say,
//! for a public site with no sensitive data) sets [`FailMode::Open`], and every error is
//! then logged and allowed.
//!
//! # Telling the owner
//!
//! The first sign-in refused in a window because an account's budget ran out returns
//! [`Refusal::Account`] with `just_locked` true, and calls the hook set by
//! [`SharedThrottle::on_lockout`], once per window per account. The app emails the
//! account's owner ("someone is trying to sign in to your account"). The hook runs in
//! the request; hand the work to a task or a queue.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use redis::aio::{ConnectionManager, ConnectionManagerConfig};
use sha2::{Digest, Sha256};

use super::{Budgets, account_key, client_key};

/// What the throttle does when Redis cannot answer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FailMode {
    /// Refuse ([`Refusal::Unavailable`]). The default: see the module documentation.
    #[default]
    Closed,
    /// Allow, and log the error.
    Open,
}

/// Why a sign-in or attempt was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Refusal {
    /// The address is over its budget of attempts of any kind.
    #[error("too many attempts from this address")]
    Attempts,
    /// The address is over its budget of sign-ins.
    #[error("too many sign-ins from this address")]
    Address,
    /// The account is over its budget of sign-ins.
    #[error("too many sign-ins to this account")]
    Account {
        /// This is the first refusal in this window: the account just crossed its
        /// limit, and its owner should be told (once).
        just_locked: bool,
    },
    /// Redis did not answer and the throttle fails closed. Not a spent budget: show a
    /// "try again shortly" page, and page whoever runs Redis.
    #[error("the sign-in throttle is unavailable")]
    Unavailable,
}

/// An account that crossed its sign-in limit, passed to the lockout hook.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lockout {
    /// The account as the throttle keys it: trimmed, lower case.
    pub account: String,
    /// The address (an IPv6 one cut to its /64) whose attempt crossed the limit.
    pub address: IpAddr,
    /// The sign-ins allowed a minute.
    pub per_minute: u32,
}

type Hook = Arc<dyn Fn(&Lockout) + Send + Sync>;

/// The throttle. Cheap to clone; hold one in the app's state.
#[derive(Clone)]
pub struct SharedThrottle {
    redis: ConnectionManager,
    prefix: Arc<str>,
    budgets: Budgets,
    fail: FailMode,
    hook: Option<Hook>,
    script: Arc<redis::Script>,
    call_budget: Duration,
}

impl std::fmt::Debug for SharedThrottle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedThrottle")
            .field("prefix", &self.prefix)
            .field("budgets", &self.budgets)
            .field("fail", &self.fail)
            .finish_non_exhaustive()
    }
}

/// A Redis key prefix that names one deployment and nothing nested under it: ASCII
/// letters, digits, `_`, `.` and `-` (the rule `owt_runtime` and `owt_bus` apply too).
/// A `:` would let one prefix's keys be another's.
fn checked_prefix(prefix: &str) -> anyhow::Result<()> {
    let literal = !prefix.is_empty()
        && prefix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'));
    anyhow::ensure!(
        literal,
        "a Redis prefix is ASCII letters, digits, `_`, `.` and `-`: {prefix:?}"
    );
    Ok(())
}

/// Count each key in order; stop at the first over its limit. Returns {0, 0} if none
/// was, else {index of that key, 1 if this is the first refusal in its window}.
/// ARGV is limit and window in milliseconds, per key. A key with no expiry (a crash
/// between the two commands cannot happen in a script, but a restored backup might)
/// gets one.
const COUNT: &str = r"
for i = 1, #KEYS do
  local n = redis.call('INCR', KEYS[i])
  if n == 1 or redis.call('PTTL', KEYS[i]) < 0 then
    redis.call('PEXPIRE', KEYS[i], ARGV[2 * i])
  end
  if n > tonumber(ARGV[2 * i - 1]) then
    local first = 0
    if n == tonumber(ARGV[2 * i - 1]) + 1 then first = 1 end
    return {i, first}
  end
end
return {0, 0}
";

impl SharedThrottle {
    /// Connect to Redis at `url`; counts are kept under `prefix` (ASCII letters,
    /// digits, `_`, `.` and `-`), so several apps can share a Redis.
    ///
    /// The connection reconnects on its own; a call during an outage waits at most
    /// `response_timeout` (500 ms) before [`FailMode`] decides.
    ///
    /// # Errors
    /// A bad `prefix` or `url`, or a Redis that cannot be reached now.
    pub async fn connect(url: &str, prefix: &str, budgets: Budgets) -> anyhow::Result<Self> {
        checked_prefix(prefix)?;
        let client = redis::Client::open(url)?;
        let response = Duration::from_millis(500);
        let config = ConnectionManagerConfig::new()
            .set_response_timeout(Some(response))
            .set_connection_timeout(Some(Duration::from_secs(2)))
            .set_number_of_retries(1)
            .set_max_delay(Duration::from_secs(1));
        let redis = client.get_connection_manager_with_config(config).await?;
        Ok(Self::new(redis, prefix, budgets)?.with_call_budget(response * 2))
    }

    /// A throttle over a connection the app already holds (it sets the timeouts).
    ///
    /// # Errors
    /// A bad `prefix`.
    pub fn new(redis: ConnectionManager, prefix: &str, budgets: Budgets) -> anyhow::Result<Self> {
        checked_prefix(prefix)?;
        Ok(Self {
            redis,
            prefix: prefix.into(),
            budgets,
            fail: FailMode::default(),
            hook: None,
            script: Arc::new(redis::Script::new(COUNT)),
            call_budget: Duration::from_secs(2),
        })
    }

    fn with_call_budget(mut self, budget: Duration) -> Self {
        self.call_budget = budget;
        self
    }

    /// What to do when Redis fails (closed by default).
    #[must_use]
    pub fn fail_mode(mut self, mode: FailMode) -> Self {
        self.fail = mode;
        self
    }

    /// Call `hook` when an account first crosses its limit in a window.
    #[must_use]
    pub fn on_lockout(mut self, hook: impl Fn(&Lockout) + Send + Sync + 'static) -> Self {
        self.hook = Some(Arc::new(hook));
        self
    }

    fn key(&self, kind: &str, name: &str) -> String {
        format!("{}:throttle:{kind}:{name}", self.prefix)
    }

    fn account_slot(account: &str) -> String {
        use std::fmt::Write as _;
        Sha256::digest(account.as_bytes())
            .iter()
            .fold(String::with_capacity(64), |mut s, b| {
                let _ = write!(s, "{b:02x}");
                s
            })
    }

    /// Run the counting script over `keys` with `limits` (budget, window) each; the
    /// refusing key's index (1-based) and whether it was the first, or `None`.
    async fn count(
        &self,
        keys: &[String],
        limits: &[(u32, Duration)],
    ) -> Result<Option<(usize, bool)>, Refusal> {
        let mut invocation = self.script.prepare_invoke();
        for key in keys {
            invocation.key(key);
        }
        for &(limit, window) in limits {
            invocation.arg(limit.max(1));
            let window = if window.is_zero() {
                Duration::from_secs(60)
            } else {
                window
            };
            invocation.arg(u64::try_from(window.as_millis()).unwrap_or(u64::MAX).max(1));
        }
        let mut conn = self.redis.clone();
        let answer = tokio::time::timeout(
            self.call_budget,
            invocation.invoke_async::<(i64, i64)>(&mut conn),
        )
        .await;
        match answer {
            Ok(Ok((0, _))) => Ok(None),
            Ok(Ok((i, first))) => Ok(Some((usize::try_from(i).unwrap_or(1), first == 1))),
            Ok(Err(e)) => self.failed(&e.to_string()),
            Err(_) => self.failed("timed out"),
        }
    }

    fn failed(&self, why: &str) -> Result<Option<(usize, bool)>, Refusal> {
        match self.fail {
            FailMode::Closed => {
                tracing::error!(error = why, "the shared throttle failed, refusing (closed)");
                Err(Refusal::Unavailable)
            }
            FailMode::Open => {
                tracing::error!(error = why, "the shared throttle failed, allowing (open)");
                Ok(None)
            }
        }
    }

    fn attempt_limit(&self) -> (u32, Duration) {
        (
            self.budgets.attempts_per_address,
            self.budgets.attempt_window,
        )
    }

    /// Count an attempt from `address` (a sign-up, a password reset).
    ///
    /// # Errors
    /// [`Refusal::Attempts`] once it is over budget; [`Refusal::Unavailable`] if Redis
    /// failed and the throttle fails closed.
    pub async fn attempt(&self, address: IpAddr) -> Result<(), Refusal> {
        let addr = client_key(address).to_string();
        match self
            .count(&[self.key("att", &addr)], &[self.attempt_limit()])
            .await?
        {
            None => Ok(()),
            Some(_) => Err(Refusal::Attempts),
        }
    }

    /// Count a sign-in to `account` from `address`, before its password is checked.
    /// The password must not be checked unless this returns `Ok`.
    ///
    /// # Errors
    /// The budget that is spent, or [`Refusal::Unavailable`] if Redis failed and the
    /// throttle fails closed.
    pub async fn sign_in(&self, address: IpAddr, account: &str) -> Result<(), Refusal> {
        let addr = client_key(address);
        let account = account_key(account);
        let (a, minute) = (addr.to_string(), Duration::from_secs(60));
        let keys = [
            self.key("att", &a),
            self.key("sia", &a),
            self.key("sic", &Self::account_slot(&account)),
        ];
        let limits = [
            self.attempt_limit(),
            (self.budgets.sign_ins_per_address, minute),
            (self.budgets.sign_ins_per_account, minute),
        ];
        match self.count(&keys, &limits).await? {
            None => Ok(()),
            Some((1, _)) => Err(Refusal::Attempts),
            Some((2, _)) => Err(Refusal::Address),
            Some((_, just_locked)) => {
                if just_locked && let Some(hook) = &self.hook {
                    hook(&Lockout {
                        account,
                        address: addr,
                        per_minute: self.budgets.sign_ins_per_account.max(1),
                    });
                }
                Err(Refusal::Account { just_locked })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([10, 1, 0, last])
    }

    /// A throttle on `REDIS_URL` under a fresh prefix, or `None` (the test skips).
    async fn throttle(budgets: Budgets) -> Option<SharedThrottle> {
        let url = std::env::var("REDIS_URL").ok()?;
        let prefix = format!("t{}", crate::random_token(10).replace(['~', '_'], "x"));
        Some(
            SharedThrottle::connect(&url, &prefix, budgets)
                .await
                .unwrap(),
        )
    }

    fn budgets(n: u32) -> Budgets {
        Budgets {
            attempts_per_address: 1000,
            attempt_window: Duration::from_secs(60),
            sign_ins_per_address: 1000,
            sign_ins_per_account: n,
        }
    }

    #[test]
    fn prefixes_are_literal() {
        for ok in ["myapp", "my-app_1.prod"] {
            assert!(checked_prefix(ok).is_ok(), "{ok}");
        }
        for bad in ["", "my:app", "my app", "a*", "é"] {
            assert!(checked_prefix(bad).is_err(), "{bad}");
        }
    }

    #[tokio::test]
    async fn each_budget_runs_out_on_its_own_key() {
        let Some(t) = throttle(Budgets {
            attempts_per_address: 3,
            attempt_window: Duration::from_secs(60),
            sign_ins_per_address: 1000,
            sign_ins_per_account: 1000,
        })
        .await
        else {
            return;
        };
        for _ in 0..3 {
            t.attempt(ip(1)).await.unwrap();
        }
        assert_eq!(t.attempt(ip(1)).await, Err(Refusal::Attempts));
        assert_eq!(t.sign_in(ip(1), "ann").await, Err(Refusal::Attempts));
        t.attempt(ip(2)).await.unwrap();

        let t = throttle(Budgets {
            attempts_per_address: 1000,
            attempt_window: Duration::from_secs(60),
            sign_ins_per_address: 2,
            sign_ins_per_account: 2,
        })
        .await
        .unwrap();
        t.sign_in(ip(3), "ann").await.unwrap();
        t.sign_in(ip(4), "Ann ").await.unwrap();
        assert!(matches!(
            t.sign_in(ip(5), "ANN").await,
            Err(Refusal::Account { .. })
        ));
        t.sign_in(ip(6), "bob").await.unwrap();
        t.sign_in(ip(6), "cy").await.unwrap();
        assert_eq!(t.sign_in(ip(6), "di").await, Err(Refusal::Address));
        // The refused sign-in spent nothing from di's budget.
        t.sign_in(ip(7), "di").await.unwrap();
        // An IPv6 block is one client.
        t.sign_in("2001:db8:1:2::1".parse().unwrap(), "e1")
            .await
            .unwrap();
        t.sign_in("2001:db8:1:2:ffff::9".parse().unwrap(), "e2")
            .await
            .unwrap();
        assert_eq!(
            t.sign_in("2001:db8:1:2::77".parse().unwrap(), "e3").await,
            Err(Refusal::Address)
        );
    }

    #[tokio::test]
    async fn two_replicas_spend_one_budget() {
        let Some(a) = throttle(budgets(3)).await else {
            return;
        };
        let b = SharedThrottle::new(a.redis.clone(), &a.prefix, a.budgets).unwrap();
        a.sign_in(ip(1), "ann").await.unwrap();
        b.sign_in(ip(2), "ann").await.unwrap();
        a.sign_in(ip(3), "ann").await.unwrap();
        assert!(matches!(
            b.sign_in(ip(4), "ann").await,
            Err(Refusal::Account { .. })
        ));
        // Another deployment's prefix is another budget.
        let c = SharedThrottle::new(a.redis.clone(), &format!("{}x", a.prefix), a.budgets).unwrap();
        c.sign_in(ip(1), "ann").await.unwrap();
    }

    #[tokio::test]
    async fn the_owner_is_told_once_per_window() {
        let Some(t) = throttle(budgets(2)).await else {
            return;
        };
        let told = Arc::new(Mutex::new(Vec::new()));
        let sink = told.clone();
        let t = t.on_lockout(move |l| sink.lock().unwrap().push(l.clone()));
        t.sign_in(ip(1), " Ann@Example.com").await.unwrap();
        t.sign_in(ip(1), "ann@example.com").await.unwrap();
        assert_eq!(
            t.sign_in(ip(9), "ann@example.com").await,
            Err(Refusal::Account { just_locked: true })
        );
        for _ in 0..5 {
            assert_eq!(
                t.sign_in(ip(9), "ann@example.com").await,
                Err(Refusal::Account { just_locked: false })
            );
        }
        let told = told.lock().unwrap();
        assert_eq!(
            *told,
            [Lockout {
                account: "ann@example.com".into(),
                address: ip(9),
                per_minute: 2
            }]
        );
    }

    #[tokio::test]
    async fn a_window_expires() {
        let Some(t) = throttle(Budgets {
            attempts_per_address: 1,
            attempt_window: Duration::from_millis(300),
            ..budgets(100)
        })
        .await
        else {
            return;
        };
        t.attempt(ip(1)).await.unwrap();
        assert!(t.attempt(ip(1)).await.is_err());
        tokio::time::sleep(Duration::from_millis(900)).await;
        t.attempt(ip(1)).await.unwrap();
    }

    #[tokio::test]
    async fn an_account_name_is_not_stored_readable() {
        let Some(t) = throttle(budgets(5)).await else {
            return;
        };
        t.sign_in(ip(1), "patient@example.com").await.unwrap();
        let mut conn = t.redis.clone();
        let keys: Vec<String> = redis::cmd("KEYS")
            .arg(format!("{}:*", t.prefix))
            .query_async(&mut conn)
            .await
            .unwrap();
        assert_eq!(keys.len(), 3);
        assert!(keys.iter().all(|k| !k.contains("patient")), "{keys:?}");
        let ttl: i64 = redis::cmd("PTTL")
            .arg(&keys[0])
            .query_async(&mut conn)
            .await
            .unwrap();
        assert!(ttl > 0, "every counter expires");
    }

    /// A Redis error (here, a counter holding text) closes the throttle by default.
    #[tokio::test]
    async fn a_redis_failure_refuses_unless_told_to_allow() {
        let Some(t) = throttle(budgets(5)).await else {
            return;
        };
        let mut conn = t.redis.clone();
        let poisoned = t.key("sic", &SharedThrottle::account_slot("ann"));
        let _: () = redis::cmd("SET")
            .arg(&poisoned)
            .arg("text")
            .query_async(&mut conn)
            .await
            .unwrap();
        assert_eq!(t.sign_in(ip(1), "ann").await, Err(Refusal::Unavailable));
        assert!(
            t.sign_in(ip(1), "bob").await.is_ok(),
            "other accounts are fine"
        );
        let open = t.clone().fail_mode(FailMode::Open);
        assert_eq!(open.sign_in(ip(2), "ann").await, Ok(()));
    }
}
