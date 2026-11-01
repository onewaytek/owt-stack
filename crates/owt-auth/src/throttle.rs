//! Throttling sign-in attempts.
//!
//! Three budgets, each per minute: every attempt from one address (a flood), sign-ins
//! from one address (guessing across accounts), and sign-ins to one account (guessing
//! one password from many addresses). A form that wants "5 an hour" sets the window of
//! the first with [`Budgets::attempt_window`].
//!
//! A sign-in is charged *before* its password is checked, and one over budget is not
//! checked at all. Charging only failures would not stop a guess: the right password,
//! tried after the budget ran out, would still sign in.
//!
//! ```ignore
//! if !throttle.sign_in(ip, &form.account) { return too_many(); }
//! let ok = password::verify_or_decoy(&form.password, hash.as_deref()).await?; // `Busy`: 503
//! ```
//!
//! A successful sign-in spends from the budgets too; at five a minute per account,
//! no person notices. The per-account budget lets anyone hold an account's sign-ins
//! off for as long as they keep spending it, from addresses of their own: that is
//! the price of bounding guesses at it, and it lasts only while they keep at it.
//!
//! An account's budget is keyed on the login as the account store matches it (NFKC,
//! lower case), so `admin` and fullwidth `ａｄｍｉｎ` spend one budget.
//!
//! The counts live in this process: with N replicas an attacker gets N times each
//! budget, which is still a bound, and the first sign-in warns when `POD_NAMESPACE`
//! is set. Where it must be exactly the budget, the
//! `redis` feature adds [`shared::SharedThrottle`]: the same three budgets counted in
//! Redis, so every replica spends from one. The address must be the client's, not the
//! proxy's: see `owt_web::client_ip`. An IPv6 address is counted by its /64, the
//! block one client is usually given.
//!
//! An address over its own budget spends nothing from an account's: its sign-in is
//! refused unchecked, so it was no guess, and charging for it would let one address
//! hold every account's sign-ins off (and fill the table with names) at any rate it
//! cared to send.

#[cfg(feature = "redis")]
pub mod shared;

use std::net::{IpAddr, Ipv6Addr};
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};

/// The budgets, each per minute except where `attempt_window` says otherwise.
#[derive(Clone, Copy, Debug)]
pub struct Budgets {
    /// Attempts of any kind (sign-in, sign-up, reset) from one address, per
    /// [`attempt_window`](Self::attempt_window).
    pub attempts_per_address: u32,
    /// The window `attempts_per_address` is counted over: a minute by default, an hour
    /// for a form that allows 5 an hour. The budget refills evenly across it (one
    /// attempt every 12 minutes at 5 an hour), so a spent budget does not come back
    /// all at once. A zero window is a minute.
    pub attempt_window: Duration,
    /// Sign-ins from one address.
    pub sign_ins_per_address: u32,
    /// Sign-ins to one account.
    pub sign_ins_per_account: u32,
}

impl Default for Budgets {
    fn default() -> Self {
        Self {
            attempts_per_address: 200,
            attempt_window: Duration::from_secs(60),
            sign_ins_per_address: 20,
            sign_ins_per_account: 5,
        }
    }
}

/// The throttle. Hold one in the app's state, behind an `Arc`.
pub struct Throttle {
    attempts: DefaultKeyedRateLimiter<IpAddr>,
    sign_ins_by_address: DefaultKeyedRateLimiter<IpAddr>,
    sign_ins_by_account: DefaultKeyedRateLimiter<String>,
    calls: AtomicU32,
}

impl Default for Throttle {
    fn default() -> Self {
        Self::new(Budgets::default())
    }
}

impl std::fmt::Debug for Throttle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Throttle").finish_non_exhaustive()
    }
}

fn per_minute(n: u32) -> Quota {
    Quota::per_minute(NonZeroU32::new(n).unwrap_or(NonZeroU32::MIN))
}

/// `n` over `window`: a burst of `n`, refilled one at a time every `window / n`.
fn per_window(n: u32, window: Duration) -> Quota {
    let n = NonZeroU32::new(n).unwrap_or(NonZeroU32::MIN);
    if window.is_zero() {
        return Quota::per_minute(n);
    }
    Quota::with_period(window / n.get()).map_or_else(
        // `window / n` rounded down to nothing: as fast as a clock can count.
        || Quota::per_minute(n),
        |q| q.allow_burst(n),
    )
}

/// The key `address` is counted under: an IPv4 address as itself (also when written
/// IPv4-mapped), an IPv6 address by its /64.
pub(crate) fn client_key(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V4(_) => address,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(Ipv6Addr::from(v6.to_bits() & !u128::from(u64::MAX))),
        },
    }
}

/// The longest account key kept. No account name is longer; a request's worth of
/// text passed off as one must not be stored whole.
const MAX_ACCOUNT_KEY_BYTES: usize = 256;

/// The key `account` is counted under: the account store's form of a login (NFKC,
/// lower case, trimmed, as `owt_accounts::store::normalize` matches it), so every
/// spelling that signs in to one account spends one budget, cut to
/// [`MAX_ACCOUNT_KEY_BYTES`]. A username and its account's email are two logins,
/// and two budgets.
pub(crate) fn account_key(account: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    // Cut before normalizing, so a megabyte of text is not copied to be discarded.
    let compatible: String = cut(account.trim()).nfkc().collect();
    let lowered: String = compatible.to_lowercase().nfkc().collect();
    // Trimmed again: NFKC turns some characters into a space and a mark. And cut
    // again, since normalizing and lower-casing can lengthen it.
    cut(lowered.trim()).to_owned()
}

/// `s` cut to at most [`MAX_ACCOUNT_KEY_BYTES`], on a character.
fn cut(s: &str) -> &str {
    let mut end = s.len().min(MAX_ACCOUNT_KEY_BYTES);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Warn once, on a pod, that the in-process budgets are per replica.
fn warn_if_replicated() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        if std::env::var_os("POD_NAMESPACE").is_some() {
            tracing::warn!(
                "the sign-in throttle counts in this process: with N replicas each \
                 budget is N times larger; with several, use the redis feature's \
                 SharedThrottle"
            );
        }
    });
}

impl Throttle {
    /// A throttle with these budgets (a budget of 0 is 1).
    #[must_use]
    pub fn new(budgets: Budgets) -> Self {
        Self {
            attempts: RateLimiter::keyed(per_window(
                budgets.attempts_per_address,
                budgets.attempt_window,
            )),
            sign_ins_by_address: RateLimiter::keyed(per_minute(budgets.sign_ins_per_address)),
            sign_ins_by_account: RateLimiter::keyed(per_minute(budgets.sign_ins_per_account)),
            calls: AtomicU32::new(0),
        }
    }

    /// Forget keys whose budgets have refilled, every so often: account names are the
    /// caller's to invent, and the maps must not grow with them for ever.
    fn sweep(&self) {
        if self.calls.fetch_add(1, Ordering::Relaxed) % 1024 == 1023 {
            self.attempts.retain_recent();
            self.sign_ins_by_address.retain_recent();
            self.sign_ins_by_account.retain_recent();
        }
    }

    /// Count an attempt from `address` (a sign-up, a password reset); `false` once it
    /// is over budget.
    pub fn attempt(&self, address: IpAddr) -> bool {
        self.sweep();
        self.attempts.check_key(&client_key(address)).is_ok()
    }

    /// Count a sign-in to `account` from `address`, before its password is checked;
    /// `false` once any budget is spent, and then the password must not be checked.
    pub fn sign_in(&self, address: IpAddr, account: &str) -> bool {
        warn_if_replicated();
        // In this order, each only if the one before allowed it: a sign-in an
        // address's budget refuses is not checked, so it costs the account nothing.
        self.attempt(address)
            && self
                .sign_ins_by_address
                .check_key(&client_key(address))
                .is_ok()
            && self
                .sign_ins_by_account
                .check_key(&account_key(account))
                .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, last])
    }

    fn budgets(n: u32) -> Budgets {
        Budgets {
            attempts_per_address: n,
            attempt_window: Duration::from_secs(60),
            sign_ins_per_address: n,
            sign_ins_per_account: n,
        }
    }

    #[test]
    fn each_budget_runs_out_on_its_own_key() {
        let t = Throttle::new(Budgets {
            attempts_per_address: 3,
            sign_ins_per_address: 100,
            sign_ins_per_account: 100,
            ..Budgets::default()
        });
        assert!((0..3).all(|_| t.attempt(ip(1))));
        assert!(!t.attempt(ip(1)));
        assert!(!t.sign_in(ip(1), "ann"), "a sign-in is an attempt");
        assert!(t.attempt(ip(2)), "another address has its own budget");

        let t = Throttle::new(Budgets {
            attempts_per_address: 100,
            sign_ins_per_address: 2,
            sign_ins_per_account: 2,
            ..Budgets::default()
        });
        // One account guessed from many addresses.
        assert!(t.sign_in(ip(3), "ann"));
        assert!(t.sign_in(ip(4), "ann"));
        assert!(!t.sign_in(ip(5), "ann"));
        // One address guessing many accounts.
        assert!(t.sign_in(ip(6), "bob"));
        assert!(t.sign_in(ip(6), "cy"));
        assert!(!t.sign_in(ip(6), "di"));
    }

    #[test]
    fn the_attempt_window_sets_how_a_budget_refills() {
        // 3 an hour: three at once, and a spent budget does not come back in a moment.
        let hourly = Throttle::new(Budgets {
            attempts_per_address: 3,
            attempt_window: Duration::from_secs(3600),
            ..Budgets::default()
        });
        assert!((0..3).all(|_| hourly.attempt(ip(1))));
        std::thread::sleep(Duration::from_millis(50));
        assert!(!hourly.attempt(ip(1)));
        assert!(hourly.attempt(ip(2)), "another address has its own");

        // 2 per 2s refills one every second (wide enough that a loaded machine
        // doesn't refill one between the attempts).
        let quick = Throttle::new(Budgets {
            attempts_per_address: 2,
            attempt_window: Duration::from_secs(2),
            ..Budgets::default()
        });
        assert!(quick.attempt(ip(1)) && quick.attempt(ip(1)));
        assert!(!quick.attempt(ip(1)));
        std::thread::sleep(Duration::from_millis(1200));
        assert!(quick.attempt(ip(1)), "one attempt came back");

        // A zero window is a minute, not a panic or an unlimited budget.
        let zero = Throttle::new(Budgets {
            attempts_per_address: 1,
            attempt_window: Duration::ZERO,
            ..Budgets::default()
        });
        assert!(zero.attempt(ip(1)) && !zero.attempt(ip(1)));
        assert_eq!(Budgets::default().attempt_window, Duration::from_secs(60));
    }

    #[test]
    fn a_spent_budget_refuses_the_right_password_too() {
        // The flow in the module docs: the check comes first, so the guess that
        // would have been right is never verified.
        let t = Throttle::new(budgets(2));
        let password = "hunter2";
        let mut signed_in = false;
        for guess in ["a", "b", "hunter2"] {
            if t.sign_in(ip(1), "ann") && guess == password {
                signed_in = true;
            }
        }
        assert!(!signed_in);
    }

    #[test]
    fn account_variants_and_an_ipv6_block_share_a_budget() {
        let t = Throttle::new(budgets(2));
        assert!(t.sign_in(ip(1), "Ann"));
        assert!(t.sign_in(ip(2), " ann "));
        assert!(!t.sign_in(ip(3), "ANN"));

        let t = Throttle::new(budgets(2));
        let a: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:ffff::9".parse().unwrap();
        let elsewhere: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert!(t.attempt(a) && t.attempt(b));
        assert!(!t.attempt(a), "one /64 is one client");
        assert!(t.attempt(elsewhere));

        let t = Throttle::new(budgets(1));
        assert!(t.attempt(ip(9)));
        assert!(
            !t.attempt("::ffff:10.0.0.9".parse().unwrap()),
            "IPv4-mapped is the IPv4 address"
        );
    }

    #[test]
    fn invented_keys_are_forgotten() {
        // 60000 a minute refills in a millisecond.
        let t = Throttle::new(budgets(60_000));
        for i in 0..1000 {
            t.sign_in(ip(1), &format!("invented-{i}"));
        }
        assert_eq!(t.sign_ins_by_account.len(), 1000);
        std::thread::sleep(std::time::Duration::from_millis(20));
        for _ in 0..1024 {
            t.attempt(ip(1));
        }
        assert!(t.sign_ins_by_account.len() < 1000);
    }

    #[test]
    fn an_address_over_budget_spends_no_accounts_budget() {
        let t = Throttle::new(Budgets {
            attempts_per_address: 100_000,
            sign_ins_per_address: 2,
            sign_ins_per_account: 2,
            ..Budgets::default()
        });
        // One address walks a list of names, far past its own budget.
        for i in 0..500 {
            t.sign_in(ip(1), &format!("user-{i}"));
            t.sign_in(ip(1), "ann");
        }
        assert!(
            t.sign_ins_by_account.len() <= 2,
            "{} account keys held for one address",
            t.sign_ins_by_account.len()
        );
        // It spent what its own budget allowed, no more: the 500th name is untouched.
        assert!(t.sign_in(ip(2), "user-499"));
    }

    #[test]
    fn long_account_names_are_not_stored_whole() {
        let t = Throttle::new(budgets(1));
        let long = "a".repeat(100_000);
        assert!(t.sign_in(ip(1), &long));
        assert!(!t.sign_in(ip(2), &long), "it still has one budget");
        assert!(account_key(&long).len() <= MAX_ACCOUNT_KEY_BYTES);
        assert!(account_key(&"é".repeat(100_000)).len() <= MAX_ACCOUNT_KEY_BYTES);
    }

    #[test]
    fn account_keys_are_cut_on_a_character() {
        // The cut falls inside a two-byte character.
        let odd = format!("a{}", "é".repeat(300));
        let key = account_key(&odd);
        assert_eq!(key.len(), MAX_ACCOUNT_KEY_BYTES - 1);
        assert!(odd.starts_with(&key));
        // Lower-casing lengthens these (two bytes to three), so the second cut runs,
        // and it too falls inside a character.
        let growing = "\u{130}".repeat(300);
        let key = account_key(&growing);
        assert!(key.len() <= MAX_ACCOUNT_KEY_BYTES && key.len() > MAX_ACCOUNT_KEY_BYTES - 3);
        assert!(key.starts_with("i\u{307}"));
        // Here the second cut falls inside a character (the first does not): two
        // bytes of ASCII, then three-byte pairs, and 256 lands in the middle of a
        // pair's two-byte mark.
        let key = account_key(&format!("aa{growing}"));
        assert_eq!(key.len(), MAX_ACCOUNT_KEY_BYTES - 1);
        assert!(
            key.ends_with('i'),
            "the mark that did not fit is dropped whole"
        );
        assert_eq!(account_key("  Ann\t"), "ann");
    }

    #[test]
    fn spellings_of_one_login_share_a_budget() {
        // Fullwidth letters, a ligature, and a decomposed accent are the login the
        // store matches.
        assert_eq!(
            account_key("\u{ff21}\u{ff44}\u{ff4d}\u{ff49}\u{ff4e}"),
            "admin"
        );
        assert_eq!(account_key("\u{fb01}ona"), "fiona");
        assert_eq!(account_key("Jose\u{301}"), "jos\u{e9}");
        let t = Throttle::new(budgets(1));
        assert!(t.sign_in(ip(1), "admin"));
        assert!(!t.sign_in(ip(2), "\u{ff41}\u{ff44}\u{ff4d}\u{ff49}\u{ff4e}"));
        assert!(format!("{:?}", Throttle::default()).contains("Throttle"));
    }
}
