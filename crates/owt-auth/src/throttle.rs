//! Throttling sign-in attempts.
//!
//! Three budgets, each per minute: every attempt from one address (a flood), failed
//! attempts from one address (guessing across accounts), and failed attempts at one
//! account (guessing one password from many addresses).
//!
//! ```ignore
//! if !throttle.attempt(ip) { return too_many(); }
//! let ok = password::verify_or_decoy(&form.password, hash.as_deref()).await;
//! if !ok && !throttle.failure(ip, &account) { return too_many(); }
//! ```
//!
//! The counts live in this process: with N replicas an attacker gets N times each
//! budget, which is still a bound. The address must be the client's, not the
//! proxy's: see `owt_web::client_ip`.

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicU32, Ordering};

use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};

/// The budgets, each per minute.
#[derive(Clone, Copy, Debug)]
pub struct Budgets {
    /// Sign-in or sign-up attempts from one address.
    pub attempts_per_address: u32,
    /// Failed sign-ins from one address.
    pub failures_per_address: u32,
    /// Failed sign-ins to one account.
    pub failures_per_account: u32,
}

impl Default for Budgets {
    fn default() -> Self {
        Self {
            attempts_per_address: 200,
            failures_per_address: 20,
            failures_per_account: 5,
        }
    }
}

/// The throttle. Hold one in the app's state.
pub struct Throttle {
    attempts: DefaultKeyedRateLimiter<IpAddr>,
    failures_by_address: DefaultKeyedRateLimiter<IpAddr>,
    failures_by_account: DefaultKeyedRateLimiter<String>,
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

impl Throttle {
    /// A throttle with these budgets (a budget of 0 is 1).
    #[must_use]
    pub fn new(budgets: Budgets) -> Self {
        Self {
            attempts: RateLimiter::keyed(per_minute(budgets.attempts_per_address)),
            failures_by_address: RateLimiter::keyed(per_minute(budgets.failures_per_address)),
            failures_by_account: RateLimiter::keyed(per_minute(budgets.failures_per_account)),
            calls: AtomicU32::new(0),
        }
    }

    /// Forget keys whose budgets have refilled, every so often: account names are the
    /// caller's to invent, and the maps must not grow with them for ever.
    fn sweep(&self) {
        if self.calls.fetch_add(1, Ordering::Relaxed) % 1024 == 1023 {
            self.attempts.retain_recent();
            self.failures_by_address.retain_recent();
            self.failures_by_account.retain_recent();
        }
    }

    /// Count an attempt from `address`; `false` once it is over budget.
    pub fn attempt(&self, address: IpAddr) -> bool {
        self.sweep();
        self.attempts.check_key(&address).is_ok()
    }

    /// Count a failed sign-in to `account` (normalize it first: trimmed, lower case)
    /// from `address`; `false` once either is over budget.
    pub fn failure(&self, address: IpAddr, account: &str) -> bool {
        self.sweep();
        let address_ok = self.failures_by_address.check_key(&address).is_ok();
        let account_ok = self
            .failures_by_account
            .check_key(&account.to_owned())
            .is_ok();
        address_ok && account_ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, last])
    }

    #[test]
    fn each_budget_runs_out_on_its_own_key() {
        let t = Throttle::new(Budgets {
            attempts_per_address: 3,
            failures_per_address: 2,
            failures_per_account: 2,
        });
        assert!((0..3).all(|_| t.attempt(ip(1))));
        assert!(!t.attempt(ip(1)));
        assert!(t.attempt(ip(2)), "another address has its own budget");

        // One account guessed from many addresses.
        assert!(t.failure(ip(3), "ann"));
        assert!(t.failure(ip(4), "ann"));
        assert!(!t.failure(ip(5), "ann"));
        // One address guessing many accounts.
        assert!(t.failure(ip(6), "bob"));
        assert!(t.failure(ip(6), "cy"));
        assert!(!t.failure(ip(6), "di"));
    }

    #[test]
    fn invented_keys_are_forgotten() {
        let t = Throttle::new(Budgets {
            // 60000 a minute refills in a millisecond.
            failures_per_account: 60_000,
            failures_per_address: 60_000,
            attempts_per_address: 60_000,
        });
        for i in 0..1000 {
            t.failure(ip(1), &format!("invented-{i}"));
        }
        assert_eq!(t.failures_by_account.len(), 1000);
        std::thread::sleep(std::time::Duration::from_millis(20));
        for _ in 0..1024 {
            t.attempt(ip(1));
        }
        assert!(t.failures_by_account.len() < 1000);
    }
}
