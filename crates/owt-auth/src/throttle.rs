//! Throttling sign-in attempts.
//!
//! Three budgets, each per minute: every attempt from one address (a flood), sign-ins
//! from one address (guessing across accounts), and sign-ins to one account (guessing
//! one password from many addresses).
//!
//! A sign-in is charged *before* its password is checked, and one over budget is not
//! checked at all. Charging only failures would not stop a guess: the right password,
//! tried after the budget ran out, would still sign in.
//!
//! ```ignore
//! if !throttle.sign_in(ip, &form.account) { return too_many(); }
//! let ok = password::verify_or_decoy(&form.password, hash.as_deref()).await;
//! ```
//!
//! A successful sign-in spends from the budgets too; at five a minute per account,
//! no person notices. The per-account budget lets anyone hold an account's sign-ins
//! off for as long as they keep spending it, from addresses of their own: that is
//! the price of bounding guesses at it, and it lasts only while they keep at it.
//!
//! The counts live in this process: with N replicas an attacker gets N times each
//! budget, which is still a bound. The address must be the client's, not the
//! proxy's: see `owt_web::client_ip`. An IPv6 address is counted by its /64, the
//! block one client is usually given.

use std::net::{IpAddr, Ipv6Addr};
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicU32, Ordering};

use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};

/// The budgets, each per minute.
#[derive(Clone, Copy, Debug)]
pub struct Budgets {
    /// Attempts of any kind (sign-in, sign-up, reset) from one address.
    pub attempts_per_address: u32,
    /// Sign-ins from one address.
    pub sign_ins_per_address: u32,
    /// Sign-ins to one account.
    pub sign_ins_per_account: u32,
}

impl Default for Budgets {
    fn default() -> Self {
        Self {
            attempts_per_address: 200,
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

/// The key `address` is counted under: an IPv4 address as itself (also when written
/// IPv4-mapped), an IPv6 address by its /64.
fn client_key(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V4(_) => address,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(Ipv6Addr::from(v6.to_bits() & !u128::from(u64::MAX))),
        },
    }
}

/// The key `account` is counted under: trimmed and lower case, so that variants of
/// one name share its budget.
fn account_key(account: &str) -> String {
    account.trim().to_lowercase()
}

impl Throttle {
    /// A throttle with these budgets (a budget of 0 is 1).
    #[must_use]
    pub fn new(budgets: Budgets) -> Self {
        Self {
            attempts: RateLimiter::keyed(per_minute(budgets.attempts_per_address)),
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
        let address_ok = self.attempt(address)
            && self
                .sign_ins_by_address
                .check_key(&client_key(address))
                .is_ok();
        // Charged even when the address is over budget: an attacker's own address
        // running out must not leave the account's budget untouched.
        let account_ok = self
            .sign_ins_by_account
            .check_key(&account_key(account))
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

    fn budgets(n: u32) -> Budgets {
        Budgets {
            attempts_per_address: n,
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
        });
        assert!((0..3).all(|_| t.attempt(ip(1))));
        assert!(!t.attempt(ip(1)));
        assert!(!t.sign_in(ip(1), "ann"), "a sign-in is an attempt");
        assert!(t.attempt(ip(2)), "another address has its own budget");

        let t = Throttle::new(Budgets {
            attempts_per_address: 100,
            sign_ins_per_address: 2,
            sign_ins_per_account: 2,
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
}
