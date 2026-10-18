//! The words the admin writes.

/// Every word the admin's pages and notices write themselves, English unless the
/// app passes its own ([`Admin::words`](super::Admin::words)): what staff are called,
/// the headings, hints, buttons and the one-line outcomes. Build one from the
/// English with struct update syntax, so a word added later needs nothing from the
/// app:
///
/// ```
/// use owt_accounts::admin::Words;
/// let words = Words { staff: "Team", staff_hint: "May use the team pages.", ..Words::ENGLISH };
/// assert_eq!(words.save, "Save");
/// ```
///
/// A `{what}`, `{name}`, `{username}` or `{lifetime}` in a sentence stands for what
/// the admin fills in. The view models carry the words
/// ([`ListView::words`](super::ListView::words), and the others'), so an app's
/// [`Views`](super::Views) draws its own markup with the same words. What an app's
/// people chose (usernames, emails, a role's label) is never in here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Words {
    /// The list's title and the link back to it: `Accounts`.
    pub accounts: &'static str,
    /// The new-account page's title and the list's button: `New account`.
    pub new_account: &'static str,
    /// The link from an account's page to the list: `All accounts`.
    pub all_accounts: &'static str,
    /// The search box without the app's own search: `Username or email`.
    pub search: &'static str,
    /// The search box with it: `Username, email or {what}`.
    pub search_with: &'static str,
    /// The filter's label, for assistive technology: `Show`.
    pub show: &'static str,
    /// The filter that filters nothing: `Everyone`.
    pub everyone: &'static str,
    /// The search button: `Search`.
    pub search_button: &'static str,
    /// After the count, singular and plural: `account`, `accounts`.
    pub account_one: &'static str,
    /// See [`Words::account_one`].
    pub account_many: &'static str,
    /// An empty list: `No accounts match.`
    pub no_accounts_match: &'static str,
    /// The list's columns: `Account`, `Access`, `Last sign-in`.
    pub column_account: &'static str,
    /// See [`Words::column_account`].
    pub column_access: &'static str,
    /// See [`Words::column_account`]; also the account page's fact.
    pub last_sign_in: &'static str,
    /// An account that never signed in: `never`.
    pub never: &'static str,
    /// The staff tier, as a badge, a filter and a checkbox: `Staff`.
    pub staff: &'static str,
    /// A deactivated account, as a badge and a filter: `Deactivated`.
    pub deactivated: &'static str,
    /// An account with no tier or role: `User`.
    pub user: &'static str,
    /// A role the app does not declare, as a badge: `{name} (undeclared)`.
    pub undeclared: &'static str,
    /// An account no password opens, as a badge: `Password sign-in off`.
    pub password_sign_in_off: &'static str,
    /// The username field's label and hint.
    pub username: &'static str,
    /// See [`Words::username`].
    pub username_hint: &'static str,
    /// The email field's label, its hint on the new-account form, and on the
    /// account's page.
    pub email: &'static str,
    /// See [`Words::email`].
    pub email_hint_new: &'static str,
    /// See [`Words::email`].
    pub email_hint: &'static str,
    /// The access fieldset's legend: `Access`.
    pub access: &'static str,
    /// Under it on the new-account form and on the account's page.
    pub every_account_is_a_user: &'static str,
    /// See [`Words::every_account_is_a_user`].
    pub every_active_account_is_a_user: &'static str,
    /// The staff checkbox's hint on the new-account form, and on the account's page
    /// (where removing it signs the account out).
    pub staff_hint_new: &'static str,
    /// See [`Words::staff_hint_new`].
    pub staff_hint: &'static str,
    /// After a role's description when staff hold it anyway: `Staff hold it anyway.`
    pub staff_hold_it_anyway: &'static str,
    /// The active checkbox: `Active`, and its hint.
    pub active: &'static str,
    /// See [`Words::active`].
    pub active_hint: &'static str,
    /// The two hints on staff's own account.
    pub cannot_deactivate_yourself: &'static str,
    /// See [`Words::cannot_deactivate_yourself`].
    pub cannot_remove_own_staff: &'static str,
    /// An undeclared role's hint on the account's page.
    pub undeclared_hint: &'static str,
    /// Under the new-account form: `The account starts with no password…`.
    pub no_password_yet: &'static str,
    /// The new-account form's button: `Create account`.
    pub create_account: &'static str,
    /// The account form's button: `Save`.
    pub save: &'static str,
    /// The account page's facts: `Joined`, `Status`.
    pub joined: &'static str,
    /// See [`Words::joined`].
    pub status: &'static str,
    /// The status's values: `Active` is [`Words::active`], `Deactivated` is
    /// [`Words::deactivated`].
    pub ways_in: &'static str,
    /// What the account's page says of its password: no password opens it, it has
    /// one, it has none.
    pub password_sign_in_off_sentence: &'static str,
    /// See [`Words::password_sign_in_off_sentence`].
    pub has_password: &'static str,
    /// See [`Words::password_sign_in_off_sentence`].
    pub no_password: &'static str,
    /// The buttons of "Ways in".
    pub set_generated_password: &'static str,
    /// See [`Words::set_generated_password`].
    pub turn_password_sign_in_off: &'static str,
    /// See [`Words::set_generated_password`].
    pub turn_password_sign_in_on: &'static str,
    /// See [`Words::set_generated_password`]: `Issue a sign-in link ({lifetime})`.
    pub issue_link: &'static str,
    /// See [`Words::set_generated_password`].
    pub sign_out_everywhere: &'static str,
    /// The secret's hint: `Shown this once…`.
    pub shown_once: &'static str,
    /// The connections heading, the hint when there are none, and the table.
    pub connections: &'static str,
    /// See [`Words::connections`].
    pub no_connections: &'static str,
    /// See [`Words::connections`].
    pub provider: &'static str,
    /// See [`Words::connections`].
    pub shown_as: &'static str,
    /// The actions column, for assistive technology: `Actions`.
    pub actions: &'static str,
    /// A connection's button: `Remove`.
    pub remove: &'static str,
    /// The local identities heading, hint and table.
    pub local_identities: &'static str,
    /// See [`Words::local_identities`].
    pub local_identities_hint: &'static str,
    /// See [`Words::local_identities`].
    pub key: &'static str,
    /// See [`Words::local_identities`].
    pub subject: &'static str,
    /// See [`Words::local_identities`].
    pub added: &'static str,
    /// A local identity's button: `Retire`.
    pub retire: &'static str,
    /// The notices after a change.
    pub notice_created: &'static str,
    /// See [`Words::notice_created`].
    pub notice_saved: &'static str,
    /// See [`Words::notice_created`].
    pub notice_signed_out: &'static str,
    /// See [`Words::notice_created`].
    pub notice_unlinked: &'static str,
    /// See [`Words::notice_created`].
    pub notice_last_way_in: &'static str,
    /// See [`Words::notice_created`].
    pub notice_password_sign_in_on: &'static str,
    /// See [`Words::notice_created`].
    pub notice_password_sign_in_off: &'static str,
    /// See [`Words::notice_created`].
    pub notice_forgotten: &'static str,
    /// The refusals on staff's own account: the first for the form, the second with
    /// `{what}` for a button ([`Words::what_turn_off`], [`Words::what_retire`]).
    pub not_own_staff_or_active: &'static str,
    /// See [`Words::not_own_staff_or_active`].
    pub not_on_yourself: &'static str,
    /// See [`Words::not_own_staff_or_active`].
    pub what_turn_off: &'static str,
    /// See [`Words::not_own_staff_or_active`].
    pub what_retire: &'static str,
    /// A bad `password_sign_in` value: `Say on or off for password sign-in.`
    pub say_on_or_off: &'static str,
    /// A link asked for a deactivated account.
    pub deactivated_no_link: &'static str,
    /// The app's own search failed: `Searching by {what} failed, …`.
    pub search_failed: &'static str,
    /// What a new password is: `New password for {username}. …`.
    pub new_password: &'static str,
    /// What a sign-in link is: `Sign-in link for {username}, good once within {lifetime}.`
    pub sign_in_link: &'static str,
    /// A duration in words: `{n} day`, `{n} days`, and the hours and minutes.
    pub day: &'static str,
    /// See [`Words::day`].
    pub days: &'static str,
    /// See [`Words::day`].
    pub hour: &'static str,
    /// See [`Words::day`].
    pub hours: &'static str,
    /// See [`Words::day`].
    pub minute: &'static str,
    /// See [`Words::day`].
    pub minutes: &'static str,
}

impl Words {
    /// The admin's own words.
    pub const ENGLISH: Self = Self {
        accounts: "Accounts",
        new_account: "New account",
        all_accounts: "All accounts",
        search: "Username or email",
        search_with: "Username, email or {what}",
        show: "Show",
        everyone: "Everyone",
        search_button: "Search",
        account_one: "account",
        account_many: "accounts",
        no_accounts_match: "No accounts match.",
        column_account: "Account",
        column_access: "Access",
        last_sign_in: "Last sign-in",
        never: "never",
        staff: "Staff",
        deactivated: "Deactivated",
        user: "User",
        undeclared: "{name} (undeclared)",
        password_sign_in_off: "Password sign-in off",
        username: "Username",
        username_hint: "One word, no “@”. It does not change later.",
        email: "Email",
        email_hint_new: "Optional. It signs in with the password, as the username does; a provider sign-in never matches it.",
        email_hint: "It signs in with the password, as the username does; a provider sign-in never matches it.",
        access: "Access",
        every_account_is_a_user: "Every account is a user. Add more only where it is needed.",
        every_active_account_is_a_user: "Every active account is a user.",
        staff_hint_new: "May use the staff pages, this one included.",
        staff_hint: "May use the staff pages, this one included. Removing it signs the account out.",
        staff_hold_it_anyway: "Staff hold it anyway.",
        active: "Active",
        active_hint: "Deactivating signs the account out everywhere and keeps its data.",
        cannot_deactivate_yourself: "You cannot deactivate yourself.",
        cannot_remove_own_staff: "You cannot take away your own staff access.",
        undeclared_hint: "Held, but this app does not declare it. Untick to revoke it; it cannot be granted here.",
        no_password_yet: "The account starts with no password. Its page offers a way in afterwards.",
        create_account: "Create account",
        save: "Save",
        joined: "Joined",
        status: "Status",
        ways_in: "Ways in",
        password_sign_in_off_sentence: "Password sign-in off: no password opens it.",
        has_password: "Has a password.",
        no_password: "No password.",
        set_generated_password: "Set a generated password",
        turn_password_sign_in_off: "Turn password sign-in off",
        turn_password_sign_in_on: "Turn password sign-in on",
        issue_link: "Issue a sign-in link ({lifetime})",
        sign_out_everywhere: "Sign out everywhere",
        shown_once: "Shown this once. Pass it on privately; nothing here can show it again.",
        connections: "Sign-in connections",
        no_connections: "None. Only the account's owner can connect one, while signed in.",
        provider: "Provider",
        shown_as: "Shown as",
        actions: "Actions",
        remove: "Remove",
        local_identities: "Local identities",
        local_identities_hint: "How the app itself reaches this account. Retiring one signs the account out everywhere.",
        key: "Key",
        subject: "Subject",
        added: "Added",
        retire: "Retire",
        notice_created: "Account created. Give it a way in below.",
        notice_saved: "Saved.",
        notice_signed_out: "Signed out everywhere.",
        notice_unlinked: "Sign-in connection removed, and the account signed out everywhere.",
        notice_last_way_in: "That is this account's only way in, so it cannot be removed. Set a password (with password sign-in on), or add a connection first.",
        notice_password_sign_in_on: "Password sign-in is on. The account has no password until one is set.",
        notice_password_sign_in_off: "Password sign-in is off: its password is gone, and the account signed out everywhere.",
        notice_forgotten: "Local identity retired, and the account signed out everywhere.",
        not_own_staff_or_active: "You cannot take away your own staff access or deactivate yourself. Ask another member of staff.",
        not_on_yourself: "You cannot {what} on your own account. Ask another member of staff.",
        what_turn_off: "turn password sign-in off",
        what_retire: "retire a local identity",
        say_on_or_off: "Say on or off for password sign-in.",
        deactivated_no_link: "A deactivated account cannot use a sign-in link. Activate it first.",
        search_failed: "Searching by {what} failed, so these are username and email matches only.",
        new_password: "New password for {username}. It has signed out every session and voided its unused sign-in links.",
        sign_in_link: "Sign-in link for {username}, good once within {lifetime}.",
        day: "{n} day",
        days: "{n} days",
        hour: "{n} hour",
        hours: "{n} hours",
        minute: "{n} minute",
        minutes: "{n} minutes",
    };

    /// A duration in these words: `15 minutes`, `1 hour`, `7 days`.
    #[must_use]
    pub fn duration(&self, d: std::time::Duration) -> String {
        let s = d.as_secs();
        let (n, one, many) = if s.is_multiple_of(86_400) && s >= 86_400 {
            (s / 86_400, self.day, self.days)
        } else if s.is_multiple_of(3_600) && s >= 3_600 {
            (s / 3_600, self.hour, self.hours)
        } else {
            ((s / 60).max(1), self.minute, self.minutes)
        };
        (if n == 1 { one } else { many }).replace("{n}", &n.to_string())
    }
}

impl Default for Words {
    fn default() -> Self {
        Self::ENGLISH
    }
}
