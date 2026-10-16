-- owt-accounts 0003: the tables hold what the library assumes. Copy this file into the
-- app's migrations directory as its next unused version, unaltered, and await
-- owt_accounts::migrations::complete before serving: it moves the rows already there
-- to the form the library stores (in Rust, as sign-in normalizes what is typed, which
-- SQL cannot reproduce exactly), then validates the constraints this file adds.
--
-- Schema only, so it holds its locks for moments: every constraint is added NOT VALID
-- (it binds each write from now on, and old rows are checked once complete has moved
-- them), and nothing here rewrites or scans a table. A deploy that cannot have its
-- locks within the timeout fails, rather than stalling every request behind it; run
-- it again.

SET LOCAL lock_timeout = '5s';
-- All three at once, in one order, so no running 0.4 statement deadlocks with this.
LOCK TABLE accounts, account_identities, sign_in_links IN ACCESS EXCLUSIVE MODE;

-- The username's confusable skeleton (Unicode TS #39), lower-cased: names a reader
-- cannot tell apart (`paypal` and `paypa1`, `coco` and the Cyrillic `сосо`) share one,
-- so the second is refused. The library writes it with each account; complete fills it
-- for rows made before (and a row with none is checked against as if it had one).
ALTER TABLE accounts ADD COLUMN username_skeleton text
    CONSTRAINT accounts_username_skeleton_form CHECK (username_skeleton <> '');
CREATE UNIQUE INDEX accounts_username_skeleton_key ON accounts (username_skeleton);

-- A password hash is an Argon2 PHC string (its version field optional, as the
-- verifier takes it) or nothing; complete clears the rest (a legacy format, a damaged
-- value), which open nothing.
ALTER TABLE accounts ADD CONSTRAINT accounts_password_hash_form
    CHECK (password_hash = '' OR password_hash LIKE '$argon2%$%m=%,t=%,p=%$%$%') NOT VALID;

-- Usernames NFKC-normalized, as owt_accounts::store::normalize stores them, so the
-- owner's login (normalized as it is typed) matches.
ALTER TABLE accounts ADD CONSTRAINT accounts_username_nfkc
    CHECK (username IS NFKC NORMALIZED) NOT VALID;

-- Emails in the same stored form, with something before the `@`.
ALTER TABLE accounts ADD CONSTRAINT accounts_email_form
    CHECK (email = '' OR (email = lower(email) AND email IS NFKC NORMALIZED
                          AND position('@' IN email) > 1)) NOT VALID;

ALTER TABLE accounts ADD CONSTRAINT accounts_session_epoch_check
    CHECK (session_epoch >= 0) NOT VALID;

-- An identity with no subject is nobody: nothing could ever match it.
ALTER TABLE account_identities ADD CONSTRAINT account_identities_named
    CHECK (provider <> '' AND subject <> '') NOT VALID;

-- A sign-in link lives 30 days at most (owt_accounts::links::MAX_TTL), and is known by
-- a SHA-256.
ALTER TABLE sign_in_links ADD CONSTRAINT sign_in_links_lifetime
    CHECK (expires_at <= created_at + interval '30 days') NOT VALID;
ALTER TABLE sign_in_links ADD CONSTRAINT sign_in_links_digest
    CHECK (octet_length(token_sha256) = 32) NOT VALID;
