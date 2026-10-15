-- owt-accounts 0003: the tables hold what the library assumes. Copy this file into the
-- app's migrations directory after 0002, unaltered, then call
-- owt_accounts::migrations::complete once the migrations have run (it fills the
-- lookalike keys, which SQL cannot compute). Existing rows are moved to the stored form
-- first, so every constraint below holds for every row, old ones included.

-- A password hash the library cannot read (a legacy format, a damaged value) opens
-- nothing, so it is no password: empty, as the library writes "none".
UPDATE accounts SET password_hash = ''
 WHERE password_hash <> '' AND password_hash NOT LIKE '$argon2%$v=%$m=%,t=%,p=%$%$%';
ALTER TABLE accounts ADD CONSTRAINT accounts_password_hash_form
    CHECK (password_hash = '' OR password_hash LIKE '$argon2%$v=%$m=%,t=%,p=%$%$%');

-- Usernames NFKC-normalized, as owt_accounts::store::normalize stores them, or the
-- owner's login (normalized as it is typed) would never match. A name that would
-- become another's (`ａｄｍｉｎ` beside `admin`) keeps its account's id as a suffix.
WITH target AS (
    SELECT id, replace(lower(normalize(username, NFKC)), '@', '-') AS name
    FROM accounts WHERE username IS NOT NFKC NORMALIZED
)
UPDATE accounts a SET username = CASE
        WHEN EXISTS (SELECT 1 FROM accounts b WHERE b.username = t.name AND b.id <> a.id)
          OR (SELECT count(*) FROM target u WHERE u.name = t.name) > 1
        THEN t.name || '-' || a.id
        ELSE t.name
    END
  FROM target t WHERE a.id = t.id;
ALTER TABLE accounts ADD CONSTRAINT accounts_username_nfkc CHECK (username IS NFKC NORMALIZED);

-- Emails in the same stored form, and one address each. An address that would become
-- another account's is cleared (the account keeps its other ways in); one with nothing
-- before its `@` is no address.
UPDATE accounts SET email = '' WHERE email <> '' AND position('@' IN email) <= 1;
UPDATE accounts SET email = lower(email) WHERE email <> lower(email);
WITH target AS (
    SELECT id, lower(normalize(email, NFKC)) AS addr
    FROM accounts WHERE email <> '' AND email IS NOT NFKC NORMALIZED
)
UPDATE accounts a SET email = CASE
        WHEN EXISTS (SELECT 1 FROM accounts b WHERE b.email = t.addr AND b.id <> a.id)
          OR (SELECT count(*) FROM target u WHERE u.addr = t.addr) > 1
        THEN ''
        ELSE t.addr
    END
  FROM target t WHERE a.id = t.id;
ALTER TABLE accounts ADD CONSTRAINT accounts_email_form
    CHECK (email = '' OR (email = lower(email) AND email IS NFKC NORMALIZED
                          AND position('@' IN email) > 1));
-- Stored lower-case now, so the index is on the column the lookups use.
DROP INDEX accounts_email_key;
CREATE UNIQUE INDEX accounts_email_key ON accounts (email) WHERE email <> '';

-- The username's confusable skeleton (Unicode TS #39), lower-cased: names a reader
-- cannot tell apart (`paypal` and `paypa1`, `coco` and the Cyrillic `сосо`) share one,
-- so the second is refused. The library writes it with each account;
-- owt_accounts::migrations::complete fills it for rows made before.
ALTER TABLE accounts ADD COLUMN username_skeleton text
    CONSTRAINT accounts_username_skeleton_key UNIQUE
    CHECK (username_skeleton <> '');

ALTER TABLE accounts ADD CONSTRAINT accounts_session_epoch_check CHECK (session_epoch >= 0);

-- An identity with no subject is nobody: nothing could ever match it.
DELETE FROM account_identities WHERE provider = '' OR subject = '';
ALTER TABLE account_identities ADD CONSTRAINT account_identities_named
    CHECK (provider <> '' AND subject <> '');

-- A sign-in link lives 30 days at most (owt_accounts::links::MAX_TTL); longer ones
-- still out are cut to that.
UPDATE sign_in_links SET expires_at = created_at + interval '30 days'
 WHERE expires_at > created_at + interval '30 days';
ALTER TABLE sign_in_links ADD CONSTRAINT sign_in_links_lifetime
    CHECK (expires_at <= created_at + interval '30 days');
ALTER TABLE sign_in_links ADD CONSTRAINT sign_in_links_digest
    CHECK (octet_length(token_sha256) = 32);
