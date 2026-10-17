-- owt-accounts 0005: accounts an app reaches by a key of its own rather than a
-- provider's (owt_accounts::identities::arrive_as), and accounts no password opens.
-- Copy this file into the app's migrations directory as its next unused version,
-- unaltered, and await owt_accounts::migrations::complete before serving: it validates
-- the constraint this file adds.
--
-- Schema only, so it holds its locks for moments: the new column's default is a
-- constant (no rewrite), and the constraint is added NOT VALID (no scan).

SET LOCAL lock_timeout = '5s';

-- Off: no password opens the account. owt_accounts::store::authenticate never finds
-- it, by username or email, and no password can be set on it.
ALTER TABLE accounts ADD COLUMN password_sign_in boolean NOT NULL DEFAULT true;
ALTER TABLE accounts ADD CONSTRAINT accounts_password_sign_in_hash
    CHECK (password_sign_in OR password_hash = '') NOT VALID;

-- An identity the app vouches for itself: `subject` in a namespace `key` it chose
-- (`kiosk`, `system`). Apart from account_identities, so no provider's subject can
-- ever match one, and no connections page lists or removes one.
CREATE TABLE account_local_identities (
    account_id bigint NOT NULL REFERENCES accounts ON DELETE CASCADE,
    key text NOT NULL CHECK (key <> ''),
    subject text NOT NULL CHECK (subject <> ''),
    created_at timestamptz NOT NULL DEFAULT now(),
    last_sign_in timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (key, subject)
);
CREATE INDEX account_local_identities_account ON account_local_identities (account_id);
