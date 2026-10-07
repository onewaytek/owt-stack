-- owt-accounts: the tables its functions read and write. Copy this file into the
-- app's migrations directory (owt_accounts::migrations::assert_installed checks it
-- is there, unaltered); the app's own tables reference accounts(id).

CREATE TABLE accounts (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- Stored lower-cased and trimmed; owt_accounts::normalize does it before every
    -- lookup, so the constraint only guards writes made around the library.
    username text NOT NULL UNIQUE CHECK (username = lower(btrim(username)) AND username <> ''),
    -- Optional; also a way to sign in. Unique where present, case-insensitively.
    email text NOT NULL DEFAULT '',
    -- Argon2 PHC string. Empty: no password opens this account (a provider identity
    -- or a sign-in link does).
    password_hash text NOT NULL DEFAULT '',
    is_staff boolean NOT NULL DEFAULT false,
    is_active boolean NOT NULL DEFAULT true,
    -- Copied into the session at sign-in and compared on every request: bumping it
    -- signs the account out everywhere.
    session_epoch integer NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_sign_in timestamptz
);
CREATE UNIQUE INDEX accounts_email_key ON accounts (lower(email)) WHERE email <> '';

-- An identity a provider vouches for (Google, Discord, an OIDC issuer), linked to
-- the account it signs in. `subject` is the provider's stable id for the person.
CREATE TABLE account_identities (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    account_id bigint NOT NULL REFERENCES accounts ON DELETE CASCADE,
    provider text NOT NULL,
    subject text NOT NULL,
    -- The provider's user-info response at the last sign-in, for whatever the app
    -- shows (a display name, an avatar).
    claims jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_sign_in timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT account_identities_provider_subject_key UNIQUE (provider, subject)
);
CREATE INDEX account_identities_account ON account_identities (account_id);

-- One-time sign-in links: the way in when nothing else works, minted by an
-- operator. Only the SHA-256 of the token is stored, so a database read yields no
-- usable link. Rows are kept as an audit trail.
CREATE TABLE sign_in_links (
    token_sha256 bytea PRIMARY KEY,
    account_id bigint NOT NULL REFERENCES accounts ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    reason text NOT NULL DEFAULT '',
    used_at timestamptz,
    used_from text
);
CREATE INDEX sign_in_links_account ON sign_in_links (account_id, created_at DESC);
