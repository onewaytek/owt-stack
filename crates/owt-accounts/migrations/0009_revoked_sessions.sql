-- owt-accounts 0009: sessions signed out one at a time. Copy this file into the app's
-- migrations directory as its next unused version, unaltered, if the app keeps copies.
--
-- Schema only: one new, empty table.

SET LOCAL lock_timeout = '5s';

-- `session::sign_out` records the session's id here, so a copy of its cookie stops
-- opening it; the per-request account load looks the id up by its primary key. A row
-- is pointless once the session's cookie could no longer open anyway (`expires_at`),
-- and sign-outs delete such rows as they go.
CREATE TABLE revoked_sessions (
    id text PRIMARY KEY,
    expires_at timestamptz NOT NULL
);

CREATE INDEX revoked_sessions_expires_at ON revoked_sessions (expires_at);
