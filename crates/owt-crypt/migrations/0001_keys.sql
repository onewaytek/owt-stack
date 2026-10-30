-- owt_crypt: each scope's keys, only ever stored wrapped by a KEK.
CREATE TABLE owt_crypt_keys (
    scope text NOT NULL CHECK (length(scope) BETWEEN 1 AND 200),
    purpose text NOT NULL CHECK (purpose IN ('data', 'index')),
    version integer NOT NULL CHECK (version >= 1),
    -- The KEK that wrapped it (`local:<name>`, `yubihsm:0x0064`).
    kek_id text NOT NULL CHECK (length(kek_id) BETWEEN 1 AND 200),
    wrapped bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (scope, purpose, version)
);
-- Rewrapping finds the keys under an old KEK.
CREATE INDEX owt_crypt_keys_kek ON owt_crypt_keys (kek_id);
-- A shredded scope never gets keys again: `shred` records it here in the same
-- transaction that deletes the keys, and key creation refuses a recorded scope.
CREATE TABLE owt_crypt_shredded (
    scope text PRIMARY KEY CHECK (length(scope) BETWEEN 1 AND 200),
    at timestamptz NOT NULL DEFAULT now()
);
