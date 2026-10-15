-- owt-accounts 0002: the roles an app defines (owt_accounts::roles::Role), held by
-- accounts. Copy this file into the app's migrations directory after 0001, unaltered.
-- Every account is a user; staff is accounts.is_staff; anything else is a row here.
CREATE TABLE account_roles (
    account_id bigint NOT NULL REFERENCES accounts ON DELETE CASCADE,
    -- The role's name, as the app's Role declares it: lower-case, a letter first,
    -- and not a built-in tier's (or the admin's other filter's) name.
    role text NOT NULL CHECK (role ~ '^[a-z][a-z0-9_]{0,62}$'
                              AND role NOT IN ('user', 'staff', 'inactive')),
    -- Who granted it, while that account exists.
    granted_by bigint REFERENCES accounts ON DELETE SET NULL,
    granted_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, role)
);
CREATE INDEX account_roles_role ON account_roles (role);
