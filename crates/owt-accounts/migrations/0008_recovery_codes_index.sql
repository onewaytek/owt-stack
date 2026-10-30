-- owt-accounts 0008: an index on every recovery code of an account. Copy this file into
-- the app's migrations directory as its next unused version, unaltered, if the app
-- keeps copies.
--
-- Schema only: one new index, nothing rewritten.

SET LOCAL lock_timeout = '5s';

-- 0007 indexes only the unused codes. Replacing an account's codes and removing an
-- account delete every row of it, used or not, and those deletes read them all by this
-- index.
CREATE INDEX account_recovery_codes_account_all ON account_recovery_codes (account_id);
