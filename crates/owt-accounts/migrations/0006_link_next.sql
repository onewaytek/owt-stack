-- owt-accounts 0006: where a sign-in link lands (owt_accounts::links::mint_with). Copy
-- this file into the app's migrations directory as its next unused version, unaltered,
-- if the app keeps copies.
--
-- Schema only: a nullable column with no default, so no rewrite. The path is checked in
-- Rust (links::valid_next) when it is stored and again when it is read.

SET LOCAL lock_timeout = '5s';

ALTER TABLE sign_in_links ADD COLUMN next text;
