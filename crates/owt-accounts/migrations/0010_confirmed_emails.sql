-- owt-accounts 0010: the addresses an account has proven (owt_accounts::confirmed_emails).
-- Copy this file into the app's migrations directory as its next unused version,
-- unaltered, if the app keeps copies.
--
-- Two nullable columns with no default, so no rewrite, and one UPDATE of the identities.
--
-- `sign_in_links.sent_to`: the address a link was emailed to (links::mint_emailed),
-- normalized as `accounts.email` is; NULL for a link handed over any other way. A link
-- minted before this column existed has NULL and proves no address: which address it
-- reached is not recorded, and the account's current email may have changed since. An
-- account proves its address again with one emailed sign-in.
--
-- `account_identities.verified_email`: the provider's email for the identity when the
-- provider says it checked it (owt_auth::oauth::Identity::email_verified), as the
-- provider sent it; NULL otherwise. Sign-in and linking write it from the provider's
-- own judgement. The UPDATE below fills it for identities already linked, reading
-- their stored claims as owt-auth's built-in providers read the user-info response:
-- Discord's `verified`, Twitch's email whenever present (Twitch returns only a verified
-- one), and `email_verified` as a JSON `true` for every other provider (Google, OpenID
-- Connect). The next sign-in through the provider rewrites it.

SET LOCAL lock_timeout = '5s';

ALTER TABLE sign_in_links ADD COLUMN sent_to text;

ALTER TABLE account_identities ADD COLUMN verified_email text;

UPDATE account_identities SET verified_email = claims->>'email'
WHERE coalesce(claims->>'email', '') <> ''
  AND CASE provider
        WHEN 'discord' THEN claims->'verified' = 'true'::jsonb
        WHEN 'twitch' THEN jsonb_typeof(claims->'email') = 'string'
        ELSE claims->'email_verified' = 'true'::jsonb
      END;
