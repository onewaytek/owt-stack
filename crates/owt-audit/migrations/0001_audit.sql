-- owt_audit: append-only, hash-chained audit events, one chain per tenant ('' for
-- events with no tenant). The hash covers every column but itself (see the crate's
-- `canonical` module); `prev` is the hash of the chain's previous event.
CREATE TABLE owt_audit_events (
    tenant text NOT NULL CHECK (length(tenant) <= 200),
    seq bigint NOT NULL CHECK (seq >= 1),
    at timestamptz NOT NULL,
    actor text NOT NULL CHECK (length(actor) BETWEEN 1 AND 200),
    actor_kind text NOT NULL CHECK (actor_kind IN ('account', 'service', 'system', 'anonymous')),
    subject text CHECK (length(subject) <= 200),
    action text NOT NULL CHECK (action ~ '^[a-z0-9_.:-]{1,100}$'),
    resource_type text NOT NULL CHECK (resource_type ~ '^[a-z0-9_.:-]{1,100}$'),
    resource_id text CHECK (length(resource_id) <= 200),
    purpose text CHECK (purpose ~ '^[a-z0-9_.:-]{1,100}$'),
    outcome text NOT NULL CHECK (outcome IN ('success', 'failure', 'denied')),
    ip text CHECK (length(ip) <= 45),
    user_agent text CHECK (length(user_agent) <= 512),
    request_id text CHECK (length(request_id) <= 200),
    prev bytea NOT NULL CHECK (length(prev) = 32),
    hash bytea NOT NULL CHECK (length(hash) = 32),
    PRIMARY KEY (tenant, seq)
);
CREATE INDEX owt_audit_events_subject ON owt_audit_events (tenant, subject, at)
    WHERE subject IS NOT NULL;
CREATE INDEX owt_audit_events_actor ON owt_audit_events (tenant, actor, at);
CREATE INDEX owt_audit_events_resource ON owt_audit_events (tenant, resource_type, resource_id, at);

-- Each anchoring of the chains' heads to external storage, as it was sent.
CREATE TABLE owt_audit_anchors (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    at timestamptz NOT NULL DEFAULT now(),
    manifest bytea NOT NULL,
    digest bytea NOT NULL CHECK (length(digest) = 32),
    provider text NOT NULL,
    receipt text NOT NULL
);

-- Rows are never changed or removed: not by the app, not by the table's owner short
-- of dropping these triggers (which the anchors then show).
CREATE FUNCTION owt_audit_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'owt_audit: % on % is refused; audit records are append-only',
        TG_OP, TG_TABLE_NAME
        USING ERRCODE = 'insufficient_privilege';
END
$$;

CREATE TRIGGER owt_audit_events_no_change BEFORE UPDATE OR DELETE ON owt_audit_events
    FOR EACH ROW EXECUTE FUNCTION owt_audit_append_only();
CREATE TRIGGER owt_audit_events_no_truncate BEFORE TRUNCATE ON owt_audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION owt_audit_append_only();
CREATE TRIGGER owt_audit_anchors_no_change BEFORE UPDATE OR DELETE ON owt_audit_anchors
    FOR EACH ROW EXECUTE FUNCTION owt_audit_append_only();
CREATE TRIGGER owt_audit_anchors_no_truncate BEFORE TRUNCATE ON owt_audit_anchors
    FOR EACH STATEMENT EXECUTE FUNCTION owt_audit_append_only();
