-- owt_audit: append-only, hash-chained audit events, one chain per tenant ('' for
-- events with no tenant). The hash covers every column but itself (see the crate's
-- `canonical` module); `prev` is the hash of the chain's previous event. The
-- database assigns seq, at, prev and hash (owt_audit_chain, below): whatever an
-- insert says for them is replaced.
CREATE TABLE owt_audit_events (
    tenant text NOT NULL CHECK (length(tenant) <= 200 AND tenant !~ '[[:cntrl:]]'),
    seq bigint NOT NULL CHECK (seq >= 1),
    at timestamptz NOT NULL,
    actor text NOT NULL CHECK (length(actor) BETWEEN 1 AND 200 AND actor !~ '[[:cntrl:]]'),
    actor_kind text NOT NULL CHECK (actor_kind IN ('account', 'service', 'system', 'anonymous')),
    subject text CHECK (length(subject) <= 200 AND subject !~ '[[:cntrl:]]'),
    action text NOT NULL CHECK (action ~ '^[a-z0-9_.:-]{1,100}$'),
    resource_type text NOT NULL CHECK (resource_type ~ '^[a-z0-9_.:-]{1,100}$'),
    resource_id text CHECK (length(resource_id) <= 200 AND resource_id !~ '[[:cntrl:]]'),
    purpose text CHECK (purpose ~ '^[a-z0-9_.:-]{1,100}$'),
    outcome text NOT NULL CHECK (outcome IN ('success', 'failure', 'denied')),
    -- As the app's IpAddr displays it; hashed as stored.
    ip text CHECK (ip ~ '^[0-9A-Fa-f:.]{2,45}$'),
    user_agent text CHECK (length(user_agent) <= 512 AND user_agent !~ '[[:cntrl:]]'),
    request_id text CHECK (length(request_id) <= 200 AND request_id !~ '[[:cntrl:]]'),
    prev bytea NOT NULL CHECK (length(prev) = 32),
    hash bytea NOT NULL CHECK (length(hash) = 32),
    PRIMARY KEY (tenant, seq)
);
CREATE INDEX owt_audit_events_subject ON owt_audit_events (tenant, subject, at)
    WHERE subject IS NOT NULL;
CREATE INDEX owt_audit_events_actor ON owt_audit_events (tenant, actor, at);
CREATE INDEX owt_audit_events_resource ON owt_audit_events (tenant, resource_type, resource_id, at);

-- A text field in the canonical encoding: its UTF-8 length (4 bytes, big-endian)
-- and bytes, or 0xFFFFFFFF alone for NULL.
CREATE FUNCTION owt_audit_lp(t text) RETURNS bytea LANGUAGE sql IMMUTABLE AS $$
    SELECT CASE WHEN t IS NULL THEN '\xffffffff'::bytea
                ELSE int4send(octet_length(convert_to(t, 'UTF8'))) || convert_to(t, 'UTF8')
           END
$$;

-- Each event joins its tenant's chain here, so no insert, by any role, chooses its
-- place, time or hash. Appends to one chain are serialized by a transaction-scoped
-- advisory lock; under REPEATABLE READ or SERIALIZABLE the chain's last event could
-- be read from a snapshot older than the lock, so those are refused.
CREATE FUNCTION owt_audit_chain() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    last_seq bigint;
    last_hash bytea;
    us bigint;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'owt_audit: record events under READ COMMITTED, not %',
            current_setting('transaction_isolation');
    END IF;
    PERFORM pg_advisory_xact_lock(1870099553, hashtext(NEW.tenant));
    SELECT e.seq, e.hash INTO last_seq, last_hash FROM owt_audit_events e
    WHERE e.tenant = NEW.tenant ORDER BY e.seq DESC LIMIT 1;
    us := floor(extract(epoch FROM clock_timestamp()) * 1000000)::bigint;
    NEW.seq := COALESCE(last_seq, 0) + 1;
    NEW.prev := COALESCE(last_hash, decode(repeat('00', 32), 'hex'));
    NEW.at := timestamptz 'epoch' + us * interval '1 microsecond';
    NEW.hash := sha256(
        convert_to('owt-audit/event/v1', 'UTF8') || '\x00'::bytea
        || owt_audit_lp(NEW.tenant) || int8send(NEW.seq) || int8send(us)
        || owt_audit_lp(NEW.actor) || owt_audit_lp(NEW.actor_kind)
        || owt_audit_lp(NEW.subject) || owt_audit_lp(NEW.action)
        || owt_audit_lp(NEW.resource_type) || owt_audit_lp(NEW.resource_id)
        || owt_audit_lp(NEW.purpose) || owt_audit_lp(NEW.outcome)
        || owt_audit_lp(NEW.ip) || owt_audit_lp(NEW.user_agent)
        || owt_audit_lp(NEW.request_id) || NEW.prev);
    RETURN NEW;
END
$$;

CREATE TRIGGER owt_audit_events_chain BEFORE INSERT ON owt_audit_events
    FOR EACH ROW EXECUTE FUNCTION owt_audit_chain();

-- Each anchoring of the chains' heads to external storage, as it was sent.
CREATE TABLE owt_audit_anchors (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    at timestamptz NOT NULL DEFAULT now(),
    manifest bytea NOT NULL,
    digest bytea NOT NULL CHECK (length(digest) = 32),
    provider text NOT NULL,
    receipt text NOT NULL
);

-- Rows are never changed or removed while these triggers stand. Only the tables'
-- owner can drop or disable them; the anchors show a chain rewritten that way.
CREATE FUNCTION owt_audit_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'owt_audit: % on % is refused; audit records are append-only',
        TG_OP, TG_TABLE_NAME;
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
