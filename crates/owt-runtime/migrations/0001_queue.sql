-- owt_runtime::queue: durable jobs, one row each, shared by every queue of the app.
CREATE TABLE owt_jobs (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    queue text NOT NULL CHECK (queue ~ '^[a-z0-9_.-]{1,64}$'),
    idempotency_key text CHECK (length(idempotency_key) BETWEEN 1 AND 200),
    -- Opaque to the library; emptied when the job is done.
    payload bytea NOT NULL,
    state text NOT NULL DEFAULT 'queued'
        CHECK (state IN ('queued', 'running', 'done', 'dead')),
    -- Claims so far, the current one included; also the claim's fencing token.
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    max_attempts integer NOT NULL CHECK (max_attempts >= 1),
    run_at timestamptz NOT NULL DEFAULT now(),
    claimed_at timestamptz,
    heartbeat_at timestamptz,
    last_error text,
    created_at timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz,
    CHECK ((state = 'running') = (heartbeat_at IS NOT NULL)),
    CHECK ((state IN ('done', 'dead')) = (finished_at IS NOT NULL))
);

-- One job per key and queue while its row lasts (done rows are purged after a while).
CREATE UNIQUE INDEX owt_jobs_idempotency ON owt_jobs (queue, idempotency_key)
    WHERE idempotency_key IS NOT NULL;
-- The claim's scan: due jobs of a queue, oldest first.
CREATE INDEX owt_jobs_due ON owt_jobs (queue, run_at, id) WHERE state = 'queued';
-- Stale-claim recovery.
CREATE INDEX owt_jobs_running ON owt_jobs (queue, heartbeat_at) WHERE state = 'running';
-- Purging done jobs and listing dead ones.
CREATE INDEX owt_jobs_finished ON owt_jobs (queue, state, finished_at)
    WHERE state IN ('done', 'dead');
