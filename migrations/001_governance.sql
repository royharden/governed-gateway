-- Source only: not applied. Caller enables foreign_keys and WAL on a nonsynced local path.
-- INT owns migrations; hash/canonical bytes are verified in application transactions.
PRAGMA user_version = 1;
CREATE TABLE IF NOT EXISTS schema_version(version INTEGER PRIMARY KEY CHECK(version = 1));
INSERT OR IGNORE INTO schema_version(version) VALUES (1);
CREATE TABLE IF NOT EXISTS authority_state(
 authority_id TEXT PRIMARY KEY, config_sha256 TEXT NOT NULL,
 generation INTEGER NOT NULL DEFAULT 0 CHECK(generation >= 0),
 active_policy_sha256 TEXT, active_approval_sha256 TEXT,
 emergency_stop INTEGER NOT NULL DEFAULT 0 CHECK(emergency_stop IN (0,1)),
 incident_halt INTEGER NOT NULL DEFAULT 0 CHECK(incident_halt IN (0,1)),
 max_observed_utc TEXT NOT NULL, halt_reasons_json TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS policy_bundles(hash TEXT PRIMARY KEY, policy_id TEXT NOT NULL, canonical BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS evaluation_authorizations(
 hash TEXT PRIMARY KEY, authority_id TEXT NOT NULL, authorization_id TEXT NOT NULL,
 canonical BLOB NOT NULL, UNIQUE(authority_id,authorization_id)
);
CREATE TABLE IF NOT EXISTS evaluations(
 hash TEXT PRIMARY KEY, authority_id TEXT NOT NULL, evaluation_id TEXT NOT NULL,
 authorization_sha256 TEXT NOT NULL REFERENCES evaluation_authorizations(hash),
 policy_sha256 TEXT NOT NULL REFERENCES policy_bundles(hash),
 canonical BLOB NOT NULL, UNIQUE(authority_id,evaluation_id)
);
CREATE TABLE IF NOT EXISTS decisions(
 hash TEXT PRIMARY KEY, authority_id TEXT NOT NULL, decision_id TEXT NOT NULL,
 action TEXT NOT NULL CHECK(action IN ('approve','reject','revoke')),
 policy_sha256 TEXT NOT NULL REFERENCES policy_bundles(hash),
 evaluation_sha256 TEXT NOT NULL REFERENCES evaluations(hash),
 target_approval_sha256 TEXT, canonical BLOB NOT NULL,
 UNIQUE(authority_id,decision_id)
);
CREATE TABLE IF NOT EXISTS activation_events(
 authority_id TEXT NOT NULL REFERENCES authority_state(authority_id),
 generation INTEGER NOT NULL CHECK(generation > 0),
 expected_generation INTEGER NOT NULL CHECK(expected_generation >= 0),
 event_kind TEXT NOT NULL CHECK(event_kind IN ('activate','rollback')),
 policy_sha256 TEXT NOT NULL REFERENCES policy_bundles(hash),
 evaluation_sha256 TEXT NOT NULL REFERENCES evaluations(hash),
 approval_sha256 TEXT NOT NULL REFERENCES decisions(hash),
 recorded_utc TEXT NOT NULL, hash TEXT NOT NULL UNIQUE, canonical BLOB NOT NULL,
 PRIMARY KEY(authority_id,generation)
);
CREATE TABLE IF NOT EXISTS permits(
 authority_id TEXT NOT NULL REFERENCES authority_state(authority_id),
 operation_id TEXT NOT NULL, permit_id TEXT NOT NULL, hash TEXT NOT NULL UNIQUE,
 policy_sha256 TEXT NOT NULL REFERENCES policy_bundles(hash),
 generation INTEGER NOT NULL CHECK(generation >= 0),
 state TEXT NOT NULL CHECK(state IN ('permitted','funded','abandoned','terminal')),
 expires_utc TEXT NOT NULL, join_sha256 TEXT, canonical BLOB NOT NULL,
 PRIMARY KEY(authority_id,operation_id), UNIQUE(authority_id,permit_id)
);
CREATE TABLE IF NOT EXISTS incident_evidence(
 hash TEXT PRIMARY KEY, authority_id TEXT NOT NULL REFERENCES authority_state(authority_id),
 operation_id TEXT NOT NULL, child_id TEXT NOT NULL, source_sha256 TEXT NOT NULL,
 authenticated INTEGER NOT NULL CHECK(authenticated IN (0,1)),
 conflict INTEGER NOT NULL CHECK(conflict IN (0,1)),
 canonical BLOB NOT NULL,
 UNIQUE(authority_id,operation_id,child_id,source_sha256,hash)
);
CREATE TABLE IF NOT EXISTS incident_maxima(
 authority_id TEXT NOT NULL REFERENCES authority_state(authority_id),
 operation_id TEXT NOT NULL, child_id TEXT NOT NULL,
 terminal_unknown_usd TEXT NOT NULL, maximum_credible_usd TEXT,
 uncovered_excess_usd TEXT NOT NULL, conflict INTEGER NOT NULL DEFAULT 0 CHECK(conflict IN (0,1)),
 canonical BLOB NOT NULL,
 PRIMARY KEY(authority_id,operation_id,child_id)
);
-- Replay ciphertext/tombstone tables will be added by INT after DL4 seam approval.
-- No trigger pretends a dual-store ledger join is an atomic transaction.

-- JOURNEY bridge source tables: unique tombstones outlive ciphertext.
CREATE TABLE IF NOT EXISTS operations(
 authority_id TEXT NOT NULL REFERENCES authority_state(authority_id),
 caller_id TEXT NOT NULL, key_digest TEXT NOT NULL, request_sha256 TEXT NOT NULL,
 operation_id TEXT NOT NULL, permit_sha256 TEXT NOT NULL REFERENCES permits(hash),
 state TEXT NOT NULL, cancelled INTEGER NOT NULL DEFAULT 0 CHECK(cancelled IN (0,1)),
 created_utc TEXT NOT NULL, deadline_utc TEXT NOT NULL,
 terminal_utc TEXT, result_expires_utc TEXT, settlement_sha256 TEXT,
 settlement_canonical BLOB, join_canonical BLOB, replay_attempt_id TEXT,
 PRIMARY KEY(authority_id,caller_id,key_digest), UNIQUE(authority_id,operation_id)
);
CREATE TABLE IF NOT EXISTS replay_results(
 authority_id TEXT NOT NULL, operation_id TEXT NOT NULL, attempt_id TEXT NOT NULL,
 key_id TEXT NOT NULL, nonce BLOB, ciphertext BLOB,
 result_sha256 TEXT NOT NULL, binding_canonical BLOB NOT NULL,
 binding_sha256 TEXT NOT NULL, receipt_sha256 TEXT NOT NULL, receipt_canonical BLOB NOT NULL,
 staged_utc TEXT NOT NULL, purged_utc TEXT,
 PRIMARY KEY(authority_id,operation_id,attempt_id),
 FOREIGN KEY(authority_id,operation_id) REFERENCES operations(authority_id,operation_id),
 CHECK((nonce IS NOT NULL AND ciphertext IS NOT NULL AND purged_utc IS NULL)
    OR (nonce IS NULL AND ciphertext IS NULL AND purged_utc IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS governance_events(
 authority_id TEXT NOT NULL REFERENCES authority_state(authority_id),
 hash TEXT NOT NULL, event_kind TEXT NOT NULL, recorded_utc TEXT NOT NULL,
 canonical BLOB NOT NULL, PRIMARY KEY(authority_id,hash)
);
