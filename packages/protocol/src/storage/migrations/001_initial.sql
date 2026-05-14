-- atHome registry schema — initial migration
-- Compatible with PostgreSQL 14+.

CREATE TABLE IF NOT EXISTS namespaces (
  identity_id TEXT PRIMARY KEY,
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS identity_manifests (
  identity_id   TEXT PRIMARY KEY,
  manifest_json TEXT NOT NULL,
  updated_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS private_identity_records (
  identity_id TEXT PRIMARY KEY,
  record_json TEXT NOT NULL,
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS public_keys (
  identity_id TEXT NOT NULL,
  key_id      TEXT NOT NULL,
  key_json    TEXT NOT NULL,
  PRIMARY KEY (identity_id, key_id)
);

CREATE TABLE IF NOT EXISTS services (
  identity_id  TEXT NOT NULL,
  service_id   TEXT NOT NULL,
  service_json TEXT NOT NULL,
  PRIMARY KEY (identity_id, service_id)
);

CREATE TABLE IF NOT EXISTS agents (
  identity_id TEXT NOT NULL,
  agent_id    TEXT NOT NULL,
  agent_json  TEXT NOT NULL,
  PRIMARY KEY (identity_id, agent_id)
);

CREATE TABLE IF NOT EXISTS capability_tokens (
  identity_id TEXT NOT NULL,
  token_id    TEXT NOT NULL,
  token_json  TEXT NOT NULL,
  PRIMARY KEY (identity_id, token_id)
);

CREATE TABLE IF NOT EXISTS revocations (
  identity_id     TEXT PRIMARY KEY,
  revocation_json TEXT NOT NULL,
  updated_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS registry_events (
  identity_id TEXT    NOT NULL,
  event_id    TEXT    NOT NULL,
  event_index INTEGER NOT NULL,
  event_json  TEXT    NOT NULL,
  event_hash  TEXT    NOT NULL,
  created_at  TEXT    NOT NULL,
  PRIMARY KEY (identity_id, event_id),
  UNIQUE (identity_id, event_index)
);

CREATE TABLE IF NOT EXISTS witness_receipts (
  identity_id   TEXT    NOT NULL,
  receipt_id    TEXT    NOT NULL,
  receipt_index INTEGER NOT NULL,
  receipt_json  TEXT    NOT NULL,
  created_at    TEXT    NOT NULL,
  PRIMARY KEY (identity_id, receipt_id),
  UNIQUE (identity_id, receipt_index)
);

CREATE TABLE IF NOT EXISTS checkpoints (
  identity_id     TEXT PRIMARY KEY,
  checkpoint_json TEXT NOT NULL,
  updated_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS custody_key_records (
  identity_id  TEXT NOT NULL,
  key_id       TEXT NOT NULL,
  record_json  TEXT NOT NULL,
  updated_at   TEXT NOT NULL,
  PRIMARY KEY (identity_id, key_id)
);

CREATE TABLE IF NOT EXISTS replay_nonces (
  scope      TEXT NOT NULL,
  nonce      TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  PRIMARY KEY (scope, nonce)
);

CREATE TABLE IF NOT EXISTS abuse_reviews (
  review_id    TEXT PRIMARY KEY,
  identity_id  TEXT,
  subject_id   TEXT,
  state        TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  created_at   TEXT NOT NULL,
  updated_at   TEXT NOT NULL
);
