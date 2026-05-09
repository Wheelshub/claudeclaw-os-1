import path from 'path';

import Database from 'better-sqlite3';

import { STORE_DIR } from '../../src/config.js';

export const description =
  'Add dashboard_sessions, dashboard_oidc_requests, and dashboard_audit tables for OIDC dashboard auth';

const UP_STATEMENTS: string[] = [
  `CREATE TABLE IF NOT EXISTS dashboard_sessions (
    id              TEXT PRIMARY KEY,
    created_at      INTEGER NOT NULL,
    last_seen_at    INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    user_oid        TEXT NOT NULL,
    user_upn        TEXT NOT NULL,
    user_name       TEXT,
    tenant_id       TEXT NOT NULL,
    roles           TEXT NOT NULL,
    id_token_hash   TEXT NOT NULL,
    user_agent      TEXT,
    ip              TEXT,
    revoked_at      INTEGER
  )`,
  `CREATE INDEX IF NOT EXISTS idx_dashboard_sessions_expires
    ON dashboard_sessions(expires_at) WHERE revoked_at IS NULL`,
  `CREATE INDEX IF NOT EXISTS idx_dashboard_sessions_user_oid
    ON dashboard_sessions(user_oid)`,

  `CREATE TABLE IF NOT EXISTS dashboard_oidc_requests (
    state           TEXT PRIMARY KEY,
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    pkce_verifier   TEXT NOT NULL,
    nonce           TEXT NOT NULL,
    redirect_uri    TEXT NOT NULL,
    return_to       TEXT NOT NULL,
    tx_binding_hash TEXT NOT NULL,
    consumed_at     INTEGER
  )`,
  `CREATE INDEX IF NOT EXISTS idx_dashboard_oidc_requests_expires
    ON dashboard_oidc_requests(expires_at)`,

  `CREATE TABLE IF NOT EXISTS dashboard_audit (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at      INTEGER NOT NULL,
    event           TEXT NOT NULL,
    reason          TEXT,
    user_oid        TEXT,
    user_upn        TEXT,
    session_id      TEXT,
    state           TEXT,
    ip              TEXT,
    user_agent      TEXT,
    details         TEXT
  )`,
  `CREATE INDEX IF NOT EXISTS idx_dashboard_audit_created
    ON dashboard_audit(created_at)`,
  `CREATE INDEX IF NOT EXISTS idx_dashboard_audit_event
    ON dashboard_audit(event, created_at)`,
];

const DOWN_STATEMENTS: string[] = [
  `DROP INDEX IF EXISTS idx_dashboard_audit_event`,
  `DROP INDEX IF EXISTS idx_dashboard_audit_created`,
  `DROP TABLE IF EXISTS dashboard_audit`,

  `DROP INDEX IF EXISTS idx_dashboard_oidc_requests_expires`,
  `DROP TABLE IF EXISTS dashboard_oidc_requests`,

  `DROP INDEX IF EXISTS idx_dashboard_sessions_user_oid`,
  `DROP INDEX IF EXISTS idx_dashboard_sessions_expires`,
  `DROP TABLE IF EXISTS dashboard_sessions`,
];

function openDb(): Database.Database {
  return new Database(path.join(STORE_DIR, 'claudeclaw.db'));
}

function applyAll(db: Database.Database, statements: string[]): void {
  for (const stmt of statements) {
    db.prepare(stmt).run();
  }
}

export async function run(): Promise<void> {
  const db = openDb();
  try {
    db.transaction(() => applyAll(db, UP_STATEMENTS))();
  } finally {
    db.close();
  }
}

// Not auto-invoked by scripts/migrate.ts (the runner only calls run()).
// Operator imports + invokes manually for emergency rollback.
// Wrapped in a transaction so a partial drop can't leave a broken schema.
export async function down(): Promise<void> {
  const db = openDb();
  try {
    db.transaction(() => applyAll(db, DOWN_STATEMENTS))();
  } finally {
    db.close();
  }
}
