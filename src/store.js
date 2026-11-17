import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";

export function createStore(path) {
  if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path);
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;
    CREATE TABLE IF NOT EXISTS connect_sessions (
      id TEXT PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL, tenant_id TEXT NOT NULL,
      external_user_id TEXT NOT NULL, provider TEXT NOT NULL, return_url TEXT NOT NULL,
      scopes_json TEXT NOT NULL, expires_at INTEGER NOT NULL, used_at INTEGER, created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS oauth_states (
      state_hash TEXT PRIMARY KEY, session_id TEXT NOT NULL, tenant_id TEXT NOT NULL,
      verifier_ciphertext TEXT NOT NULL, expires_at INTEGER NOT NULL, consumed_at INTEGER,
      FOREIGN KEY(session_id) REFERENCES connect_sessions(id)
    );
    CREATE TABLE IF NOT EXISTS connections (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, external_user_id TEXT NOT NULL,
      provider TEXT NOT NULL, credentials_ciphertext TEXT NOT NULL, scopes_json TEXT NOT NULL,
      status TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
      UNIQUE(tenant_id, external_user_id, provider)
    );
    CREATE INDEX IF NOT EXISTS idx_connections_tenant ON connections(tenant_id, external_user_id);
    CREATE TABLE IF NOT EXISTS workflows (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, name TEXT NOT NULL,
      version INTEGER NOT NULL, definition_json TEXT NOT NULL, source TEXT NOT NULL,
      created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
      UNIQUE(tenant_id, name, version)
    );
    CREATE INDEX IF NOT EXISTS idx_workflows_tenant ON workflows(tenant_id, name);
    CREATE TABLE IF NOT EXISTS workflow_runs (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, workflow_id TEXT NOT NULL,
      connection_id TEXT NOT NULL, status TEXT NOT NULL, steps_json TEXT NOT NULL,
      error TEXT, started_at INTEGER NOT NULL, finished_at INTEGER,
      FOREIGN KEY(workflow_id) REFERENCES workflows(id)
    );
    CREATE INDEX IF NOT EXISTS idx_workflow_runs_tenant ON workflow_runs(tenant_id, workflow_id, started_at);
  `);

  return {
    db,
    createSession(s) { db.prepare(`INSERT INTO connect_sessions VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)`).run(s.id, s.tokenHash, s.tenantId, s.externalUserId, s.provider, s.returnUrl, JSON.stringify(s.scopes), s.expiresAt, s.createdAt); },
    sessionByTokenHash(hash) { return db.prepare(`SELECT * FROM connect_sessions WHERE token_hash = ?`).get(hash); },
    sessionById(id) { return db.prepare(`SELECT * FROM connect_sessions WHERE id = ?`).get(id); },
    useSession(id, now) { return db.prepare(`UPDATE connect_sessions SET used_at = ? WHERE id = ? AND used_at IS NULL AND expires_at > ?`).run(now, id, now).changes === 1; },
    createState(s) { db.prepare(`INSERT INTO oauth_states VALUES (?, ?, ?, ?, ?, NULL)`).run(s.stateHash, s.sessionId, s.tenantId, s.verifierCiphertext, s.expiresAt); },
    consumeState(hash, now) {
      const tx = db.prepare(`UPDATE oauth_states SET consumed_at = ? WHERE state_hash = ? AND consumed_at IS NULL AND expires_at > ?`);
      if (tx.run(now, hash, now).changes !== 1) return null;
      return db.prepare(`SELECT * FROM oauth_states WHERE state_hash = ?`).get(hash);
    },
    upsertConnection(c) {
      db.prepare(`INSERT INTO connections VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?) ON CONFLICT(tenant_id, external_user_id, provider) DO UPDATE SET credentials_ciphertext=excluded.credentials_ciphertext, scopes_json=excluded.scopes_json, status='active', updated_at=excluded.updated_at`).run(c.id, c.tenantId, c.externalUserId, c.provider, c.credentialsCiphertext, JSON.stringify(c.scopes), c.now, c.now);
      return db.prepare(`SELECT id FROM connections WHERE tenant_id=? AND external_user_id=? AND provider=?`).get(c.tenantId, c.externalUserId, c.provider).id;
    },
    updateCredentials(id, tenantId, ciphertext, updatedAt) { return db.prepare(`UPDATE connections SET credentials_ciphertext=?, updated_at=? WHERE id=? AND tenant_id=? AND status='active'`).run(ciphertext, updatedAt, id, tenantId).changes === 1; },
    connection(id, tenantId) { return db.prepare(`SELECT * FROM connections WHERE id = ? AND tenant_id = ? AND status = 'active'`).get(id, tenantId); },
    connections(tenantId, userId) { return db.prepare(`SELECT id, external_user_id, provider, scopes_json, status, created_at, updated_at FROM connections WHERE tenant_id = ? AND (? IS NULL OR external_user_id = ?) AND status = 'active' ORDER BY created_at DESC`).all(tenantId, userId ?? null, userId ?? null); },
    disconnect(id, tenantId, now) { return db.prepare(`UPDATE connections SET status='revoked', credentials_ciphertext='', updated_at=? WHERE id=? AND tenant_id=? AND status='active'`).run(now, id, tenantId).changes === 1; },
    createWorkflow(w) { db.prepare(`INSERT INTO workflows VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).run(w.id, w.tenantId, w.name, w.version, JSON.stringify(w.definition), w.source, w.now, w.now); },
    nextWorkflowVersion(tenantId, name) { return Number(db.prepare(`SELECT COALESCE(MAX(version),0)+1 AS version FROM workflows WHERE tenant_id=? AND name=?`).get(tenantId, name).version); },
    workflow(id, tenantId) { return db.prepare(`SELECT * FROM workflows WHERE id=? AND tenant_id=?`).get(id, tenantId); },
    workflows(tenantId) { return db.prepare(`SELECT id,name,version,source,created_at,updated_at FROM workflows WHERE tenant_id=? ORDER BY name,version DESC`).all(tenantId); },
    createRun(r) { db.prepare(`INSERT INTO workflow_runs VALUES (?, ?, ?, ?, 'running', '[]', NULL, ?, NULL)`).run(r.id,r.tenantId,r.workflowId,r.connectionId,r.startedAt); },
    finishRun(id, tenantId, status, steps, error, finishedAt) { db.prepare(`UPDATE workflow_runs SET status=?,steps_json=?,error=?,finished_at=? WHERE id=? AND tenant_id=?`).run(status,JSON.stringify(steps),error,finishedAt,id,tenantId); },
    run(id, tenantId) { return db.prepare(`SELECT * FROM workflow_runs WHERE id=? AND tenant_id=?`).get(id,tenantId); },
    close() { db.close(); },
  };
}
