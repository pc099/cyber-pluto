/**
 * DDL for the Layer 2 state schema (Architecture §4.2-§4.4), applied
 * idempotently. `tactic`/`technique` on `attempts` are the §5.4 addition
 * ("costs little to add to the schema") — pluto-build invariant 4 requires
 * every attempts row to carry an ATT&CK tag, so they're included from the
 * schema's first version rather than bolted on as a later migration.
 */
export const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS targets (
  id           INTEGER PRIMARY KEY,
  label        TEXT NOT NULL,
  host         TEXT,
  scope_notes  TEXT,
  phase        TEXT NOT NULL DEFAULT 'recon',
  created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS nodes (
  id           INTEGER PRIMARY KEY,
  target_id    INTEGER NOT NULL REFERENCES targets(id),
  parent_id    INTEGER REFERENCES nodes(id),
  node_type    TEXT NOT NULL,
  status       TEXT NOT NULL DEFAULT 'active',
  label        TEXT NOT NULL,
  priority     INTEGER NOT NULL DEFAULT 0,
  created_at   TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_nodes_target_status ON nodes(target_id, status);
CREATE INDEX IF NOT EXISTS idx_nodes_parent        ON nodes(parent_id);

CREATE TABLE IF NOT EXISTS findings (
  id            INTEGER PRIMARY KEY,
  target_id     INTEGER NOT NULL REFERENCES targets(id),
  node_id       INTEGER REFERENCES nodes(id),
  port          INTEGER,
  protocol      TEXT,
  service       TEXT,
  product       TEXT,
  version       TEXT,
  honeypot_susp INTEGER NOT NULL DEFAULT 0,
  confidence    REAL,
  status        TEXT NOT NULL DEFAULT 'candidate',
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS credentials (
  id          INTEGER PRIMARY KEY,
  target_id   INTEGER NOT NULL REFERENCES targets(id),
  node_id     INTEGER REFERENCES nodes(id),
  username    TEXT,
  secret      TEXT,
  secret_type TEXT,
  source      TEXT,
  scope       TEXT,
  validated   INTEGER NOT NULL DEFAULT 0,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS attempts (
  id             INTEGER PRIMARY KEY,
  target_id      INTEGER NOT NULL REFERENCES targets(id),
  node_id        INTEGER REFERENCES nodes(id),
  tool           TEXT NOT NULL,
  command        TEXT NOT NULL,
  started_at     TEXT NOT NULL DEFAULT (datetime('now')),
  finished_at    TEXT,
  outcome        TEXT,
  output_ref     TEXT,
  reasoning_note TEXT,
  tactic         TEXT,
  technique      TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_target_status ON findings(target_id, status);
CREATE INDEX IF NOT EXISTS idx_findings_fingerprint   ON findings(product, version);
CREATE INDEX IF NOT EXISTS idx_attempts_node          ON attempts(node_id);
CREATE INDEX IF NOT EXISTS idx_attempts_tool          ON attempts(tool);

CREATE TABLE IF NOT EXISTS validations (
  id            INTEGER PRIMARY KEY,
  finding_id    INTEGER NOT NULL REFERENCES findings(id),
  validator     TEXT NOT NULL,
  baseline_ref  TEXT,
  attack_ref    TEXT,
  diff_summary  TEXT,
  passed        INTEGER NOT NULL,
  validated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS submissions (
  id             INTEGER PRIMARY KEY,
  finding_id     INTEGER NOT NULL REFERENCES findings(id),
  program        TEXT,
  approved_by    TEXT NOT NULL,
  approved_at    TEXT NOT NULL,
  submitted_at   TEXT,
  platform_ref   TEXT
);

-- Vision-pipeline evidence (§2.3.1): headless-browser screenshots captured at
-- exploitation-relevant moments, fed to Claude's vision and stored alongside
-- findings. The image bytes are an evidence file; this row is the record.
CREATE TABLE IF NOT EXISTS screenshots (
  id          INTEGER PRIMARY KEY,
  target_id   INTEGER NOT NULL REFERENCES targets(id),
  node_id     INTEGER REFERENCES nodes(id),
  finding_id  INTEGER REFERENCES findings(id),
  url         TEXT,
  trigger     TEXT NOT NULL DEFAULT 'manual',
  path        TEXT NOT NULL,
  sha256      TEXT,
  width       INTEGER,
  height      INTEGER,
  note        TEXT,
  captured_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_screenshots_target ON screenshots(target_id);
`;
