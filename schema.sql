PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS sites (
  id TEXT PRIMARY KEY,
  slug TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  target_url TEXT NOT NULL UNIQUE,
  mode TEXT NOT NULL CHECK (mode IN ('redirect', 'protected')),
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS visitors (
  visitor_id TEXT PRIMARY KEY,
  nickname TEXT,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  visits INTEGER NOT NULL DEFAULT 0,
  user_agent TEXT,
  browser TEXT,
  operating_system TEXT,
  device_type TEXT,
  country TEXT,
  region TEXT,
  city TEXT,
  timezone TEXT,
  language TEXT,
  screen_size TEXT,
  ip_hash TEXT,
  consented_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS access_logs (
  id TEXT PRIMARY KEY,
  visitor_id TEXT,
  site_id TEXT NOT NULL,
  site_slug TEXT NOT NULL,
  accessed_at TEXT NOT NULL,
  exited_at TEXT,
  path TEXT NOT NULL,
  access_mode TEXT NOT NULL CHECK (access_mode IN ('redirect', 'protected')),
  outcome TEXT NOT NULL DEFAULT 'allowed',
  FOREIGN KEY (visitor_id) REFERENCES visitors(visitor_id) ON DELETE SET NULL,
  FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_access_logs_accessed_at ON access_logs(accessed_at DESC);
CREATE INDEX IF NOT EXISTS idx_access_logs_visitor ON access_logs(visitor_id, accessed_at DESC);
CREATE INDEX IF NOT EXISTS idx_access_logs_site ON access_logs(site_id, accessed_at DESC);
CREATE INDEX IF NOT EXISTS idx_visitors_last_seen ON visitors(last_seen DESC);

-- Primer sitio de ejemplo: Vitrasa Chase protegido.
-- Cambia el nombre o la URL desde el panel cuando quieras.
INSERT OR IGNORE INTO sites (id, slug, name, target_url, mode, active)
VALUES (
  'site_vitrasachase',
  'vitrasachase',
  'Vitrasa Chase',
  'https://lucasmaneirodelatm-dot.github.io/vitrasachase/',
  'protected',
  1
);
