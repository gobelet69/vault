-- Vault enterprise upgrade schema:
-- - version history
-- - editor presence
-- - sharing controls
-- - activity/audit logs
-- - favorites/tags/trash/recent
-- - quota + bandwidth
-- - rate limiting support

CREATE TABLE IF NOT EXISTS file_versions (
  id TEXT PRIMARY KEY,
  file_key TEXT NOT NULL,
  version_number INTEGER NOT NULL,
  saved_by TEXT NOT NULL,
  saved_at INTEGER NOT NULL,
  previous_etag TEXT,
  new_etag TEXT,
  byte_size INTEGER NOT NULL,
  summary TEXT,
  r2_version_key TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_file_versions_file_key_saved_at
  ON file_versions (file_key, saved_at DESC);

CREATE TABLE IF NOT EXISTS file_edit_sessions (
  file_key TEXT NOT NULL,
  username TEXT NOT NULL,
  started_at INTEGER NOT NULL,
  last_heartbeat_at INTEGER NOT NULL,
  PRIMARY KEY (file_key, username)
);
CREATE INDEX IF NOT EXISTS idx_file_edit_sessions_heartbeat
  ON file_edit_sessions (last_heartbeat_at);

CREATE TABLE IF NOT EXISTS file_permissions (
  id TEXT PRIMARY KEY,
  scope_type TEXT NOT NULL CHECK (scope_type IN ('file', 'folder')),
  scope_key TEXT NOT NULL,
  username TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin', 'editor', 'commenter', 'viewer', 'viewer-download-disabled')),
  can_download INTEGER NOT NULL DEFAULT 1 CHECK (can_download IN (0, 1)),
  expires_at INTEGER,
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE (scope_type, scope_key, username)
);
CREATE INDEX IF NOT EXISTS idx_file_permissions_lookup
  ON file_permissions (username, scope_type, scope_key);

CREATE TABLE IF NOT EXISTS file_tags (
  file_key TEXT NOT NULL,
  tag TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (file_key, tag)
);
CREATE INDEX IF NOT EXISTS idx_file_tags_tag
  ON file_tags (tag);

CREATE TABLE IF NOT EXISTS favorites (
  username TEXT NOT NULL,
  item_type TEXT NOT NULL CHECK (item_type IN ('file', 'folder')),
  item_key TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (username, item_type, item_key)
);
CREATE INDEX IF NOT EXISTS idx_favorites_user_created
  ON favorites (username, created_at DESC);

CREATE TABLE IF NOT EXISTS trash_items (
  item_type TEXT NOT NULL CHECK (item_type IN ('file', 'folder')),
  item_key TEXT NOT NULL,
  trashed_by TEXT NOT NULL,
  trashed_at INTEGER NOT NULL,
  original_parent TEXT,
  PRIMARY KEY (item_type, item_key)
);
CREATE INDEX IF NOT EXISTS idx_trash_items_trashed_at
  ON trash_items (trashed_at DESC);

CREATE TABLE IF NOT EXISTS share_links (
  id TEXT PRIMARY KEY,
  token TEXT NOT NULL UNIQUE,
  file_key TEXT NOT NULL,
  created_by TEXT NOT NULL,
  permission TEXT NOT NULL CHECK (permission IN ('view', 'download', 'comment')),
  expires_at INTEGER,
  max_downloads INTEGER,
  download_count INTEGER NOT NULL DEFAULT 0,
  disable_download INTEGER NOT NULL DEFAULT 0 CHECK (disable_download IN (0, 1)),
  password_hash TEXT,
  ip_allow_list TEXT NOT NULL DEFAULT '[]',
  ip_block_list TEXT NOT NULL DEFAULT '[]',
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_share_links_file
  ON share_links (file_key, created_at DESC);

CREATE TABLE IF NOT EXISTS file_comments (
  id TEXT PRIMARY KEY,
  file_key TEXT NOT NULL,
  username TEXT NOT NULL,
  body TEXT NOT NULL,
  anchor TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_file_comments_file
  ON file_comments (file_key, created_at ASC);

CREATE TABLE IF NOT EXISTS activity_log (
  id TEXT PRIMARY KEY,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  file_key TEXT,
  target_user TEXT,
  metadata TEXT NOT NULL DEFAULT '{}',
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_activity_log_created
  ON activity_log (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_activity_log_file
  ON activity_log (file_key, created_at DESC);

CREATE TABLE IF NOT EXISTS recent_items (
  username TEXT NOT NULL,
  item_type TEXT NOT NULL CHECK (item_type IN ('file', 'folder')),
  item_key TEXT NOT NULL,
  last_accessed_at INTEGER NOT NULL,
  PRIMARY KEY (username, item_type, item_key)
);
CREATE INDEX IF NOT EXISTS idx_recent_items_user
  ON recent_items (username, last_accessed_at DESC);

CREATE TABLE IF NOT EXISTS user_quotas (
  username TEXT PRIMARY KEY,
  max_bytes INTEGER NOT NULL DEFAULT 10737418240,
  used_bytes INTEGER NOT NULL DEFAULT 0,
  bandwidth_bytes INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS folder_metadata (
  path TEXT PRIMARY KEY,
  parent_path TEXT NOT NULL,
  name TEXT NOT NULL,
  color TEXT NOT NULL DEFAULT '#6366f1',
  icon TEXT NOT NULL DEFAULT '📁',
  template_key TEXT,
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_folder_metadata_parent
  ON folder_metadata (parent_path);

CREATE TABLE IF NOT EXISTS rate_limits (
  limit_key TEXT NOT NULL,
  window_start INTEGER NOT NULL,
  count INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (limit_key, window_start)
);
CREATE INDEX IF NOT EXISTS idx_rate_limits_window
  ON rate_limits (window_start);

CREATE TABLE IF NOT EXISTS file_search_index (
  file_key TEXT PRIMARY KEY,
  searchable_text TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_file_search_updated
  ON file_search_index (updated_at DESC);

CREATE TABLE IF NOT EXISTS pending_invites (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  role TEXT NOT NULL,
  invited_by TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'accepted', 'revoked'))
);
CREATE INDEX IF NOT EXISTS idx_pending_invites_email
  ON pending_invites (email, status);

