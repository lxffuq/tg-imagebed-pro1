CREATE TABLE IF NOT EXISTS images (
  id TEXT PRIMARY KEY,
  original_name TEXT NOT NULL,
  mime_type TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  telegram_chat_id TEXT NOT NULL,
  telegram_message_id INTEGER NOT NULL,
  telegram_file_id TEXT NOT NULL,
  telegram_file_unique_id TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  status TEXT NOT NULL DEFAULT 'active',
  delete_error TEXT
);
CREATE INDEX IF NOT EXISTS idx_images_created ON images(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_images_name ON images(original_name);
CREATE INDEX IF NOT EXISTS idx_images_status ON images(status);
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
