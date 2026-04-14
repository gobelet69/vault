# Vault Enterprise

Vault is a Cloudflare Workers + R2 + D1 storage platform upgraded to support:

- Embedded VS Code-style web editing (Monaco-based)
- Multi-tab editing, diff preview, autosave, and live presence
- File version history and restore
- Share links with expiry/download controls
- Rich file operations (batch delete/move, tags, favorites, trash/restore, duplicate, rename)
- Folder tree navigation, recent items, audit activity
- React frontend with component architecture and centralized state
- Modular Worker route handlers with validation, rate limiting, and structured errors

## Architecture

### Backend

- Entry: `worker.js` -> `src/worker.js`
- Route modules:
  - `src/routes/files.js` (listing, upload, folders, file management, preview)
  - `src/routes/editor.js` (`/vault/api/file-content`, `/vault/api/file-save`, versions, presence)
  - `src/routes/sharing.js` (share links, comments, activity log, permission overrides)
  - `src/routes/users.js` (user and invite management)
  - `src/routes/ui.js` (app shell)
- Shared utilities:
  - `src/lib/http.js` (errors, JSON helpers, security headers)
  - `src/lib/auth.js` (session auth + role normalization)
  - `src/lib/permissions.js` (effective access calculation)
  - `src/lib/files.js` (file type, sanitization, language detection)
  - `src/lib/db.js` (activity logging, quotas, rate limiting, cleanup)

### Frontend

- React app entry: `frontend/main.jsx`
- Main app: `frontend/App.jsx`
- State management: Zustand (`frontend/store.js`)
- API client: `frontend/api/client.js`
- Key components:
  - `HeaderBar`
  - `FolderTree`
  - `FileTable`
  - `EditorWorkspace`
  - `PreviewPanel`
  - `ShareModal`
- Styling: `frontend/styles.css`

## VS Code Web Editor Features

- Edit action from file table row
- Supports text/code formats (`.js`, `.ts`, `.py`, `.json`, `.md`, `.txt`, `.html`, `.css`, `.yaml`, etc.)
- Auto-save with debounce (`/vault/api/file-save`)
- ETag conflict detection + conflict response payload
- Diff preview mode (inline Monaco diff editor)
- Multi-tab editing
- Language detection + syntax highlighting
- Theme sync (dark/light)
- Breadcrumb path display
- Quick-open in editor (`Ctrl/Cmd + P`)
- Permission-aware save (read-only tabs for non-edit roles)
- Version history viewer + restore
- Active editor presence indicators (`/vault/api/editor-presence`)
- Offline save queue retry

## API Highlights

### Editor

- `GET /vault/api/file-content?key=<r2-key>`
- `POST /vault/api/file-save`
- `GET /vault/api/file-history?key=<r2-key>`
- `POST /vault/api/file-restore`
- `GET|POST /vault/api/editor-presence`
- `POST /vault/api/file-diff`

### File management

- `GET /vault/api/bootstrap`
- `GET /vault/api/files`
- `GET /vault/api/search`
- `POST /vault/api/upload`
- `POST /vault/api/create-folder`
- `POST /vault/api/create-text-file`
- `POST /vault/api/delete-folder`
- `GET /vault/api/delete/<key>` (soft delete to trash by default)
- `POST /vault/api/batch`
- `POST /vault/api/move`
- `POST /vault/api/rename`
- `POST /vault/api/duplicate`
- `POST /vault/api/favorite`
- `POST /vault/api/tags`
- `POST /vault/api/restore-trash`
- `GET /vault/api/preview`

### Collaboration / sharing / security

- `POST|GET /vault/api/share-link`
- `GET|POST /vault/api/comments`
- `GET /vault/api/activity`
- `POST /vault/api/permissions`
- `POST /vault/api/invite`
- `POST /vault/api/users`

## Database Migrations

Migration SQL is in:

- `migrations/0001_enterprise_upgrade.sql`

Apply migration to the `DB` binding:

```bash
npx wrangler d1 migrations apply pdfs --remote
```

## Build & Run

Install dependencies:

```bash
npm install
```

Build frontend bundle:

```bash
npm run build
```

Deploy:

```bash
npx wrangler deploy
```

## Static Assets

Built frontend artifacts are served from:

- `/vault/static/vault-app.js`
- `/vault/static/vault-app.css`

Configured through Wrangler `assets` binding (`ASSETS`) in `wrangler.jsonc`.
