import { isAdmin } from "../lib/auth.js";
import { logActivity, makeId, nowMs } from "../lib/db.js";
import { HttpError, assert, json, readJson } from "../lib/http.js";
import { getEffectiveAccess } from "../lib/permissions.js";

async function sha256Hex(value) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function parseIpList(value) {
  if (!value) return [];
  if (Array.isArray(value)) return value.map((item) => `${item}`.trim()).filter(Boolean);
  return `${value}`
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function randomShareToken() {
  return crypto.randomUUID().replace(/-/g, "");
}

function validateIp(ip, allowList, blockList) {
  if (blockList.includes(ip)) return false;
  if (!allowList.length) return true;
  return allowList.includes(ip);
}

export async function handleCreateShareLink(request, env, user) {
  const payload = await readJson(request);
  const key = payload.key || "";
  assert(key, 400, "key is required.");

  const object = await env.BUCKET.head(key);
  assert(object, 404, "File not found.");
  const access = await getEffectiveAccess(env, user, key, object.customMetadata || {});
  assert(access.canEdit || access.owner === user.username || isAdmin(user), 403, "Permission denied.");

  const permission = ["view", "download", "comment"].includes(payload.permission) ? payload.permission : "view";
  const expiresAt = payload.expiresAt ? Number(payload.expiresAt) : null;
  const maxDownloads = payload.maxDownloads ? Number(payload.maxDownloads) : null;
  const disableDownload = payload.disableDownload === true;
  const password = payload.password ? `${payload.password}` : "";
  const allowList = parseIpList(payload.ipAllowList);
  const blockList = parseIpList(payload.ipBlockList);

  if (expiresAt && (!Number.isFinite(expiresAt) || expiresAt <= Date.now())) {
    throw new HttpError(400, "expiresAt must be a future timestamp.");
  }
  if (maxDownloads && (!Number.isFinite(maxDownloads) || maxDownloads < 1 || maxDownloads > 100000)) {
    throw new HttpError(400, "maxDownloads must be between 1 and 100000.");
  }

  const token = randomShareToken();
  const passwordHash = password ? await sha256Hex(password) : null;
  await env.DB.prepare(
    `
      INSERT INTO share_links (
        id, token, file_key, created_by, permission, expires_at, max_downloads,
        download_count, disable_download, password_hash, ip_allow_list, ip_block_list, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?)
    `,
  )
    .bind(
      makeId("share"),
      token,
      key,
      user.username,
      permission,
      expiresAt,
      maxDownloads,
      disableDownload ? 1 : 0,
      passwordHash,
      JSON.stringify(allowList),
      JSON.stringify(blockList),
      nowMs(),
    )
    .run();

  await logActivity(env, user.username, "share.created", key, {
    permission,
    expiresAt,
    maxDownloads,
    disableDownload,
  });

  const shareUrl = `${new URL(request.url).origin}/vault/file/${encodeURIComponent(key)}?share=${token}`;
  return json({
    ok: true,
    key,
    token,
    url: shareUrl,
    expiresAt,
    maxDownloads,
    disableDownload,
  });
}

export async function handleListShareLinks(request, env, user) {
  const key = new URL(request.url).searchParams.get("key") || "";
  assert(key, 400, "key is required.");

  const object = await env.BUCKET.head(key);
  assert(object, 404, "File not found.");
  const access = await getEffectiveAccess(env, user, key, object.customMetadata || {});
  assert(access.canView, 403, "Permission denied.");

  const { results } = await env.DB.prepare(
    `
      SELECT id, token, file_key, created_by, permission, expires_at, max_downloads, download_count, disable_download, created_at
      FROM share_links
      WHERE file_key = ?
      ORDER BY created_at DESC
    `,
  )
    .bind(key)
    .all();

  return json({
    key,
    links: (results || []).map((row) => ({
      ...row,
      disable_download: Boolean(row.disable_download),
      url: `${new URL(request.url).origin}/vault/file/${encodeURIComponent(row.file_key)}?share=${row.token}`,
    })),
  });
}

export async function validateShareAccess(request, env, key, token) {
  if (!token) return { granted: false };

  const link = await env.DB.prepare(
    `
      SELECT id, token, file_key, permission, expires_at, max_downloads, download_count,
             disable_download, password_hash, ip_allow_list, ip_block_list
      FROM share_links
      WHERE token = ? AND file_key = ?
      LIMIT 1
    `,
  )
    .bind(token, key)
    .first();
  if (!link) return { granted: false };

  const now = nowMs();
  if (link.expires_at && now > Number(link.expires_at)) return { granted: false };
  if (link.max_downloads && Number(link.download_count) >= Number(link.max_downloads)) return { granted: false };

  const ip = request.headers.get("CF-Connecting-IP") || "";
  let allowList = [];
  let blockList = [];
  try {
    allowList = parseIpList(JSON.parse(link.ip_allow_list || "[]"));
    blockList = parseIpList(JSON.parse(link.ip_block_list || "[]"));
  } catch {
    allowList = [];
    blockList = [];
  }
  if (!validateIp(ip, allowList, blockList)) return { granted: false };

  if (link.password_hash) {
    const url = new URL(request.url);
    const provided = request.headers.get("X-Share-Password") || url.searchParams.get("password") || "";
    const providedHash = await sha256Hex(provided);
    if (providedHash !== link.password_hash) return { granted: false, passwordRequired: true };
  }

  return {
    granted: true,
    linkId: link.id,
    token: link.token,
    disableDownload: Boolean(link.disable_download),
    permission: link.permission,
  };
}

export async function consumeShareDownload(env, linkId) {
  if (!linkId) return;
  await env.DB.prepare("UPDATE share_links SET download_count = download_count + 1 WHERE id = ?")
    .bind(linkId)
    .run();
}

export async function handleCommentsGet(request, env, user) {
  const key = new URL(request.url).searchParams.get("key") || "";
  assert(key, 400, "key is required.");

  const object = await env.BUCKET.head(key);
  assert(object, 404, "File not found.");
  const access = await getEffectiveAccess(env, user, key, object.customMetadata || {});
  assert(access.canView, 403, "Permission denied.");

  const { results } = await env.DB.prepare(
    `
      SELECT id, file_key, username, body, anchor, created_at, updated_at
      FROM file_comments
      WHERE file_key = ?
      ORDER BY created_at ASC
    `,
  )
    .bind(key)
    .all();

  return json({ key, comments: results || [] });
}

export async function handleCommentsPost(request, env, user) {
  const payload = await readJson(request);
  const key = payload.key || "";
  const body = `${payload.body || ""}`.trim();
  const anchor = payload.anchor ? `${payload.anchor}`.slice(0, 500) : null;
  assert(key, 400, "key is required.");
  assert(body.length > 0, 400, "Comment body is required.");
  assert(body.length <= 4000, 400, "Comment body is too long.");

  const object = await env.BUCKET.head(key);
  assert(object, 404, "File not found.");
  const access = await getEffectiveAccess(env, user, key, object.customMetadata || {});
  assert(access.canComment || access.canEdit || access.owner === user.username, 403, "Comment permission denied.");

  const commentId = makeId("comment");
  await env.DB.prepare(
    `
      INSERT INTO file_comments (id, file_key, username, body, anchor, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `,
  )
    .bind(commentId, key, user.username, body, anchor, nowMs(), nowMs())
    .run();

  await logActivity(env, user.username, "comment.created", key, { commentId, anchor });
  return json({
    ok: true,
    comment: {
      id: commentId,
      file_key: key,
      username: user.username,
      body,
      anchor,
      created_at: nowMs(),
      updated_at: nowMs(),
    },
  });
}

export async function handleActivityLog(request, env, user) {
  const url = new URL(request.url);
  const limit = Math.min(300, Math.max(1, Number(url.searchParams.get("limit") || 100)));
  const key = url.searchParams.get("key");

  if (!isAdmin(user) && !key) {
    throw new HttpError(403, "Admin role required for global audit log.");
  }

  const bindings = [];
  let sql = `
    SELECT id, actor, action, file_key, target_user, metadata, created_at
    FROM activity_log
  `;
  if (key) {
    sql += " WHERE file_key = ? ";
    bindings.push(key);
  }
  sql += " ORDER BY created_at DESC LIMIT ?";
  bindings.push(limit);

  const { results } = await env.DB.prepare(sql).bind(...bindings).all();
  return json({
    events: (results || []).map((row) => ({
      ...row,
      metadata: (() => {
        try {
          return JSON.parse(row.metadata || "{}");
        } catch {
          return {};
        }
      })(),
    })),
  });
}

export async function handlePermissionOverride(request, env, user) {
  assert(isAdmin(user), 403, "Admin role required.");
  const payload = await readJson(request);
  const scopeType = payload.scopeType === "folder" ? "folder" : "file";
  const scopeKey = scopeType === "folder" ? `${payload.scopeKey || ""}`.trim().replace(/^\/+|\/+$/g, "") : payload.scopeKey || "";
  const username = `${payload.username || ""}`.trim();
  const role = `${payload.role || ""}`.trim();
  const canDownload = payload.canDownload !== false;
  const expiresAt = payload.expiresAt ? Number(payload.expiresAt) : null;

  assert(scopeKey, 400, "scopeKey is required.");
  assert(username, 400, "username is required.");
  assert(
    ["admin", "editor", "commenter", "viewer", "viewer-download-disabled"].includes(role),
    400,
    "Invalid permission role.",
  );

  await env.DB.prepare(
    `
      INSERT INTO file_permissions (id, scope_type, scope_key, username, role, can_download, expires_at, created_by, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(scope_type, scope_key, username)
      DO UPDATE SET role = excluded.role, can_download = excluded.can_download, expires_at = excluded.expires_at
    `,
  )
    .bind(makeId("perm"), scopeType, scopeKey, username, role, canDownload ? 1 : 0, expiresAt, user.username, nowMs())
    .run();

  await logActivity(env, user.username, "permission.override_set", scopeKey, {
    scopeType,
    username,
    role,
    canDownload,
    expiresAt,
  });

  return json({ ok: true });
}
