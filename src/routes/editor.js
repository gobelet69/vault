import { isAdmin } from "../lib/auth.js";
import { adjustUsedBytes, logActivity, makeId, nowMs, upsertRecentItem } from "../lib/db.js";
import { detectLanguage, getMimeType, isEditableFile } from "../lib/files.js";
import { HttpError, assert, json, readJson } from "../lib/http.js";
import { getEffectiveAccess } from "../lib/permissions.js";
import { upsertSearchIndex } from "./files.js";

function encodeVersionKey(key, versionId) {
  const encoded = encodeURIComponent(key);
  return `.versions/${encoded}/${versionId}.txt`;
}

async function readFileObject(env, key) {
  const object = await env.BUCKET.get(key);
  assert(object, 404, "File not found.");
  return object;
}

async function requireFileAccess(env, user, key, metadata, mode = "view") {
  const access = await getEffectiveAccess(env, user, key, metadata || {});
  if (mode === "edit") {
    assert(access.canEdit || access.owner === user.username || isAdmin(user), 403, "Edit permission denied.");
  } else {
    assert(access.canView, 403, "View permission denied.");
  }
  return access;
}

function buildBreadcrumbs(key) {
  const parts = key.split("/");
  const breadcrumbs = [];
  for (let i = 0; i < parts.length; i += 1) {
    const value = parts.slice(0, i + 1).join("/");
    breadcrumbs.push({
      label: parts[i],
      value,
      isFile: i === parts.length - 1,
    });
  }
  return breadcrumbs;
}

export async function handleFileContent(request, env, user) {
  const url = new URL(request.url);
  const key = url.searchParams.get("key") || "";
  assert(key, 400, "key is required.");

  const metadataOnly = url.searchParams.get("metadata") === "1";
  const object = await readFileObject(env, key);
  const access = await requireFileAccess(env, user, key, object.customMetadata, "view");
  const editableFile = isEditableFile(key);
  const language = detectLanguage(key);

  const activeEditors = await env.DB.prepare(
    `
      SELECT username, started_at, last_heartbeat_at
      FROM file_edit_sessions
      WHERE file_key = ? AND last_heartbeat_at > ?
      ORDER BY username
    `,
  )
    .bind(key, nowMs() - 90_000)
    .all();

  if (metadataOnly) {
    return json({
      key,
      etag: object.httpEtag || object.etag || null,
      size: object.size,
      mimeType: getMimeType(key),
      language,
      editable: editableFile,
      canEdit: access.canEdit || access.owner === user.username || isAdmin(user),
      activeEditors: activeEditors.results || [],
    });
  }

  assert(editableFile, 415, "This file type is not editable in the embedded editor.");
  const content = await object.text();

  await Promise.all([
    upsertRecentItem(env, user.username, "file", key),
    logActivity(env, user.username, "file.opened_in_editor", key, {
      size: object.size,
      language,
    }),
  ]);

  return json({
    key,
    content,
    etag: object.httpEtag || object.etag || null,
    size: object.size,
    mimeType: getMimeType(key),
    language,
    editable: editableFile,
    canEdit: access.canEdit || access.owner === user.username || isAdmin(user),
    breadcrumbs: buildBreadcrumbs(key),
    activeEditors: activeEditors.results || [],
  });
}

export async function handleFileSave(request, env, user) {
  const payload = await readJson(request);
  const key = payload.key || "";
  const content = typeof payload.content === "string" ? payload.content : null;
  const baseEtag = payload.baseEtag || null;
  const message = (payload.message || "").toString().trim().slice(0, 240);

  assert(key, 400, "key is required.");
  assert(content !== null, 400, "content is required.");
  assert(isEditableFile(key), 415, "This file type cannot be edited.");

  const object = await readFileObject(env, key);
  const metadata = object.customMetadata || {};
  const access = await requireFileAccess(env, user, key, metadata, "edit");

  const currentEtag = object.httpEtag || object.etag || null;
  if (baseEtag && currentEtag && baseEtag !== currentEtag) {
    return json(
      {
        error: "Conflict detected: file changed since it was opened.",
        code: "ETAG_CONFLICT",
        key,
        etag: currentEtag,
        latestContent: await object.text(),
      },
      409,
    );
  }

  const previousContent = await object.text();
  if (previousContent === content) {
    return json({
      ok: true,
      key,
      unchanged: true,
      etag: currentEtag,
      savedAt: nowMs(),
    });
  }

  const owner = metadata.uploader || access.owner || user.username;
  const versionId = makeId("ver");
  const versionKey = encodeVersionKey(key, versionId);
  const previousSize = object.size || previousContent.length;
  const newSize = new TextEncoder().encode(content).byteLength;

  const maxVersionResult = await env.DB.prepare(
    "SELECT COALESCE(MAX(version_number), 0) AS max_version FROM file_versions WHERE file_key = ?",
  )
    .bind(key)
    .first();
  const nextVersionNumber = Number(maxVersionResult?.max_version || 0) + 1;

  await env.BUCKET.put(versionKey, previousContent, {
    httpMetadata: { contentType: "text/plain; charset=utf-8" },
    customMetadata: {
      original_key: key,
      previous_etag: currentEtag || "",
      saved_by: user.username,
      saved_at: `${nowMs()}`,
      version_number: `${nextVersionNumber}`,
    },
  });

  await env.DB.prepare(
    `
      INSERT INTO file_versions (
        id, file_key, version_number, saved_by, saved_at, previous_etag,
        new_etag, byte_size, summary, r2_version_key
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `,
  )
    .bind(
      versionId,
      key,
      nextVersionNumber,
      user.username,
      nowMs(),
      currentEtag,
      null,
      previousSize,
      message || "Autosave snapshot",
      versionKey,
    )
    .run();

  await env.BUCKET.put(key, content, {
    customMetadata: {
      ...metadata,
      updated_at: `${nowMs()}`,
      last_editor: user.username,
    },
    httpMetadata: {
      contentType: getMimeType(key),
    },
  });

  const fresh = await env.BUCKET.head(key);
  await Promise.all([
    adjustUsedBytes(env, owner, newSize - previousSize),
    upsertSearchIndex(env, key, content),
    logActivity(env, user.username, "file.saved", key, {
      bytesBefore: previousSize,
      bytesAfter: newSize,
      versionNumber: nextVersionNumber,
      summary: message || null,
    }),
    upsertRecentItem(env, user.username, "file", key),
  ]);

  await env.DB.prepare("UPDATE file_versions SET new_etag = ? WHERE id = ?")
    .bind(fresh?.httpEtag || fresh?.etag || null, versionId)
    .run();

  return json({
    ok: true,
    key,
    etag: fresh?.httpEtag || fresh?.etag || null,
    savedAt: nowMs(),
    version: {
      id: versionId,
      number: nextVersionNumber,
      savedBy: user.username,
      summary: message || null,
    },
  });
}

export async function handleFileHistory(request, env, user) {
  const key = new URL(request.url).searchParams.get("key") || "";
  const limit = Math.min(200, Math.max(1, Number(new URL(request.url).searchParams.get("limit") || 50)));
  assert(key, 400, "key is required.");

  const object = await env.BUCKET.head(key);
  assert(object, 404, "File not found.");
  await requireFileAccess(env, user, key, object.customMetadata || {}, "view");

  const { results } = await env.DB.prepare(
    `
      SELECT id, file_key, version_number, saved_by, saved_at, previous_etag, new_etag, byte_size, summary
      FROM file_versions
      WHERE file_key = ?
      ORDER BY version_number DESC
      LIMIT ?
    `,
  )
    .bind(key, limit)
    .all();

  return json({
    key,
    versions: results || [],
  });
}

export async function handleRestoreVersion(request, env, user) {
  const payload = await readJson(request);
  const versionId = payload.versionId || "";
  assert(versionId, 400, "versionId is required.");

  const version = await env.DB.prepare(
    `
      SELECT id, file_key, r2_version_key
      FROM file_versions
      WHERE id = ?
    `,
  )
    .bind(versionId)
    .first();
  assert(version, 404, "Version not found.");

  const versionObject = await env.BUCKET.get(version.r2_version_key);
  assert(versionObject, 404, "Version blob not found.");

  const content = await versionObject.text();
  return handleFileSave(
    new Request("https://vault.local/vault/api/file-save", {
      method: "POST",
      body: JSON.stringify({
        key: version.file_key,
        content,
        message: `Restored ${versionId}`,
      }),
    }),
    env,
    user,
  );
}

export async function handleEditorPresenceGet(request, env, user) {
  const key = new URL(request.url).searchParams.get("key") || "";
  assert(key, 400, "key is required.");

  const object = await env.BUCKET.head(key);
  assert(object, 404, "File not found.");
  await requireFileAccess(env, user, key, object.customMetadata || {}, "view");

  const { results } = await env.DB.prepare(
    `
      SELECT username, started_at, last_heartbeat_at
      FROM file_edit_sessions
      WHERE file_key = ? AND last_heartbeat_at > ?
      ORDER BY username
    `,
  )
    .bind(key, nowMs() - 90_000)
    .all();

  return json({
    key,
    editors: (results || []).map((row) => ({
      ...row,
      isCurrentUser: row.username === user.username,
    })),
  });
}

export async function handleEditorPresencePost(request, env, user) {
  const payload = await readJson(request);
  const key = payload.key || "";
  const active = payload.active !== false;
  assert(key, 400, "key is required.");

  const object = await env.BUCKET.head(key);
  assert(object, 404, "File not found.");
  await requireFileAccess(env, user, key, object.customMetadata || {}, active ? "edit" : "view");

  if (!active) {
    await env.DB.prepare(
      `
        DELETE FROM file_edit_sessions
        WHERE file_key = ? AND username = ?
      `,
    )
      .bind(key, user.username)
      .run();
    return json({ ok: true, active: false });
  }

  await env.DB.prepare(
    `
      INSERT INTO file_edit_sessions (file_key, username, started_at, last_heartbeat_at)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(file_key, username)
      DO UPDATE SET last_heartbeat_at = excluded.last_heartbeat_at
    `,
  )
    .bind(key, user.username, nowMs(), nowMs())
    .run();

  return json({ ok: true, active: true, heartbeatAt: nowMs() });
}

export async function handleDiffPreview(request, env, user) {
  const payload = await readJson(request);
  const key = payload.key || "";
  const content = typeof payload.content === "string" ? payload.content : "";
  assert(key, 400, "key is required.");

  const object = await env.BUCKET.get(key);
  assert(object, 404, "File not found.");
  await requireFileAccess(env, user, key, object.customMetadata || {}, "view");

  const original = await object.text();
  const originalLines = original.split("\n");
  const modifiedLines = content.split("\n");
  const max = Math.max(originalLines.length, modifiedLines.length);
  let changed = 0;
  for (let i = 0; i < max; i += 1) {
    if ((originalLines[i] || "") !== (modifiedLines[i] || "")) changed += 1;
  }

  return json({
    key,
    changedLines: changed,
    originalLineCount: originalLines.length,
    modifiedLineCount: modifiedLines.length,
    hasChanges: changed > 0,
  });
}

