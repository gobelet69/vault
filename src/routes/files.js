import { isAdmin } from "../lib/auth.js";
import {
  detectLanguage,
  extensionOf,
  getMimeType,
  isEditableFile,
  isFolderMetaKey,
  isInternalVersionKey,
  joinFolderAndFile,
  sanitizeFilename,
  sanitizeFolderPath,
} from "../lib/files.js";
import { HttpError, assert, json, readJson, text } from "../lib/http.js";
import { canAccessFolder, canUploadFileByRole, getEffectiveAccess, normalizeVisibility } from "../lib/permissions.js";
import {
  addBandwidth,
  adjustUsedBytes,
  getQuota,
  logActivity,
  nowMs,
  recomputeUsedBytesFromStorage,
  upsertRecentItem,
} from "../lib/db.js";

function fileIconFromKey(fileKey) {
  if (/\.(png|jpe?g|gif|webp|svg)$/i.test(fileKey)) return "image";
  if (/\.(mp4|mov|avi)$/i.test(fileKey)) return "video";
  if (/\.(mp3|wav|ogg)$/i.test(fileKey)) return "audio";
  if (/\.pdf$/i.test(fileKey)) return "pdf";
  if (isEditableFile(fileKey)) return "code";
  return "file";
}

function folderMetaKey(path) {
  return `.folder:${path}`;
}

async function listAllWithDelimiter(env, options) {
  let cursor;
  const objects = [];
  const prefixes = new Set();
  do {
    const listed = await env.BUCKET.list({ ...options, cursor });
    for (const object of listed.objects || []) {
      objects.push(object);
    }
    for (const prefixed of listed.delimitedPrefixes || []) {
      prefixes.add(prefixed);
    }
    cursor = listed.truncated ? listed.cursor : undefined;
  } while (cursor);
  return {
    objects,
    delimitedPrefixes: [...prefixes],
  };
}

function parseSort({ sortBy = "name", sortDir = "asc" } = {}) {
  const normalizedSortBy = ["name", "date", "size", "type", "owner", "access"].includes(sortBy)
    ? sortBy
    : "name";
  const normalizedSortDir = sortDir === "desc" ? "desc" : "asc";
  return { sortBy: normalizedSortBy, sortDir: normalizedSortDir };
}

function sortWithDirection(a, b, direction) {
  if (a === b) return 0;
  const base = a > b ? 1 : -1;
  return direction === "desc" ? -base : base;
}

function sortFiles(files, sorting) {
  const { sortBy, sortDir } = parseSort(sorting);
  return [...files].sort((a, b) => {
    if (sortBy === "date") return sortWithDirection(a.updatedAt || 0, b.updatedAt || 0, sortDir);
    if (sortBy === "size") return sortWithDirection(a.size || 0, b.size || 0, sortDir);
    if (sortBy === "type") return sortWithDirection(extensionOf(a.key), extensionOf(b.key), sortDir);
    if (sortBy === "owner") return sortWithDirection(a.owner || "", b.owner || "", sortDir);
    if (sortBy === "access") return sortWithDirection(a.visibility || "", b.visibility || "", sortDir);
    return sortWithDirection((a.displayName || "").toLowerCase(), (b.displayName || "").toLowerCase(), sortDir);
  });
}

function sortFolders(folders, sorting) {
  const { sortBy, sortDir } = parseSort(sorting);
  return [...folders].sort((a, b) => {
    if (sortBy === "date") return sortWithDirection(a.updatedAt || 0, b.updatedAt || 0, sortDir);
    return sortWithDirection((a.name || "").toLowerCase(), (b.name || "").toLowerCase(), sortDir);
  });
}

async function listAllFolderMetadata(env) {
  let cursor;
  const folders = [];
  do {
    const listed = await env.BUCKET.list({
      prefix: ".folder:",
      cursor,
      include: ["customMetadata"],
    });
    for (const object of listed.objects || []) {
      if (!object.key.startsWith(".folder:")) continue;
      const path = object.key.replace(".folder:", "");
      const parts = path.split("/");
      folders.push({
        path,
        name: parts[parts.length - 1] || path,
        parentPath: parts.slice(0, -1).join("/"),
        visibility: normalizeVisibility(object.customMetadata?.visibility),
        allowedUsers: object.customMetadata?.allowed_users || "",
        owner: object.customMetadata?.uploader || "",
        color: object.customMetadata?.color || "#6366f1",
        icon: object.customMetadata?.icon || "📁",
        updatedAt: object.uploaded ? new Date(object.uploaded).getTime() : null,
      });
    }
    cursor = listed.truncated ? listed.cursor : undefined;
  } while (cursor);
  return folders;
}

async function queryMapByKeys(env, sql, keys, bindPrefix = []) {
  if (!keys.length) return new Map();
  const placeholders = keys.map(() => "?").join(",");
  const stmt = env.DB.prepare(sql.replace("$KEYS$", placeholders)).bind(...bindPrefix, ...keys);
  const { results } = await stmt.all();
  const map = new Map();
  for (const row of results || []) {
    map.set(row.item_key || row.file_key, row);
  }
  return map;
}

async function queryTagsByFileKeys(env, keys) {
  if (!keys.length) return new Map();
  const placeholders = keys.map(() => "?").join(",");
  const { results } = await env.DB.prepare(
    `SELECT file_key, tag FROM file_tags WHERE file_key IN (${placeholders})`,
  )
    .bind(...keys)
    .all();
  const map = new Map();
  for (const row of results || []) {
    if (!map.has(row.file_key)) map.set(row.file_key, []);
    map.get(row.file_key).push(row.tag);
  }
  return map;
}

async function listVisiblePathContents(env, user, currentPath, options = {}) {
  const cleanPath = sanitizeFolderPath(currentPath || "");
  const prefix = cleanPath ? `${cleanPath}/` : "";
  const listing = await listAllWithDelimiter(env, {
    prefix,
    delimiter: "/",
    include: ["customMetadata"],
  });

  const folderObjects = await Promise.all(
    (listing.delimitedPrefixes || []).map(async (prefixed) => {
      const path = prefixed.slice(0, -1);
      const metaHead = await env.BUCKET.head(folderMetaKey(path));
      const meta = metaHead?.customMetadata || {};
      return {
        path,
        name: path.replace(prefix, ""),
        owner: meta.uploader || "",
        visibility: normalizeVisibility(meta.visibility),
        allowedUsers: meta.allowed_users || "",
        color: meta.color || "#6366f1",
        icon: meta.icon || "📁",
        updatedAt: metaHead?.uploaded ? new Date(metaHead.uploaded).getTime() : null,
      };
    }),
  );

  // Also include empty folders that only exist as .folder: metadata objects
  const allFolderMeta = await listAllFolderMetadata(env);
  const existingPaths = new Set(folderObjects.map((f) => f.path));
  for (const meta of allFolderMeta) {
    if (existingPaths.has(meta.path)) continue;
    // Only include folders whose parent matches the current path
    const expectedParent = meta.path.includes("/")
      ? meta.path.split("/").slice(0, -1).join("/")
      : "";
    if (expectedParent !== cleanPath) continue;
    folderObjects.push({
      path: meta.path,
      name: meta.path.replace(prefix, ""),
      owner: meta.owner || "",
      visibility: normalizeVisibility(meta.visibility),
      allowedUsers: meta.allowedUsers || "",
      color: meta.color || "#6366f1",
      icon: meta.icon || "📁",
      updatedAt: meta.updatedAt || null,
    });
  }

  const visibleFolders = folderObjects.filter((folder) => canAccessFolder(user, {
    uploader: folder.owner,
    visibility: folder.visibility,
    allowed_users: folder.allowedUsers,
  }));

  const fileCandidates = [];
  for (const object of listing.objects || []) {
    if (isFolderMetaKey(object.key) || isInternalVersionKey(object.key)) continue;
    const access = await getEffectiveAccess(env, user, object.key, object.customMetadata || {});
    if (!access.canView) continue;
    fileCandidates.push({
      key: object.key,
      displayName: cleanPath ? object.key.replace(prefix, "") : object.key,
      size: object.size,
      owner: object.customMetadata?.uploader || "",
      visibility: access.visibility,
      allowedUsers: access.allowedUsers,
      updatedAt: object.uploaded ? new Date(object.uploaded).getTime() : null,
      etag: object.httpEtag || object.etag || null,
      mimeType: getMimeType(object.key),
      language: detectLanguage(object.key),
      editable: isEditableFile(object.key),
      access,
      previewType: fileIconFromKey(object.key),
    });
  }

  const fileKeys = fileCandidates.map((item) => item.key);
  const folderPaths = visibleFolders.map((folder) => folder.path);
  const [tagMap, favoriteMap, folderFavoriteMap, trashMap] = await Promise.all([
    queryTagsByFileKeys(env, fileKeys),
    queryMapByKeys(
      env,
      `
        SELECT item_key, created_at
        FROM favorites
        WHERE username = ? AND item_type = 'file' AND item_key IN ($KEYS$)
      `,
      fileKeys,
      [user.username],
    ),
    queryMapByKeys(
      env,
      `
        SELECT item_key, created_at
        FROM favorites
        WHERE username = ? AND item_type = 'folder' AND item_key IN ($KEYS$)
      `,
      folderPaths,
      [user.username],
    ),
    queryMapByKeys(
      env,
      `
        SELECT item_key, trashed_at
        FROM trash_items
        WHERE item_type = 'file' AND item_key IN ($KEYS$)
      `,
      fileKeys,
    ),
  ]);

  const showTrash = options.showTrash === true;
  const normalizedSearch = (options.search || "").trim().toLowerCase();
  const fullTextMatches = new Set();
  if (normalizedSearch) {
    const { results } = await env.DB.prepare(
      `
        SELECT file_key
        FROM file_search_index
        WHERE searchable_text LIKE ?
        LIMIT 500
      `,
    )
      .bind(`%${normalizedSearch}%`)
      .all();
    for (const row of results || []) {
      fullTextMatches.add(row.file_key);
    }
  }

  const files = fileCandidates
    .filter((item) => {
      const isTrashed = trashMap.has(item.key);
      if (showTrash && !isTrashed) return false;
      if (!showTrash && isTrashed) return false;
      if (!normalizedSearch) return true;
      const byName = item.displayName.toLowerCase().includes(normalizedSearch);
      const byTag = (tagMap.get(item.key) || []).some((tag) => tag.toLowerCase().includes(normalizedSearch));
      const byText = fullTextMatches.has(item.key);
      return byName || byTag || byText;
    })
    .map((item) => ({
      ...item,
      tags: tagMap.get(item.key) || [],
      starred: favoriteMap.has(item.key),
      trashed: trashMap.has(item.key),
    }));

  const folders = visibleFolders
    .filter((folder) => {
      if (!normalizedSearch) return true;
      return folder.name.toLowerCase().includes(normalizedSearch) || folder.path.toLowerCase().includes(normalizedSearch);
    })
    .map((folder) => ({
      ...folder,
      starred: folderFavoriteMap.has(folder.path),
    }));

  return {
    currentPath: cleanPath,
    folders: sortFolders(folders, options),
    files: sortFiles(files, options),
  };
}

function parsePathFromUrl(url) {
  return sanitizeFolderPath(url.searchParams.get("path") || "");
}

export async function handleBootstrap(request, env, user) {
  const url = new URL(request.url);
  const currentPath = parsePathFromUrl(url);
  const search = (url.searchParams.get("search") || "").trim();
  const sortBy = url.searchParams.get("sortBy") || "name";
  const sortDir = url.searchParams.get("sortDir") || "asc";
  const showTrash = url.searchParams.get("trash") === "1";

  const [contents, tree, quota, recentRaw, favoriteRaw] = await Promise.all([
    listVisiblePathContents(env, user, currentPath, { search, sortBy, sortDir, showTrash }),
    listAllFolderMetadata(env),
    (async () => {
      await recomputeUsedBytesFromStorage(env, user.username, { includeUnowned: isAdmin(user) });
      return getQuota(env, user.username);
    })(),
    env.DB.prepare(
      `
        SELECT item_type, item_key, last_accessed_at
        FROM recent_items
        WHERE username = ?
        ORDER BY last_accessed_at DESC
        LIMIT 40
      `,
    )
      .bind(user.username)
      .all(),
    env.DB.prepare(
      `
        SELECT item_type, item_key, created_at
        FROM favorites
        WHERE username = ?
        ORDER BY created_at DESC
        LIMIT 200
      `,
    )
      .bind(user.username)
      .all(),
  ]);

  const visibleTree = tree.filter((folder) => canAccessFolder(user, {
    uploader: folder.owner,
    visibility: folder.visibility,
    allowed_users: folder.allowedUsers,
  }));

  const editableCount = contents.files.filter((file) => file.editable).length;
  return json({
    user: {
      username: user.username,
      role: user.role,
      isAdmin: isAdmin(user),
    },
    currentPath: contents.currentPath,
    folders: contents.folders,
    files: contents.files,
    tree: visibleTree,
    recent: recentRaw.results || [],
    favorites: favoriteRaw.results || [],
    quota: quota || {
      max_bytes: 10 * 1024 * 1024 * 1024,
      used_bytes: 0,
      bandwidth_bytes: 0,
      updated_at: nowMs(),
    },
    features: {
      editor: true,
      quickOpen: true,
      versionHistory: true,
      comments: true,
      collaborationPresence: true,
      runnerService: Boolean(env.RUNNER_URL),
      offlineQueue: true,
      editableFileCount: editableCount,
    },
  });
}

export async function handleListFiles(request, env, user) {
  const url = new URL(request.url);
  const currentPath = parsePathFromUrl(url);
  const search = (url.searchParams.get("search") || "").trim();
  const sortBy = url.searchParams.get("sortBy") || "name";
  const sortDir = url.searchParams.get("sortDir") || "asc";
  const showTrash = url.searchParams.get("trash") === "1";
  const data = await listVisiblePathContents(env, user, currentPath, { search, sortBy, sortDir, showTrash });
  return json(data);
}

export async function handleUpload(request, env, user) {
  const originalName = request.headers.get("X-File-Name");
  assert(originalName, 400, "Missing X-File-Name header.");
  assert(canUploadFileByRole(user, originalName), 403, "Your role cannot upload this file type.");

  const folderPath = sanitizeFolderPath(request.headers.get("X-Folder") || "");
  const fileName = sanitizeFilename(originalName);

  let visibility = normalizeVisibility(request.headers.get("X-Visibility") || "only-me");
  let allowedUsers = request.headers.get("X-Allowed-Users") || "";
  if (folderPath) {
    const folderHead = await env.BUCKET.head(folderMetaKey(folderPath));
    if (folderHead?.customMetadata?.visibility) {
      visibility = normalizeVisibility(folderHead.customMetadata.visibility);
      allowedUsers = folderHead.customMetadata.allowed_users || "";
    }
  }

  let key = joinFolderAndFile(folderPath, fileName);
  let copy = 1;
  while (await env.BUCKET.head(key)) {
    const ext = extensionOf(fileName);
    const base = ext ? fileName.slice(0, -ext.length - 1) : fileName;
    const candidate = ext ? `${base} (${copy}).${ext}` : `${base} (${copy})`;
    key = joinFolderAndFile(folderPath, candidate);
    copy += 1;
  }

  const body = request.body;
  assert(body, 400, "Upload body is empty.");

  await env.BUCKET.put(key, body, {
    customMetadata: {
      uploader: user.username,
      role: user.role,
      visibility,
      allowed_users: allowedUsers,
      inherit_visibility: folderPath ? "1" : "0",
      updated_at: `${nowMs()}`,
    },
    httpMetadata: {
      contentType: getMimeType(key),
    },
  });

  const fresh = await env.BUCKET.head(key);
  await Promise.all([
    adjustUsedBytes(env, user.username, fresh?.size || 0),
    (async () => {
      if (!isTextBasedFile(key)) return;
      const uploaded = await env.BUCKET.get(key);
      if (!uploaded) return;
      await upsertSearchIndex(env, key, await uploaded.text());
    })(),
    logActivity(env, user.username, "file.uploaded", key, {
      size: fresh?.size || 0,
      folderPath,
      visibility,
    }),
    upsertRecentItem(env, user.username, "file", key),
  ]);

  return json({
    ok: true,
    key,
    size: fresh?.size || 0,
  });
}

export async function handleCreateFolder(request, env, user) {
  const payload = await readJson(request);
  const name = sanitizeFilename(payload.name || "");
  const parentPath = sanitizeFolderPath(payload.parentPath || "");
  const folderPath = parentPath ? `${parentPath}/${name}` : name;

  await env.BUCKET.put(folderMetaKey(folderPath), "", {
    customMetadata: {
      uploader: user.username,
      visibility: "only-me",
      allowed_users: "",
      color: payload.color || "#6366f1",
      icon: payload.icon || "📁",
    },
  });

  await Promise.all([
    env.DB.prepare(
      `
        INSERT INTO folder_metadata (path, parent_path, name, color, icon, template_key, created_by, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(path) DO UPDATE SET color = excluded.color, icon = excluded.icon, updated_at = excluded.updated_at
      `,
    )
      .bind(
        folderPath,
        parentPath,
        name,
        payload.color || "#6366f1",
        payload.icon || "📁",
        payload.templateKey || null,
        user.username,
        nowMs(),
        nowMs(),
      )
      .run(),
    logActivity(env, user.username, "folder.created", folderPath, {
      parentPath,
      color: payload.color || "#6366f1",
      icon: payload.icon || "📁",
    }),
    upsertRecentItem(env, user.username, "folder", folderPath),
  ]);

  return json({ ok: true, path: folderPath });
}

export async function handleCreateTextFile(request, env, user) {
  const payload = await readJson(request);
  const parentPath = sanitizeFolderPath(payload.parentPath || "");
  let name = sanitizeFilename(payload.name || "");
  if (!/\.[a-z0-9]+$/i.test(name)) {
    name = `${name}.txt`;
  }

  assert(canUploadFileByRole(user, name), 403, "Your role cannot create this file type.");
  assert(isTextBasedFile(name), 400, "Only text-based files can be created with this action.");

  let visibility = normalizeVisibility(payload.visibility || "only-me");
  let allowedUsers = payload.allowedUsers || "";

  if (parentPath) {
    const folderHead = await env.BUCKET.head(folderMetaKey(parentPath));
    assert(folderHead, 404, "Parent folder not found.");
    const folderMeta = folderHead.customMetadata || {};
    assert(
      canAccessFolder(user, {
        uploader: folderMeta.uploader || "",
        visibility: folderMeta.visibility || "only-me",
        allowed_users: folderMeta.allowed_users || "",
      }),
      403,
      "You do not have permission to create files in this folder.",
    );
    if (folderMeta.visibility) {
      visibility = normalizeVisibility(folderMeta.visibility);
      allowedUsers = folderMeta.allowed_users || "";
    }
  }

  let key = joinFolderAndFile(parentPath, name);
  let copy = 1;
  while (await env.BUCKET.head(key)) {
    const ext = extensionOf(name);
    const base = ext ? name.slice(0, -ext.length - 1) : name;
    const candidate = ext ? `${base} (${copy}).${ext}` : `${base} (${copy})`;
    key = joinFolderAndFile(parentPath, candidate);
    copy += 1;
  }

  const content = typeof payload.content === "string" ? payload.content : "";
  await env.BUCKET.put(key, content, {
    customMetadata: {
      uploader: user.username,
      role: user.role,
      visibility,
      allowed_users: allowedUsers,
      inherit_visibility: parentPath ? "1" : "0",
      updated_at: `${nowMs()}`,
      last_editor: user.username,
    },
    httpMetadata: {
      contentType: getMimeType(key),
    },
  });

  const fresh = await env.BUCKET.head(key);
  await Promise.all([
    adjustUsedBytes(env, user.username, fresh?.size || 0),
    upsertSearchIndex(env, key, content),
    logActivity(env, user.username, "file.created_text", key, {
      parentPath,
      visibility,
      size: fresh?.size || 0,
    }),
    upsertRecentItem(env, user.username, "file", key),
  ]);

  return json({
    ok: true,
    key,
    size: fresh?.size || 0,
  });
}

export async function handleDeleteFolder(request, env, user) {
  const { path } = await readJson(request);
  const folderPath = sanitizeFolderPath(path || "");
  assert(folderPath, 400, "Folder path is required.");

  const folderKey = folderMetaKey(folderPath);
  const folderHead = await env.BUCKET.head(folderKey);

  let fileCursor;
  const folderObjects = [];
  do {
    const listed = await env.BUCKET.list({
      prefix: `${folderPath}/`,
      cursor: fileCursor,
      include: ["customMetadata"],
    });
    for (const object of listed.objects || []) {
      folderObjects.push(object);
    }
    fileCursor = listed.truncated ? listed.cursor : undefined;
  } while (fileCursor);

  let nestedFolderCursor;
  const nestedFolderMetaKeys = [];
  do {
    const listed = await env.BUCKET.list({ prefix: `${folderKey}/`, cursor: nestedFolderCursor });
    for (const object of listed.objects || []) {
      nestedFolderMetaKeys.push(object.key);
    }
    nestedFolderCursor = listed.truncated ? listed.cursor : undefined;
  } while (nestedFolderCursor);

  assert(folderHead || folderObjects.length > 0 || nestedFolderMetaKeys.length > 0, 404, "Folder not found.");

  const owner = folderHead?.customMetadata?.uploader || "";
  if (!isAdmin(user)) {
    if (owner) {
      assert(owner === user.username, 403, "You do not have permission to delete this folder.");
    } else {
      const hasForeignOwnedFiles = folderObjects.some((object) => {
        const objectOwner = object.customMetadata?.uploader || "";
        return objectOwner && objectOwner !== user.username;
      });
      assert(!hasForeignOwnedFiles, 403, "You do not have permission to delete this folder.");
    }
  }

  const deletedKeys = [];
  for (const object of folderObjects) {
    await env.BUCKET.delete(object.key);
    deletedKeys.push(object.key);
    await adjustUsedBytes(env, object.customMetadata?.uploader || owner, -(object.size || 0));
  }

  if (folderHead) {
    await env.BUCKET.delete(folderKey);
  }
  for (const key of nestedFolderMetaKeys) {
    await env.BUCKET.delete(key);
  }

  await Promise.all([
    env.DB.prepare("DELETE FROM folder_metadata WHERE path = ? OR path LIKE ?")
      .bind(folderPath, `${folderPath}/%`)
      .run(),
    env.DB.prepare("DELETE FROM file_tags WHERE file_key LIKE ?").bind(`${folderPath}/%`).run(),
    env.DB.prepare("DELETE FROM file_versions WHERE file_key LIKE ?").bind(`${folderPath}/%`).run(),
    env.DB.prepare("DELETE FROM file_edit_sessions WHERE file_key LIKE ?").bind(`${folderPath}/%`).run(),
    env.DB.prepare("DELETE FROM favorites WHERE item_type = 'file' AND item_key LIKE ?").bind(`${folderPath}/%`).run(),
    env.DB.prepare("DELETE FROM favorites WHERE item_type = 'folder' AND (item_key = ? OR item_key LIKE ?)")
      .bind(folderPath, `${folderPath}/%`)
      .run(),
    env.DB.prepare("DELETE FROM recent_items WHERE item_type = 'folder' AND (item_key = ? OR item_key LIKE ?)")
      .bind(folderPath, `${folderPath}/%`)
      .run(),
    env.DB.prepare("DELETE FROM trash_items WHERE item_type = 'file' AND item_key LIKE ?").bind(`${folderPath}/%`).run(),
    env.DB.prepare("DELETE FROM trash_items WHERE item_type = 'folder' AND (item_key = ? OR item_key LIKE ?)")
      .bind(folderPath, `${folderPath}/%`)
      .run(),
    env.DB.prepare("DELETE FROM file_search_index WHERE file_key LIKE ?").bind(`${folderPath}/%`).run(),
    env.DB.prepare("DELETE FROM file_permissions WHERE scope_type = 'file' AND scope_key LIKE ?").bind(`${folderPath}/%`).run(),
    env.DB.prepare("DELETE FROM file_permissions WHERE scope_type = 'folder' AND (scope_key = ? OR scope_key LIKE ?)")
      .bind(folderPath, `${folderPath}/%`)
      .run(),
    env.DB.prepare("DELETE FROM share_links WHERE file_key LIKE ?").bind(`${folderPath}/%`).run(),
    env.DB.prepare("DELETE FROM share_links WHERE file_key = ? OR file_key LIKE ?")
      .bind(folderKey, `${folderKey}/%`)
      .run(),
    env.DB.prepare("DELETE FROM file_comments WHERE file_key LIKE ?").bind(`${folderPath}/%`).run(),
    logActivity(env, user.username, "folder.deleted", folderPath, { deletedFileCount: deletedKeys.length }),
  ]);

  return json({ ok: true, deletedFileCount: deletedKeys.length });
}

export async function handleDeleteFile(env, user, key, { hardDelete = false } = {}) {
  const fileKey = decodeURIComponent(key);
  const object = await env.BUCKET.head(fileKey);
  assert(object, 404, "File not found.");

  const access = await getEffectiveAccess(env, user, fileKey, object.customMetadata || {});
  assert(access.canDelete || isAdmin(user) || access.owner === user.username, 403, "Delete permission denied.");

  if (!hardDelete) {
    await env.DB.prepare(
      `
        INSERT INTO trash_items (item_type, item_key, trashed_by, trashed_at, original_parent)
        VALUES ('file', ?, ?, ?, ?)
        ON CONFLICT(item_type, item_key)
        DO UPDATE SET trashed_by = excluded.trashed_by, trashed_at = excluded.trashed_at
      `,
    )
      .bind(fileKey, user.username, nowMs(), sanitizeFolderPath(fileKey.split("/").slice(0, -1).join("/")))
      .run();
    await logActivity(env, user.username, "file.trashed", fileKey);
    return json({ ok: true, trashed: true, key: fileKey });
  }

  await env.BUCKET.delete(fileKey);
  await Promise.all([
    env.DB.prepare("DELETE FROM trash_items WHERE item_type = 'file' AND item_key = ?").bind(fileKey).run(),
    env.DB.prepare("DELETE FROM file_tags WHERE file_key = ?").bind(fileKey).run(),
    env.DB.prepare("DELETE FROM favorites WHERE item_type = 'file' AND item_key = ?").bind(fileKey).run(),
    env.DB.prepare("DELETE FROM file_search_index WHERE file_key = ?").bind(fileKey).run(),
    env.DB.prepare("DELETE FROM file_permissions WHERE scope_type = 'file' AND scope_key = ?").bind(fileKey).run(),
    env.DB.prepare("DELETE FROM file_comments WHERE file_key = ?").bind(fileKey).run(),
    adjustUsedBytes(env, object.customMetadata?.uploader || access.owner, -(object.size || 0)),
    logActivity(env, user.username, "file.deleted", fileKey, { hardDelete: true }),
  ]);
  return json({ ok: true, deleted: true, key: fileKey });
}

export async function handleMove(request, env, user) {
  const payload = await readJson(request);
  const oldKey = payload.oldKey || "";
  const newFolder = sanitizeFolderPath(payload.newFolder || "");
  assert(oldKey, 400, "oldKey is required.");

  const object = await env.BUCKET.get(oldKey);
  assert(object, 404, "Source file not found.");
  const access = await getEffectiveAccess(env, user, oldKey, object.customMetadata || {});
  assert(access.canEdit || access.owner === user.username || isAdmin(user), 403, "Move permission denied.");

  const fileName = sanitizeFilename(payload.newName || oldKey.split("/").pop() || "");
  const newKey = newFolder ? `${newFolder}/${fileName}` : fileName;
  assert(newKey !== oldKey, 400, "New destination must be different.");
  const exists = await env.BUCKET.head(newKey);
  assert(!exists, 409, "Destination already has a file with this name.");

  await env.BUCKET.put(newKey, object.body, {
    customMetadata: {
      ...object.customMetadata,
      updated_at: `${nowMs()}`,
    },
    httpMetadata: object.httpMetadata,
  });
  await env.BUCKET.delete(oldKey);

  await Promise.all([
    env.DB.prepare("UPDATE file_tags SET file_key = ? WHERE file_key = ?").bind(newKey, oldKey).run(),
    env.DB.prepare("UPDATE favorites SET item_key = ? WHERE item_type = 'file' AND item_key = ?")
      .bind(newKey, oldKey)
      .run(),
    env.DB.prepare("UPDATE file_search_index SET file_key = ?, updated_at = ? WHERE file_key = ?")
      .bind(newKey, nowMs(), oldKey)
      .run(),
    env.DB.prepare("UPDATE file_permissions SET scope_key = ? WHERE scope_type = 'file' AND scope_key = ?")
      .bind(newKey, oldKey)
      .run(),
    logActivity(env, user.username, "file.moved", newKey, { from: oldKey, to: newKey }),
  ]);

  return json({ ok: true, oldKey, newKey });
}

export async function handleUpdateVisibility(request, env, user) {
  const payload = await readJson(request);
  const key = payload.key || "";
  const visibility = normalizeVisibility(payload.visibility || "only-me");
  const allowedUsers = payload.allowed_users || "";
  assert(key, 400, "key is required.");

  if (key.startsWith(".folder:")) {
    const folderPath = sanitizeFolderPath(key.replace(".folder:", ""));
    const folderObject = await env.BUCKET.head(folderMetaKey(folderPath));
    assert(folderObject, 404, "Folder not found.");
    if (!isAdmin(user) && folderObject.customMetadata?.uploader !== user.username) {
      throw new HttpError(403, "Permission denied.");
    }
    await env.BUCKET.put(folderMetaKey(folderPath), "", {
      customMetadata: {
        ...folderObject.customMetadata,
        visibility,
        allowed_users: allowedUsers,
      },
    });
    await logActivity(env, user.username, "folder.visibility_updated", folderPath, { visibility, allowedUsers });
    return json({ ok: true });
  }

  const object = await env.BUCKET.get(key);
  assert(object, 404, "File not found.");
  const access = await getEffectiveAccess(env, user, key, object.customMetadata || {});
  if (!isAdmin(user) && access.owner !== user.username) {
    throw new HttpError(403, "Permission denied.");
  }

  await env.BUCKET.put(key, object.body, {
    customMetadata: {
      ...object.customMetadata,
      visibility,
      allowed_users: allowedUsers,
      inherit_visibility: "0",
      updated_at: `${nowMs()}`,
    },
    httpMetadata: object.httpMetadata,
  });

  await logActivity(env, user.username, "file.visibility_updated", key, { visibility, allowedUsers });
  return json({ ok: true });
}

export async function handleBatch(request, env, user) {
  const payload = await readJson(request);
  const action = payload.action;
  const keys = Array.isArray(payload.keys) ? payload.keys : [];
  assert(keys.length > 0, 400, "keys[] is required.");

  if (action === "delete") {
    const hardDelete = payload.hardDelete === true;
    const results = [];
    for (const key of keys) {
      try {
        const response = await handleDeleteFile(env, user, encodeURIComponent(key), { hardDelete });
        results.push({ key, ok: response.ok !== false });
      } catch (error) {
        results.push({ key, ok: false, error: error.message });
      }
    }
    return json({ ok: true, action, results });
  }

  if (action === "move") {
    const destination = sanitizeFolderPath(payload.destination || "");
    const results = [];
    for (const key of keys) {
      try {
        await handleMove(
          new Request("https://vault.local/vault/api/move", {
            method: "POST",
            body: JSON.stringify({ oldKey: key, newFolder: destination }),
          }),
          env,
          user,
        );
        results.push({ key, ok: true });
      } catch (error) {
        results.push({ key, ok: false, error: error.message });
      }
    }
    return json({ ok: true, action, results });
  }

  throw new HttpError(400, "Unsupported batch action.");
}

export async function handleRename(request, env, user) {
  const payload = await readJson(request);
  const key = payload.key || "";
  const newName = sanitizeFilename(payload.newName || "");
  assert(key, 400, "key is required.");
  const folder = key.includes("/") ? key.split("/").slice(0, -1).join("/") : "";
  const newKey = folder ? `${folder}/${newName}` : newName;
  assert(key !== newKey, 400, "New name must differ from current name.");

  return handleMove(
    new Request("https://vault.local/vault/api/move", {
      method: "POST",
      body: JSON.stringify({ oldKey: key, newFolder: folder, newName }),
    }),
    env,
    user,
  );
}

export async function handleDuplicate(request, env, user) {
  const payload = await readJson(request);
  const key = payload.key || "";
  assert(key, 400, "key is required.");

  const object = await env.BUCKET.get(key);
  assert(object, 404, "File not found.");

  const access = await getEffectiveAccess(env, user, key, object.customMetadata || {});
  assert(access.canView, 403, "Permission denied.");

  const folder = key.includes("/") ? key.split("/").slice(0, -1).join("/") : "";
  const name = key.split("/").pop() || "file";
  const ext = extensionOf(name);
  const base = ext ? name.slice(0, -ext.length - 1) : name;
  let copy = 1;
  let newKey = folder ? `${folder}/${base} copy${ext ? `.${ext}` : ""}` : `${base} copy${ext ? `.${ext}` : ""}`;
  while (await env.BUCKET.head(newKey)) {
    copy += 1;
    newKey = folder ? `${folder}/${base} copy (${copy})${ext ? `.${ext}` : ""}` : `${base} copy (${copy})${ext ? `.${ext}` : ""}`;
  }

  await env.BUCKET.put(newKey, object.body, {
    customMetadata: {
      ...object.customMetadata,
      uploader: user.username,
      updated_at: `${nowMs()}`,
    },
    httpMetadata: object.httpMetadata,
  });

  const duplicated = await env.BUCKET.head(newKey);
  await Promise.all([
    adjustUsedBytes(env, user.username, duplicated?.size || 0),
    logActivity(env, user.username, "file.duplicated", newKey, { source: key }),
  ]);

  return json({ ok: true, key: newKey });
}

export async function handleFavorite(request, env, user) {
  const payload = await readJson(request);
  const itemType = payload.itemType === "folder" ? "folder" : "file";
  const itemKey = itemType === "folder" ? sanitizeFolderPath(payload.itemKey || "") : payload.itemKey || "";
  const starred = payload.starred !== false;
  assert(itemKey, 400, "itemKey is required.");

  if (starred) {
    await env.DB.prepare(
      `
        INSERT INTO favorites (username, item_type, item_key, created_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(username, item_type, item_key) DO NOTHING
      `,
    )
      .bind(user.username, itemType, itemKey, nowMs())
      .run();
  } else {
    await env.DB.prepare("DELETE FROM favorites WHERE username = ? AND item_type = ? AND item_key = ?")
      .bind(user.username, itemType, itemKey)
      .run();
  }

  return json({ ok: true, itemType, itemKey, starred });
}

export async function handleTags(request, env, user) {
  const payload = await readJson(request);
  const key = payload.key || "";
  assert(key, 400, "key is required.");
  const tags = Array.isArray(payload.tags)
    ? payload.tags
      .map((tag) => `${tag}`.trim().toLowerCase())
      .filter(Boolean)
      .slice(0, 20)
    : [];

  const object = await env.BUCKET.head(key);
  assert(object, 404, "File not found.");
  const access = await getEffectiveAccess(env, user, key, object.customMetadata || {});
  assert(access.canEdit || access.owner === user.username || isAdmin(user), 403, "Tag edit permission denied.");

  await env.DB.prepare("DELETE FROM file_tags WHERE file_key = ?").bind(key).run();
  for (const tag of tags) {
    await env.DB.prepare(
      `
        INSERT INTO file_tags (file_key, tag, created_by, created_at)
        VALUES (?, ?, ?, ?)
      `,
    )
      .bind(key, tag, user.username, nowMs())
      .run();
  }

  await logActivity(env, user.username, "file.tags_updated", key, { tags });
  return json({ ok: true, key, tags });
}

export async function handleTrashRestore(request, env, user) {
  const payload = await readJson(request);
  const key = payload.key || "";
  assert(key, 400, "key is required.");

  const trashItem = await env.DB.prepare(
    "SELECT item_key FROM trash_items WHERE item_type = 'file' AND item_key = ?",
  )
    .bind(key)
    .first();
  assert(trashItem, 404, "File is not in trash.");

  const object = await env.BUCKET.head(key);
  assert(object, 404, "File no longer exists in storage.");
  const access = await getEffectiveAccess(env, user, key, object.customMetadata || {});
  assert(access.canEdit || access.owner === user.username || isAdmin(user), 403, "Restore permission denied.");

  await env.DB.prepare("DELETE FROM trash_items WHERE item_type = 'file' AND item_key = ?")
    .bind(key)
    .run();
  await logActivity(env, user.username, "file.restored", key);
  return json({ ok: true, key });
}

export async function handleFileDeleteRoute(request, env, user, encodedKey) {
  const hardDelete = new URL(request.url).searchParams.get("hard") === "1";
  return handleDeleteFile(env, user, encodedKey, { hardDelete });
}

export async function handleLegacyPathRedirect(request, env, user) {
  const url = new URL(request.url);
  const currentPath = parsePathFromUrl(url);
  const full = await listVisiblePathContents(env, user, currentPath);
  return json(full);
}

export async function handleFilePreviewContent(request, env, user) {
  const url = new URL(request.url);
  const key = url.searchParams.get("key") || "";
  assert(key, 400, "key is required.");
  const object = await env.BUCKET.get(key);
  assert(object, 404, "File not found.");
  const access = await getEffectiveAccess(env, user, key, object.customMetadata || {});
  assert(access.canView, 403, "Permission denied.");

  const isText = isEditableFile(key) || /^text\//i.test(getMimeType(key));
  let textPreview = null;
  if (isText) {
    const content = await object.text();
    textPreview = content.slice(0, 50_000);
  }

  await upsertRecentItem(env, user.username, "file", key);
  return json({
    key,
    mimeType: getMimeType(key),
    previewType: fileIconFromKey(key),
    textPreview,
    size: object.size,
    canDownload: access.canDownload,
    url: `/vault/file/${encodeURIComponent(key)}`,
  });
}

export async function handleSearch(request, env, user) {
  const url = new URL(request.url);
  const query = (url.searchParams.get("q") || "").trim().toLowerCase();
  assert(query.length >= 2, 400, "Search query must be at least 2 characters.");

  const { results: byTextRows } = await env.DB.prepare(
    `
      SELECT file_key
      FROM file_search_index
      WHERE searchable_text LIKE ?
      LIMIT 200
    `,
  )
    .bind(`%${query}%`)
    .all();
  const byText = new Set((byTextRows || []).map((row) => row.file_key));

  const matched = [];
  let cursor;
  do {
    const listed = await env.BUCKET.list({ include: ["customMetadata"], cursor });
    for (const object of listed.objects || []) {
      if (isFolderMetaKey(object.key) || isInternalVersionKey(object.key)) continue;
      if (!object.key.toLowerCase().includes(query) && !byText.has(object.key)) continue;
      const access = await getEffectiveAccess(env, user, object.key, object.customMetadata || {});
      if (!access.canView) continue;
      matched.push({
        key: object.key,
        size: object.size,
        owner: object.customMetadata?.uploader || "",
        visibility: access.visibility,
        updatedAt: object.uploaded ? new Date(object.uploaded).getTime() : null,
        editable: isEditableFile(object.key),
      });
    }
    cursor = listed.truncated ? listed.cursor : undefined;
  } while (cursor && matched.length < 500);

  return json({
    query,
    count: matched.length,
    files: matched.slice(0, 200),
  });
}

export async function serveDirectFile(request, env, user, key, { sharedAccess = null } = {}) {
  const fileKey = decodeURIComponent(key);
  const object = await env.BUCKET.get(fileKey);
  assert(object, 404, "File not found.");

  let canAccess = false;
  let canDownload = true;

  if (sharedAccess?.granted) {
    canAccess = true;
    canDownload = sharedAccess.permission === "download" && !sharedAccess.disableDownload;
  } else {
    const access = await getEffectiveAccess(env, user, fileKey, object.customMetadata || {});
    canAccess = access.canView;
    canDownload = access.canDownload;
  }

  if (!canAccess) {
    if (!user) {
      return new Response(null, {
        status: 302,
        headers: {
          Location: `/auth/login?redirect=${encodeURIComponent(`/vault/file/${encodeURIComponent(fileKey)}`)}`,
        },
      });
    }
    throw new HttpError(403, "Access denied.");
  }

  const wantsDownload = new URL(request.url).searchParams.get("download") === "1";
  if (wantsDownload && !canDownload) {
    throw new HttpError(403, "Download is disabled for this file.");
  }

  const headers = new Headers();
  object.writeHttpMetadata(headers);
  headers.set("etag", object.httpEtag);
  headers.set("Content-Type", getMimeType(fileKey));
  if (wantsDownload) {
    const filename = fileKey.split("/").pop() || "download";
    headers.set("Content-Disposition", `attachment; filename="${filename}"`);
  }

  if (user?.username) {
    await Promise.all([
      addBandwidth(env, user.username, object.size || 0),
      upsertRecentItem(env, user.username, "file", fileKey),
    ]);
  }

  return new Response(object.body, { headers });
}

export function isTextBasedFile(fileKey) {
  return isEditableFile(fileKey) || /^text\//i.test(getMimeType(fileKey));
}

export async function upsertSearchIndex(env, key, content) {
  const searchable = `${key}\n${(content || "").slice(0, 20000)}`;
  await env.DB.prepare(
    `
      INSERT INTO file_search_index (file_key, searchable_text, updated_at)
      VALUES (?, ?, ?)
      ON CONFLICT(file_key)
      DO UPDATE SET searchable_text = excluded.searchable_text, updated_at = excluded.updated_at
    `,
  )
    .bind(key, searchable, nowMs())
    .run();
}

export async function removeSearchIndex(env, key) {
  await env.DB.prepare("DELETE FROM file_search_index WHERE file_key = ?").bind(key).run();
}

export function maybeTextResponse(message) {
  return text(message);
}
