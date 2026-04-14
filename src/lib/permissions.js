import { canDownloadByRole, isAdmin, isCommenterOrHigher, isEditor, normalizeRole } from "./auth.js";

export const VISIBILITY = {
  ONLY_ME: "only-me",
  VAULT: "vault",
  PEOPLE: "people",
  PUBLIC: "public",
};

export function normalizeVisibility(value) {
  if (value === "specific") return VISIBILITY.PEOPLE;
  if (value === "private") return VISIBILITY.ONLY_ME;
  if (value === "inherit") return VISIBILITY.ONLY_ME;
  if (
    value === VISIBILITY.ONLY_ME ||
    value === VISIBILITY.VAULT ||
    value === VISIBILITY.PEOPLE ||
    value === VISIBILITY.PUBLIC
  ) {
    return value;
  }
  return VISIBILITY.ONLY_ME;
}

export function parseAllowedUsers(value) {
  if (!value) return [];
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

export function getAncestors(path) {
  const parts = (path || "")
    .split("/")
    .map((part) => part.trim())
    .filter(Boolean);
  const ancestors = [];
  for (let i = parts.length; i > 0; i -= 1) {
    ancestors.push(parts.slice(0, i).join("/"));
  }
  return ancestors;
}

export async function getFolderMetadata(env, folderPath) {
  if (!folderPath) return null;
  const folderObject = await env.BUCKET.head(`.folder:${folderPath}`);
  return folderObject?.customMetadata || null;
}

export async function resolveVisibilityForKey(env, key, metadata) {
  let visibility = normalizeVisibility(metadata?.visibility);
  let allowedUsers = metadata?.allowed_users || "";
  let owner = metadata?.uploader || "";
  const inheritFromFolder =
    metadata?.inherit_visibility === "1" ||
    metadata?.inherit_visibility === 1 ||
    metadata?.inherit_visibility == null;

  if (!key.includes("/")) {
    return { visibility, allowedUsers, owner };
  }

  const folderPath = key.split("/").slice(0, -1).join("/");
  const folderMeta = await getFolderMetadata(env, folderPath);
  if (inheritFromFolder && folderMeta?.visibility) {
    visibility = normalizeVisibility(folderMeta.visibility);
    allowedUsers = folderMeta.allowed_users || "";
  }
  if (!owner) {
    owner = folderMeta?.uploader || "";
  }

  return { visibility, allowedUsers, owner };
}

export async function getPermissionOverride(env, username, key) {
  const path = key.includes("/") ? key.split("/").slice(0, -1).join("/") : "";
  const ancestors = getAncestors(path);
  const scopeKeys = [key, ...ancestors];
  const placeholders = scopeKeys.map(() => "?").join(",");

  if (!placeholders) return null;

  const { results } = await env.DB.prepare(
    `
      SELECT scope_type, scope_key, role, can_download, expires_at
      FROM file_permissions
      WHERE username = ?
        AND (
          (scope_type = 'file' AND scope_key = ?)
          OR (scope_type = 'folder' AND scope_key IN (${placeholders}))
        )
        AND (expires_at IS NULL OR expires_at > ?)
      ORDER BY CASE scope_type WHEN 'file' THEN 0 ELSE 1 END,
               LENGTH(scope_key) DESC
      LIMIT 1
    `,
  )
    .bind(username, key, ...scopeKeys, Date.now())
    .all();

  if (!results?.length) return null;
  return results[0];
}

function isAllowedByVisibility(user, visibility, allowedUsers, owner) {
  if (visibility === VISIBILITY.PUBLIC || visibility === VISIBILITY.VAULT) return true;
  if (!user) return false;
  if (owner && user.username === owner) return true;
  if (visibility === VISIBILITY.PEOPLE) {
    return parseAllowedUsers(allowedUsers).includes(user.username);
  }
  return false;
}

export function canAccessFolder(user, folderMeta) {
  const visibility = normalizeVisibility(folderMeta?.visibility);
  const allowedUsers = folderMeta?.allowed_users || "";
  const owner = folderMeta?.uploader || "";
  return isAllowedByVisibility(user, visibility, allowedUsers, owner) || isAdmin(user);
}

function roleCapabilities(role, user, owner) {
  const normalized = normalizeRole(role);
  if (normalized === "admin") {
    return {
      role: normalized,
      canView: true,
      canEdit: true,
      canComment: true,
      canDelete: true,
      canDownload: true,
    };
  }

  if (normalized === "editor") {
    const isOwner = user?.username && owner && user.username === owner;
    return {
      role: normalized,
      canView: true,
      canEdit: true,
      canComment: true,
      canDelete: isOwner,
      canDownload: true,
    };
  }

  if (normalized === "commenter") {
    return {
      role: normalized,
      canView: true,
      canEdit: false,
      canComment: true,
      canDelete: false,
      canDownload: true,
    };
  }

  if (normalized === "viewer-download-disabled") {
    return {
      role: normalized,
      canView: true,
      canEdit: false,
      canComment: false,
      canDelete: false,
      canDownload: false,
    };
  }

  return {
    role: "viewer",
    canView: true,
    canEdit: false,
    canComment: false,
    canDelete: false,
    canDownload: true,
  };
}

export async function getEffectiveAccess(env, user, key, metadata) {
  const visibilityState = await resolveVisibilityForKey(env, key, metadata);
  const { visibility, allowedUsers, owner } = visibilityState;

  if (user && isAdmin(user)) {
    return {
      visibility,
      owner,
      allowedUsers: parseAllowedUsers(allowedUsers),
      effectiveRole: "admin",
      canView: true,
      canEdit: true,
      canComment: true,
      canDelete: true,
      canDownload: true,
    };
  }

  if (!isAllowedByVisibility(user, visibility, allowedUsers, owner)) {
    return {
      visibility,
      owner,
      allowedUsers: parseAllowedUsers(allowedUsers),
      effectiveRole: null,
      canView: false,
      canEdit: false,
      canComment: false,
      canDelete: false,
      canDownload: false,
    };
  }

  if (!user) {
    return {
      visibility,
      owner,
      allowedUsers: parseAllowedUsers(allowedUsers),
      effectiveRole: "public",
      canView: true,
      canEdit: false,
      canComment: false,
      canDelete: false,
      canDownload: true,
    };
  }

  const override = await getPermissionOverride(env, user.username, key);
  const roleSource = override?.role || user.role;
  const caps = roleCapabilities(roleSource, user, owner);

  const canDelete = caps.canDelete || owner === user.username || isAdmin(user);

  return {
    visibility,
    owner,
    allowedUsers: parseAllowedUsers(allowedUsers),
    effectiveRole: caps.role,
    canView: true,
    canEdit: caps.canEdit || (isEditor(user) && owner === user.username),
    canComment: caps.canComment || isCommenterOrHigher(user),
    canDelete,
    canDownload: (override ? Boolean(override.can_download) : caps.canDownload) && canDownloadByRole(user),
  };
}

export function canUploadFileByRole(user, filename) {
  if (isEditor(user) || isAdmin(user)) return true;
  if (!filename) return false;
  return /\.pdf$/i.test(filename);
}
