import { getSessionUser, requireUser } from "./lib/auth.js";
import { cleanupExpiredData, enforceRateLimit } from "./lib/db.js";
import { HttpError, getApiErrorBody, json, text, withSecurityHeaders } from "./lib/http.js";
import {
  handleBatch,
  handleBootstrap,
  handleCreateFolder,
  handleCreateTextFile,
  handleDeleteFolder,
  handleDuplicate,
  handleFavorite,
  handleFileDeleteRoute,
  handleFilePreviewContent,
  handleLegacyPathRedirect,
  handleListFiles,
  handleMove,
  handleRename,
  handleSearch,
  handleTags,
  handleTrashRestore,
  handleUpdateVisibility,
  handleUpload,
  serveDirectFile,
} from "./routes/files.js";
import {
  handleDiffPreview,
  handleEditorPresenceGet,
  handleEditorPresencePost,
  handleFileContent,
  handleFileHistory,
  handleFileSave,
  handleRestoreVersion,
} from "./routes/editor.js";
import {
  consumeShareDownload,
  handleActivityLog,
  handleCommentsGet,
  handleCommentsPost,
  handleCreateShareLink,
  handleListShareLinks,
  handlePermissionOverride,
  validateShareAccess,
} from "./routes/sharing.js";
import { renderVaultAppShell } from "./routes/ui.js";
import { handleUserInvite, handleUserManagement } from "./routes/users.js";

function isApi(pathname) {
  return pathname.startsWith("/vault/api/");
}

function getRateLimitKey(request, user) {
  if (user?.username) return `user:${user.username}`;
  const ip = request.headers.get("CF-Connecting-IP") || "anon";
  return `ip:${ip}`;
}

async function routeRequest(request, env, ctx) {
  const url = new URL(request.url);
  const pathname = url.pathname;
  const method = request.method.toUpperCase();

  if (pathname.startsWith("/vault/static/")) {
    if (!env.ASSETS || typeof env.ASSETS.fetch !== "function") {
      throw new HttpError(500, "Static assets binding is not configured.");
    }
    return env.ASSETS.fetch(request);
  }

  const user = await getSessionUser(request, env);

  if (pathname.startsWith("/vault/file/")) {
    const key = pathname.replace("/vault/file/", "");
    const shareToken = url.searchParams.get("share");
    const sharedAccess = shareToken ? await validateShareAccess(request, env, decodeURIComponent(key), shareToken) : null;
    if (shareToken && sharedAccess?.passwordRequired) {
      throw new HttpError(401, "Share password required. Provide ?password=... or X-Share-Password header.");
    }
    if (shareToken && !sharedAccess?.granted && !user) {
      throw new HttpError(403, "Share link is invalid, expired, or blocked.");
    }
    const response = await serveDirectFile(request, env, user, key, { sharedAccess });
    if (sharedAccess?.granted) {
      ctx.waitUntil(consumeShareDownload(env, sharedAccess.linkId));
    }
    return response;
  }

  if (isApi(pathname)) {
    const limitOk = await enforceRateLimit(env, getRateLimitKey(request, user), {
      windowSeconds: 60,
      maxRequests: 240,
    });
    if (!limitOk) {
      throw new HttpError(429, "Rate limit exceeded.");
    }
  }

  if (pathname === "/vault" || pathname === "/vault/" || pathname === "/vault/admin") {
    if (!user) {
      return new Response(null, {
        status: 302,
        headers: { Location: `/auth/login?redirect=${encodeURIComponent(pathname + url.search)}` },
      });
    }
    return renderVaultAppShell(user);
  }

  if (!user && pathname.startsWith("/vault/api/")) {
    throw new HttpError(401, "Authentication required.");
  }

  if (pathname === "/vault/api/bootstrap" && method === "GET") {
    requireUser(user);
    return handleBootstrap(request, env, user);
  }

  if ((pathname === "/vault/api/files" || pathname === "/vault/api/list") && method === "GET") {
    requireUser(user);
    return handleListFiles(request, env, user);
  }

  if (pathname === "/vault/api/search" && method === "GET") {
    requireUser(user);
    return handleSearch(request, env, user);
  }

  if (pathname === "/vault/api/path" && method === "GET") {
    requireUser(user);
    return handleLegacyPathRedirect(request, env, user);
  }

  if (pathname === "/vault/api/upload" && method === "POST") {
    requireUser(user);
    return handleUpload(request, env, user);
  }

  if (pathname === "/vault/api/create-folder" && method === "POST") {
    requireUser(user);
    return handleCreateFolder(request, env, user);
  }

  if (pathname === "/vault/api/create-text-file" && method === "POST") {
    requireUser(user);
    return handleCreateTextFile(request, env, user);
  }

  if (pathname === "/vault/api/delete-folder" && method === "POST") {
    requireUser(user);
    return handleDeleteFolder(request, env, user);
  }

  if (pathname.startsWith("/vault/api/delete/")) {
    requireUser(user);
    const key = pathname.replace("/vault/api/delete/", "");
    return handleFileDeleteRoute(request, env, user, key);
  }

  if (pathname === "/vault/api/move" && method === "POST") {
    requireUser(user);
    return handleMove(request, env, user);
  }

  if (pathname === "/vault/api/update-visibility" && method === "POST") {
    requireUser(user);
    return handleUpdateVisibility(request, env, user);
  }

  if (pathname === "/vault/api/batch" && method === "POST") {
    requireUser(user);
    return handleBatch(request, env, user);
  }

  if (pathname === "/vault/api/rename" && method === "POST") {
    requireUser(user);
    return handleRename(request, env, user);
  }

  if (pathname === "/vault/api/duplicate" && method === "POST") {
    requireUser(user);
    return handleDuplicate(request, env, user);
  }

  if (pathname === "/vault/api/favorite" && method === "POST") {
    requireUser(user);
    return handleFavorite(request, env, user);
  }

  if (pathname === "/vault/api/tags" && method === "POST") {
    requireUser(user);
    return handleTags(request, env, user);
  }

  if (pathname === "/vault/api/restore-trash" && method === "POST") {
    requireUser(user);
    return handleTrashRestore(request, env, user);
  }

  if (pathname === "/vault/api/preview" && method === "GET") {
    requireUser(user);
    return handleFilePreviewContent(request, env, user);
  }

  if (pathname === "/vault/api/file-content" && method === "GET") {
    requireUser(user);
    return handleFileContent(request, env, user);
  }

  if (pathname === "/vault/api/file-save" && method === "POST") {
    requireUser(user);
    return handleFileSave(request, env, user);
  }

  if (pathname === "/vault/api/file-history" && method === "GET") {
    requireUser(user);
    return handleFileHistory(request, env, user);
  }

  if (pathname === "/vault/api/file-restore" && method === "POST") {
    requireUser(user);
    return handleRestoreVersion(request, env, user);
  }

  if (pathname === "/vault/api/file-diff" && method === "POST") {
    requireUser(user);
    return handleDiffPreview(request, env, user);
  }

  if (pathname === "/vault/api/editor-presence" && method === "GET") {
    requireUser(user);
    return handleEditorPresenceGet(request, env, user);
  }

  if (pathname === "/vault/api/editor-presence" && method === "POST") {
    requireUser(user);
    return handleEditorPresencePost(request, env, user);
  }

  if (pathname === "/vault/api/share-link" && method === "POST") {
    requireUser(user);
    return handleCreateShareLink(request, env, user);
  }

  if (pathname === "/vault/api/share-link" && method === "GET") {
    requireUser(user);
    return handleListShareLinks(request, env, user);
  }

  if (pathname === "/vault/api/comments" && method === "GET") {
    requireUser(user);
    return handleCommentsGet(request, env, user);
  }

  if (pathname === "/vault/api/comments" && method === "POST") {
    requireUser(user);
    return handleCommentsPost(request, env, user);
  }

  if (pathname === "/vault/api/activity" && method === "GET") {
    requireUser(user);
    return handleActivityLog(request, env, user);
  }

  if (pathname === "/vault/api/permissions" && method === "POST") {
    requireUser(user);
    return handlePermissionOverride(request, env, user);
  }

  if (pathname === "/vault/api/users" && method === "POST") {
    requireUser(user);
    return handleUserManagement(request, env, user);
  }

  if (pathname === "/vault/api/invite" && method === "POST") {
    requireUser(user);
    return handleUserInvite(request, env, user);
  }

  if (env.ASSETS && typeof env.ASSETS.fetch === "function") {
    return env.ASSETS.fetch(request);
  }

  throw new HttpError(404, "Not found.");
}

export default {
  async fetch(request, env, ctx) {
    try {
      const response = await routeRequest(request, env, ctx);
      ctx.waitUntil(cleanupExpiredData(env));
      return withSecurityHeaders(response);
    } catch (error) {
      if (error instanceof HttpError) {
        if (isApi(new URL(request.url).pathname)) {
          return withSecurityHeaders(json(getApiErrorBody(error), error.status));
        }
        return withSecurityHeaders(text(error.message, error.status));
      }

      if (isApi(new URL(request.url).pathname)) {
        return withSecurityHeaders(json(getApiErrorBody(error), 500));
      }
      return withSecurityHeaders(text("Internal server error.", 500));
    }
  },
};
