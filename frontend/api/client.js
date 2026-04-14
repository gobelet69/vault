function buildQuery(params = {}) {
  const entries = Object.entries(params).filter(([, value]) => value !== undefined && value !== null && value !== "");
  const search = new URLSearchParams(entries);
  return search.toString();
}

class ApiError extends Error {
  constructor(message, status, payload = null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.payload = payload;
  }
}

async function request(path, { method = "GET", jsonBody, headers = {}, rawBody } = {}) {
  const response = await fetch(path, {
    method,
    headers: {
      ...(jsonBody ? { "Content-Type": "application/json" } : {}),
      ...headers,
    },
    body: jsonBody ? JSON.stringify(jsonBody) : rawBody,
  });

  const contentType = response.headers.get("content-type") || "";
  const isJson = contentType.includes("application/json");
  const payload = isJson ? await response.json() : await response.text();

  if (!response.ok) {
    const message = isJson ? payload.error || "Request failed." : payload || "Request failed.";
    throw new ApiError(message, response.status, payload);
  }
  return payload;
}

export const apiClient = {
  bootstrap(params = {}) {
    const query = buildQuery(params);
    return request(`/vault/api/bootstrap${query ? `?${query}` : ""}`);
  },
  listFiles(params = {}) {
    const query = buildQuery(params);
    return request(`/vault/api/files${query ? `?${query}` : ""}`);
  },
  search(query) {
    return request(`/vault/api/search?q=${encodeURIComponent(query)}`);
  },
  upload(file, options = {}) {
    return request("/vault/api/upload", {
      method: "POST",
      rawBody: file,
      headers: {
        "X-File-Name": file.name,
        "X-Folder": options.folderPath || "",
        "X-Visibility": options.visibility || "only-me",
        "X-Allowed-Users": options.allowedUsers || "",
      },
    });
  },
  createFolder(payload) {
    return request("/vault/api/create-folder", { method: "POST", jsonBody: payload });
  },
  createTextFile(payload) {
    return request("/vault/api/create-text-file", { method: "POST", jsonBody: payload });
  },
  deleteFolder(path) {
    return request("/vault/api/delete-folder", {
      method: "POST",
      jsonBody: { path },
    });
  },
  deleteFile(key, { hardDelete = false } = {}) {
    return request(`/vault/api/delete/${encodeURIComponent(key)}${hardDelete ? "?hard=1" : ""}`);
  },
  moveFile(oldKey, newFolder, newName) {
    return request("/vault/api/move", {
      method: "POST",
      jsonBody: { oldKey, newFolder, newName },
    });
  },
  renameFile(key, newName) {
    return request("/vault/api/rename", { method: "POST", jsonBody: { key, newName } });
  },
  duplicateFile(key) {
    return request("/vault/api/duplicate", { method: "POST", jsonBody: { key } });
  },
  updateVisibility(payload) {
    return request("/vault/api/update-visibility", { method: "POST", jsonBody: payload });
  },
  batch(payload) {
    return request("/vault/api/batch", { method: "POST", jsonBody: payload });
  },
  toggleFavorite(itemType, itemKey, starred) {
    return request("/vault/api/favorite", { method: "POST", jsonBody: { itemType, itemKey, starred } });
  },
  updateTags(key, tags) {
    return request("/vault/api/tags", { method: "POST", jsonBody: { key, tags } });
  },
  restoreTrash(key) {
    return request("/vault/api/restore-trash", { method: "POST", jsonBody: { key } });
  },
  preview(key) {
    return request(`/vault/api/preview?key=${encodeURIComponent(key)}`);
  },
  getFileContent(key, { metadataOnly = false } = {}) {
    const query = metadataOnly ? "&metadata=1" : "";
    return request(`/vault/api/file-content?key=${encodeURIComponent(key)}${query}`);
  },
  saveFile(payload) {
    return request("/vault/api/file-save", { method: "POST", jsonBody: payload });
  },
  fileHistory(key) {
    return request(`/vault/api/file-history?key=${encodeURIComponent(key)}`);
  },
  restoreVersion(versionId) {
    return request("/vault/api/file-restore", { method: "POST", jsonBody: { versionId } });
  },
  diffPreview(key, content) {
    return request("/vault/api/file-diff", { method: "POST", jsonBody: { key, content } });
  },
  getPresence(key) {
    return request(`/vault/api/editor-presence?key=${encodeURIComponent(key)}`);
  },
  heartbeatPresence(key, active = true) {
    return request("/vault/api/editor-presence", {
      method: "POST",
      jsonBody: { key, active },
    });
  },
  createShareLink(payload) {
    return request("/vault/api/share-link", { method: "POST", jsonBody: payload });
  },
  listShareLinks(key) {
    return request(`/vault/api/share-link?key=${encodeURIComponent(key)}`);
  },
  setPermissionOverride(payload) {
    return request("/vault/api/permissions", { method: "POST", jsonBody: payload });
  },
  getComments(key) {
    return request(`/vault/api/comments?key=${encodeURIComponent(key)}`);
  },
  postComment(key, body, anchor) {
    return request("/vault/api/comments", { method: "POST", jsonBody: { key, body, anchor } });
  },
  getActivity(params = {}) {
    const query = buildQuery(params);
    return request(`/vault/api/activity${query ? `?${query}` : ""}`);
  },
};

export { ApiError };
