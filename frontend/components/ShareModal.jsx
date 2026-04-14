import React, { useEffect, useMemo, useState } from "react";
import { apiClient } from "../api/client.js";

function normalizeVisibility(value) {
  if (["only-me", "vault", "people", "public"].includes(value)) return value;
  return "only-me";
}

function normalizeAllowedUsers(value) {
  if (!value) return "";
  if (Array.isArray(value)) return value.join(", ");
  return `${value}`;
}

export function ShareModal({
  open,
  onClose,
  targetKey,
  initialVisibility = "only-me",
  initialAllowedUsers = "",
  isAdmin = false,
  onSaved,
}) {
  const [links, setLinks] = useState([]);
  const [visibility, setVisibility] = useState("only-me");
  const [allowedUsers, setAllowedUsers] = useState("");

  const [linkPermission, setLinkPermission] = useState("download");
  const [expiresAt, setExpiresAt] = useState("");
  const [maxDownloads, setMaxDownloads] = useState("");
  const [disableDownload, setDisableDownload] = useState(false);
  const [password, setPassword] = useState("");

  const [permUsername, setPermUsername] = useState("");
  const [permRole, setPermRole] = useState("viewer");
  const [permCanDownload, setPermCanDownload] = useState(true);
  const [permExpiresAt, setPermExpiresAt] = useState("");
  const [activeSection, setActiveSection] = useState("permissions");

  const [busyAction, setBusyAction] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [latestLink, setLatestLink] = useState("");

  useEffect(() => {
    if (!open || !targetKey) return;
    setVisibility(normalizeVisibility(initialVisibility));
    setAllowedUsers(normalizeAllowedUsers(initialAllowedUsers));
    setLinks([]);
    setLatestLink("");
    setError("");
    setNotice("");
    setActiveSection("permissions");
  }, [open, targetKey, initialVisibility, initialAllowedUsers]);

  const isFolder = targetKey?.startsWith(".folder:");
  const normalizedKey = useMemo(
    () => (isFolder ? targetKey.replace(".folder:", "") : targetKey),
    [isFolder, targetKey],
  );

  useEffect(() => {
    if (!open || !normalizedKey || isFolder) return;
    apiClient
      .listShareLinks(normalizedKey)
      .then((payload) => setLinks(payload.links || []))
      .catch((err) => setError(err.message));
  }, [open, normalizedKey, isFolder]);

  if (!open) return null;

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-card" onClick={(event) => event.stopPropagation()}>
        <div className="modal-header">
          <h3>Share {isFolder ? "folder" : "file"}</h3>
          <button type="button" className="btn btn-sm btn-muted" onClick={onClose}>
            Close
          </button>
        </div>
        <div className="muted modal-key">{normalizedKey}</div>

        <div className="modal-tabs">
          <button
            type="button"
            className={`modal-tab ${activeSection === "permissions" ? "active" : ""}`}
            onClick={() => setActiveSection("permissions")}
          >
            Permission edition
          </button>
          <button
            type="button"
            className={`modal-tab ${activeSection === "links" ? "active" : ""}`}
            onClick={() => setActiveSection("links")}
          >
            Share via link
          </button>
        </div>

        {activeSection === "permissions" ? (
          <>
            <div className="panel">
              <div className="panel-title">Visibility & access</div>
              <div className="form-grid">
                <label>
                  Visibility
                  <select value={visibility} onChange={(event) => setVisibility(event.target.value)}>
                    <option value="only-me">Only me</option>
                    <option value="people">Specific people</option>
                    <option value="vault">All signed-in users</option>
                    <option value="public">Public</option>
                  </select>
                </label>
                <label>
                  Allowed users (comma-separated)
                  <input
                    value={allowedUsers}
                    onChange={(event) => setAllowedUsers(event.target.value)}
                    placeholder="alice, bob"
                    disabled={visibility !== "people"}
                  />
                </label>
              </div>
              <div className="modal-actions">
                <button
                  type="button"
                  className="btn"
                  disabled={busyAction === "visibility"}
                  onClick={async () => {
                    try {
                      setBusyAction("visibility");
                      setError("");
                      setNotice("");
                      await apiClient.updateVisibility({
                        key: targetKey,
                        visibility,
                        allowed_users: visibility === "people" ? allowedUsers : "",
                      });
                      setNotice("Visibility updated.");
                      await onSaved?.();
                    } catch (err) {
                      setError(err.message);
                    } finally {
                      setBusyAction("");
                    }
                  }}
                >
                  {busyAction === "visibility" ? "Saving..." : "Save visibility"}
                </button>
              </div>
            </div>

            {isAdmin ? (
              <div className="panel">
                <div className="panel-title">Permission override (admin)</div>
                <div className="form-grid">
                  <label>
                    Username
                    <input
                      value={permUsername}
                      onChange={(event) => setPermUsername(event.target.value)}
                      placeholder="username"
                    />
                  </label>
                  <label>
                    Role
                    <select value={permRole} onChange={(event) => setPermRole(event.target.value)}>
                      <option value="admin">Admin</option>
                      <option value="editor">Editor</option>
                      <option value="commenter">Commenter</option>
                      <option value="viewer">Viewer</option>
                      <option value="viewer-download-disabled">Viewer (no download)</option>
                    </select>
                  </label>
                  <label>
                    Expires at (optional)
                    <input
                      type="datetime-local"
                      value={permExpiresAt}
                      onChange={(event) => setPermExpiresAt(event.target.value)}
                    />
                  </label>
                  <label className="checkbox-label">
                    <input
                      type="checkbox"
                      checked={permCanDownload}
                      onChange={(event) => setPermCanDownload(event.target.checked)}
                    />
                    Allow download
                  </label>
                </div>
                <div className="modal-actions">
                  <button
                    type="button"
                    className="btn btn-muted"
                    disabled={busyAction === "permission-override"}
                    onClick={async () => {
                      try {
                        setBusyAction("permission-override");
                        setError("");
                        setNotice("");
                        await apiClient.setPermissionOverride({
                          scopeType: isFolder ? "folder" : "file",
                          scopeKey: normalizedKey,
                          username: permUsername.trim(),
                          role: permRole,
                          canDownload: permCanDownload,
                          expiresAt: permExpiresAt ? new Date(permExpiresAt).getTime() : null,
                        });
                        setNotice("Permission override saved.");
                        await onSaved?.();
                      } catch (err) {
                        setError(err.message);
                      } finally {
                        setBusyAction("");
                      }
                    }}
                  >
                    {busyAction === "permission-override" ? "Saving..." : "Apply override"}
                  </button>
                </div>
              </div>
            ) : null}
          </>
        ) : null}

        {activeSection === "links" ? (
          !isFolder ? (
            <div className="panel">
              <div className="panel-title">Share links</div>
              <div className="form-grid">
                <label>
                  Link permission
                  <select value={linkPermission} onChange={(event) => setLinkPermission(event.target.value)}>
                    <option value="download">View + download</option>
                    <option value="view">View only</option>
                    <option value="comment">Comment</option>
                  </select>
                </label>
                <label>
                  Expires at (optional)
                  <input
                    type="datetime-local"
                    value={expiresAt}
                    onChange={(event) => setExpiresAt(event.target.value)}
                  />
                </label>
                <label>
                  Max downloads
                  <input
                    type="number"
                    min="1"
                    value={maxDownloads}
                    onChange={(event) => setMaxDownloads(event.target.value)}
                    placeholder="Unlimited"
                  />
                </label>
                <label>
                  Password
                  <input
                    type="password"
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                    placeholder="Optional"
                  />
                </label>
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={disableDownload}
                    disabled={linkPermission !== "download"}
                    onChange={(event) => setDisableDownload(event.target.checked)}
                  />
                  Disable downloads
                </label>
              </div>

              <div className="modal-actions">
                <button
                  type="button"
                  className="btn"
                  disabled={busyAction === "share-link"}
                  onClick={async () => {
                    try {
                      setBusyAction("share-link");
                      setError("");
                      setNotice("");
                      const effectiveDisableDownload = disableDownload || linkPermission !== "download";
                      const payload = await apiClient.createShareLink({
                        key: normalizedKey,
                        permission: linkPermission,
                        expiresAt: expiresAt ? new Date(expiresAt).getTime() : null,
                        maxDownloads: maxDownloads ? Number(maxDownloads) : null,
                        disableDownload: effectiveDisableDownload,
                        password: password || null,
                      });
                      setLatestLink(payload.url || "");
                      setNotice("Share link created.");
                      const refreshed = await apiClient.listShareLinks(normalizedKey);
                      setLinks(refreshed.links || []);
                    } catch (err) {
                      setError(err.message);
                    } finally {
                      setBusyAction("");
                    }
                  }}
                >
                  {busyAction === "share-link" ? "Creating..." : "Create share link"}
                </button>
                {latestLink ? (
                  <button
                    type="button"
                    className="btn btn-muted"
                    onClick={() => navigator.clipboard.writeText(latestLink)}
                  >
                    Copy latest
                  </button>
                ) : null}
              </div>

              <div className="panel-title">Existing links</div>
              <div className="share-list">
                {links.map((link) => (
                  <div className="share-row" key={link.id}>
                    <div>
                      <div className="share-url">{link.url}</div>
                      <div className="muted">
                        Permission: {link.permission}
                        {link.disable_download ? " · download blocked" : ""}
                        {" · "}
                        {link.download_count}
                        {link.max_downloads ? ` / ${link.max_downloads}` : ""} downloads
                        {" · "}
                        {link.expires_at ? `expires ${new Date(Number(link.expires_at)).toLocaleString()}` : "no expiry"}
                      </div>
                    </div>
                    <button
                      type="button"
                      className="btn btn-sm btn-muted"
                      onClick={() => navigator.clipboard.writeText(link.url)}
                    >
                      Copy
                    </button>
                  </div>
                ))}
                {!links.length ? <div className="empty-mini">No links yet.</div> : null}
              </div>
            </div>
          ) : (
            <div className="notice">Share via link is available for files only.</div>
          )
        ) : null}

        {notice ? <div className="notice">{notice}</div> : null}
        {latestLink ? <div className="notice">Latest link: {latestLink}</div> : null}
        {error ? <div className="error-banner">{error}</div> : null}
      </div>
    </div>
  );
}
