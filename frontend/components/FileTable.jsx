import React, { useEffect, useMemo, useState } from "react";
import {
  FileText,
  Folder,
  Image,
  Film,
  Code,
  File,
  Eye,
  MoreHorizontal,
  CloudUpload,
} from "lucide-react";

function roleBadge(role) {
  if (role === "admin") return "Admin";
  if (role === "editor") return "Editor";
  if (role === "commenter") return "Commenter";
  if (role === "viewer-download-disabled") return "View (No DL)";
  return "Viewer";
}

function formatBytes(bytes) {
  if (!Number.isFinite(bytes)) return "0 B";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

function formatDate(timestamp) {
  if (!timestamp) return "\u2014";
  return new Date(timestamp).toLocaleString();
}

function relativeTime(timestamp) {
  if (!timestamp) return "\u2014";
  const now = Date.now();
  const diff = now - new Date(timestamp).getTime();
  if (diff < 0) return "just now";
  const minutes = Math.floor(diff / 60000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 7) return `${days}d ago`;
  if (days < 30) return `${Math.floor(days / 7)}w ago`;
  const months = Math.floor(days / 30);
  if (months < 12) return `${months}mo ago`;
  return `${Math.floor(months / 12)}y ago`;
}

function visibilityLabel(value) {
  if (value === "public") return "Public";
  if (value === "vault") return "Vault";
  if (value === "people") return "Shared";
  return "Only me";
}

function visibilityClass(value) {
  if (value === "public") return "public";
  if (value === "vault") return "vault";
  if (value === "people") return "people";
  return "only-me";
}

function FileTypeIcon({ file, size = 16 }) {
  const isHidden = file.displayName?.startsWith(".") || file.key?.startsWith(".");
  if (isHidden) return <Eye size={size} />;
  if (file.previewType === "code") return <Code size={size} />;
  if (file.previewType === "pdf") return <FileText size={size} />;
  if (file.previewType === "video") return <Film size={size} />;
  if (file.previewType === "image") return <Image size={size} />;
  return <File size={size} />;
}

function fileTypeClass(file) {
  const isHidden = file.displayName?.startsWith(".") || file.key?.startsWith(".");
  if (isHidden) return "hidden";
  if (file.previewType === "code") return "code";
  if (file.previewType === "pdf") return "pdf";
  if (file.previewType === "video") return "video";
  if (file.previewType === "image") return "image";
  return "default";
}

function ActionMenu({ children, ariaLabel }) {
  return (
    <details className="action-menu">
      <summary className="btn btn-sm btn-ghost menu-trigger row-actions-trigger" aria-label={ariaLabel || "Row actions"}>
        <MoreHorizontal size={16} />
      </summary>
      <div className="action-popover">{children}</div>
    </details>
  );
}

function buildFolderActions(folder, { onNavigate, onShare, onToggleFavorite, onDeleteFolder }) {
  const actions = [{ label: "Open", run: () => onNavigate(folder.path) }];
  if (onShare) {
    actions.push({ label: "Share", run: () => onShare(`.folder:${folder.path}`) });
  }
  if (onToggleFavorite) {
    actions.push({
      label: folder.starred ? "Remove favorite" : "Add to favorites",
      run: () => onToggleFavorite("folder", folder.path, !folder.starred),
    });
  }
  if (onDeleteFolder) {
    actions.push({
      label: "Delete folder",
      run: () => onDeleteFolder(folder.path),
      danger: true,
    });
  }
  return actions;
}

function buildFileActions(file, handlers, showTrash) {
  const canView = file.access?.canView !== false;
  const canDownload = file.access?.canDownload !== false;
  const canEdit = file.access?.canEdit === true;
  const canDelete = file.access?.canDelete === true;

  const actions = [];
  if (canView) {
    actions.push({ label: "Preview", run: () => handlers.onPreview(file.key) });
  }
  if (canDownload) {
    actions.push({ label: "Download", run: () => handlers.onDownload(file.key) });
  }
  if (canEdit && file.editable) {
    actions.push({ label: "Edit", run: () => handlers.onOpenEditor(file.key) });
  }
  if (canEdit) {
    actions.push({ label: "Share", run: () => handlers.onShare(file.key) });
  }
  if (canView) {
    actions.push({
      label: file.starred ? "Remove favorite" : "Add to favorites",
      run: () => handlers.onToggleFavorite("file", file.key, !file.starred),
    });
    actions.push({ label: "Duplicate", run: () => handlers.onDuplicate(file.key) });
  }
  if (canEdit) {
    actions.push({ label: "Rename", run: () => handlers.onRename(file) });
  }
  if (showTrash && file.trashed && canEdit) {
    actions.push({ label: "Restore", run: () => handlers.onRestore(file.key) });
  } else if (canDelete) {
    actions.push({ label: file.trashed ? "Delete" : "Trash", run: () => handlers.onDelete(file.key), danger: true });
  }
  return actions;
}

export function FileTable({
  folders,
  files,
  selectedKeys,
  viewMode,
  onNavigate,
  onToggleSelect,
  onOpenEditor,
  onPreview,
  onDownload,
  onDelete,
  onShare,
  onToggleFavorite,
  onDeleteFolder,
  onRename,
  onDuplicate,
  onRestore,
  showTrash,
  onUpload,
}) {
  const compact = viewMode === "compact";
  const allKeys = files.map((file) => file.key);
  const allSelected = allKeys.length > 0 && allKeys.every((key) => selectedKeys.includes(key));

  const [contextMenu, setContextMenu] = useState(null);
  const [dragActive, setDragActive] = useState(false);

  useEffect(() => {
    const close = () => setContextMenu(null);
    const onKey = (event) => {
      if (event.key === "Escape") close();
    };
    window.addEventListener("click", close);
    window.addEventListener("scroll", close, true);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("click", close);
      window.removeEventListener("scroll", close, true);
      window.removeEventListener("keydown", onKey);
    };
  }, []);

  const contextActions = useMemo(() => {
    if (!contextMenu) return [];
    if (contextMenu.type === "folder") {
      return buildFolderActions(contextMenu.item, { onNavigate, onShare, onToggleFavorite, onDeleteFolder });
    }
    return buildFileActions(
      contextMenu.item,
      { onPreview, onDownload, onOpenEditor, onShare, onToggleFavorite, onRename, onDuplicate, onRestore, onDelete },
      showTrash,
    );
  }, [contextMenu, onNavigate, onShare, onToggleFavorite, onDeleteFolder, onPreview, onDownload, onOpenEditor, onRename, onDuplicate, onRestore, onDelete, showTrash]);

  const openContextMenu = (event, type, item) => {
    event.preventDefault();
    setContextMenu({
      type,
      item,
      x: event.clientX,
      y: event.clientY,
    });
  };

  const handleDragOver = (event) => {
    event.preventDefault();
    event.stopPropagation();
    setDragActive(true);
  };

  const handleDragLeave = (event) => {
    event.preventDefault();
    event.stopPropagation();
    setDragActive(false);
  };

  const handleDrop = (event) => {
    event.preventDefault();
    event.stopPropagation();
    setDragActive(false);
    const droppedFiles = event.dataTransfer?.files;
    if (droppedFiles?.length && onUpload) {
      onUpload(Array.from(droppedFiles));
    }
  };

  const renderActions = (actions) =>
    actions.map((action) => (
      <button
        key={action.label}
        type="button"
        className={`menu-item ${action.danger ? "danger" : ""}`}
        onClick={() => action.run()}
      >
        {action.label}
      </button>
    ));

  const isEmpty = !folders.length && !files.length;

  // Drop zone for empty state
  if (isEmpty && viewMode !== "grid") {
    return (
      <div
        className={`drop-zone ${dragActive ? "active" : ""}`}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={() => onUpload?.(null)}
      >
        <CloudUpload size={40} className="drop-zone-icon" />
        <div className="drop-zone-text">Drop files here or click to upload</div>
        <div className="drop-zone-hint">No items in this folder</div>
      </div>
    );
  }

  if (viewMode === "grid") {
    return (
      <>
        <div
          className="grid"
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
        >
          {folders.map((folder) => {
            const actions = buildFolderActions(folder, { onNavigate, onShare, onToggleFavorite, onDeleteFolder });
            return (
              <div
                key={folder.path}
                className="grid-card folder"
                onContextMenu={(event) => openContextMenu(event, "folder", folder)}
              >
                <div className="grid-card-top">
                  <div className="muted grid-kind">Folder</div>
                  <ActionMenu ariaLabel={`Folder actions for ${folder.name}`}>{renderActions(actions)}</ActionMenu>
                </div>
                <button type="button" className="grid-open" onClick={() => onNavigate(folder.path)}>
                  <span className="grid-icon"><Folder size={22} style={{ color: "#F59E0B" }} /></span>
                  <span className="grid-title">{folder.name}</span>
                  <span className="grid-sub">{visibilityLabel(folder.visibility)}</span>
                </button>
              </div>
            );
          })}

          {files.map((file) => {
            const actions = buildFileActions(
              file,
              { onPreview, onDownload, onOpenEditor, onShare, onToggleFavorite, onRename, onDuplicate, onRestore, onDelete },
              showTrash,
            );
            return (
              <div
                key={file.key}
                className="grid-card"
                onContextMenu={(event) => openContextMenu(event, "file", file)}
              >
                <div className="grid-card-top">
                  <div className="muted grid-kind">File</div>
                  <ActionMenu ariaLabel={`File actions for ${file.displayName}`}>{renderActions(actions)}</ActionMenu>
                </div>
                <div className="grid-icon">
                  <div className={`file-type-icon ${fileTypeClass(file)}`}>
                    <FileTypeIcon file={file} size={20} />
                  </div>
                </div>
                <div className="grid-title" title={file.displayName}>
                  {file.displayName}
                </div>
                <div className="grid-sub">
                  {formatBytes(file.size)} &middot; {relativeTime(file.updatedAt)}
                </div>
                <div className="grid-actions">
                  <button type="button" className="btn btn-sm btn-muted" onClick={() => onPreview(file.key)}>
                    Preview
                  </button>
                  {file.access?.canDownload !== false ? (
                    <button type="button" className="btn btn-sm btn-muted" onClick={() => onDownload(file.key)}>
                      Download
                    </button>
                  ) : null}
                  {file.editable && file.access?.canEdit ? (
                    <button type="button" className="btn btn-sm" onClick={() => onOpenEditor(file.key)}>
                      Edit
                    </button>
                  ) : null}
                </div>
              </div>
            );
          })}

          {isEmpty ? (
            <div
              className={`drop-zone ${dragActive ? "active" : ""}`}
              style={{ gridColumn: "1 / -1" }}
              onClick={() => onUpload?.(null)}
            >
              <CloudUpload size={40} className="drop-zone-icon" />
              <div className="drop-zone-text">Drop files here or click to upload</div>
            </div>
          ) : null}
        </div>

        {contextMenu ? (
          <div
            className="context-menu"
            style={{ left: Math.max(8, contextMenu.x), top: Math.max(8, contextMenu.y) }}
          >
            {contextActions.map((action) => (
              <button
                key={action.label}
                type="button"
                className={`menu-item ${action.danger ? "danger" : ""}`}
                onClick={() => {
                  setContextMenu(null);
                  action.run();
                }}
              >
                {action.label}
              </button>
            ))}
          </div>
        ) : null}
      </>
    );
  }

  return (
    <>
      <div
        className="table-wrap"
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
      >
        {dragActive && (
          <div className="drop-zone active" style={{ position: "absolute", inset: 0, zIndex: 10, minHeight: 0, borderRadius: "12px" }}>
            <CloudUpload size={40} className="drop-zone-icon" />
            <div className="drop-zone-text">Drop files to upload</div>
          </div>
        )}
        <table className={`file-table ${compact ? "compact" : ""}`}>
          <thead>
            <tr>
              <th>
                <input
                  type="checkbox"
                  className="row-checkbox"
                  checked={allSelected}
                  onChange={(event) => {
                    const checked = event.target.checked;
                    for (const key of allKeys) {
                      onToggleSelect(key, checked);
                    }
                  }}
                />
              </th>
              <th>Name</th>
              {!compact ? <th>Access</th> : null}
              {!compact ? <th>Size</th> : null}
              <th>Modified</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {folders.map((folder) => {
              const actions = buildFolderActions(folder, { onNavigate, onShare, onToggleFavorite, onDeleteFolder });
              return (
                <tr key={folder.path} onContextMenu={(event) => openContextMenu(event, "folder", folder)}>
                  <td />
                  <td>
                    <div className="file-name-cell">
                      <div className="file-type-icon folder">
                        <Folder size={16} />
                      </div>
                      <div className="file-name-info">
                        <button type="button" className="link-btn file-name-primary" onClick={() => onNavigate(folder.path)}>
                          {folder.name}
                        </button>
                        <div className="file-name-sub">{folder.owner || "\u2014"}</div>
                      </div>
                    </div>
                  </td>
                  {!compact ? (
                    <td>
                      <span className={`access-badge ${visibilityClass(folder.visibility)}`}>
                        {visibilityLabel(folder.visibility)}
                      </span>
                    </td>
                  ) : null}
                  {!compact ? <td className="cell-mono">&mdash;</td> : null}
                  <td className="cell-mono" title={formatDate(folder.updatedAt)}>
                    {relativeTime(folder.updatedAt)}
                  </td>
                  <td>
                    <ActionMenu ariaLabel={`Folder actions for ${folder.name}`}>{renderActions(actions)}</ActionMenu>
                  </td>
                </tr>
              );
            })}

            {files.map((file) => {
              const actions = buildFileActions(
                file,
                { onPreview, onDownload, onOpenEditor, onShare, onToggleFavorite, onRename, onDuplicate, onRestore, onDelete },
                showTrash,
              );
              const isSelected = selectedKeys.includes(file.key);
              return (
                <tr key={file.key} onContextMenu={(event) => openContextMenu(event, "file", file)}>
                  <td>
                    <input
                      type="checkbox"
                      className={`row-checkbox ${isSelected ? "visible" : ""}`}
                      checked={isSelected}
                      onChange={(event) => onToggleSelect(file.key, event.target.checked)}
                    />
                  </td>
                  <td>
                    <div className="file-name-cell">
                      <div className={`file-type-icon ${fileTypeClass(file)}`}>
                        <FileTypeIcon file={file} />
                      </div>
                      <div className="file-name-info">
                        <button type="button" className="link-btn file-name-primary" onClick={() => onPreview(file.key)}>
                          {file.displayName}
                        </button>
                        <div className="file-name-sub">{file.owner || "\u2014"}</div>
                        {!compact && file.tags?.length ? (
                          <div className="tag-row">{file.tags.map((tag) => <span key={tag}>#{tag}</span>)}</div>
                        ) : null}
                        {compact ? (
                          <div className="muted compact-meta">
                            {formatBytes(file.size)} &middot; {visibilityLabel(file.visibility)}
                          </div>
                        ) : null}
                      </div>
                    </div>
                  </td>
                  {!compact ? (
                    <td>
                      <span className={`access-badge ${visibilityClass(file.visibility)}`}>
                        {visibilityLabel(file.visibility)}
                      </span>
                    </td>
                  ) : null}
                  {!compact ? <td className="cell-mono">{formatBytes(file.size)}</td> : null}
                  <td className="cell-mono" title={formatDate(file.updatedAt)}>
                    {relativeTime(file.updatedAt)}
                  </td>
                  <td>
                    <ActionMenu ariaLabel={`File actions for ${file.displayName}`}>{renderActions(actions)}</ActionMenu>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {contextMenu ? (
        <div
          className="context-menu"
          style={{ left: Math.max(8, contextMenu.x), top: Math.max(8, contextMenu.y) }}
        >
          {contextActions.map((action) => (
            <button
              key={action.label}
              type="button"
              className={`menu-item ${action.danger ? "danger" : ""}`}
              onClick={() => {
                setContextMenu(null);
                action.run();
              }}
            >
              {action.label}
            </button>
          ))}
        </div>
      ) : null}
    </>
  );
}
