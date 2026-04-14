import React, { useEffect, useMemo, useState } from "react";
import { Folder, Home, Star, FileText, ChevronRight } from "lucide-react";

function makeTree(items) {
  const byPath = new Map();
  const roots = [];

  for (const item of items) {
    byPath.set(item.path, { ...item, children: [] });
  }
  for (const item of byPath.values()) {
    if (item.parentPath && byPath.has(item.parentPath)) {
      byPath.get(item.parentPath).children.push(item);
    } else {
      roots.push(item);
    }
  }
  return roots.sort((a, b) => a.path.localeCompare(b.path));
}

function favoriteLabel(item) {
  if (item.item_type === "folder") return item.item_key;
  const name = item.item_key.split("/").pop() || item.item_key;
  return name;
}

function openFavoriteItem(item, { onNavigate, onOpenFile }) {
  if (item.item_type === "folder") {
    onNavigate(item.item_key);
    return;
  }
  if (onOpenFile) {
    onOpenFile(item.item_key);
    return;
  }
  const parent = item.item_key.includes("/") ? item.item_key.split("/").slice(0, -1).join("/") : "";
  onNavigate(parent);
}

function TreeNode({ node, currentPath, onNavigate, onContextMenu, level = 0 }) {
  const isActive = currentPath === node.path;
  return (
    <div>
      <button
        type="button"
        className={`tree-node ${isActive ? "active" : ""}`}
        style={{ paddingLeft: `${10 + level * 0}px` }}
        onClick={() => onNavigate(node.path)}
        onContextMenu={(event) => onContextMenu(event, node)}
      >
        <Folder size={15} className="tree-icon folder" />
        <span className="tree-label">{node.name}</span>
        {node.children.length > 0 && (
          <ChevronRight size={12} style={{ marginLeft: "auto", opacity: 0.4 }} />
        )}
      </button>
      {node.children.length > 0 && (
        <div className="tree-children">
          {node.children
            .sort((a, b) => a.name.localeCompare(b.name))
            .map((child) => (
              <TreeNode
                key={child.path}
                node={child}
                currentPath={currentPath}
                onNavigate={onNavigate}
                onContextMenu={onContextMenu}
                level={level + 1}
              />
            ))}
        </div>
      )}
    </div>
  );
}

export function FolderTree({
  tree,
  currentPath,
  onNavigate,
  favorites,
  onOpenFile,
  onShare,
  onToggleFavorite,
  onDeleteFolder,
}) {
  const nestedTree = useMemo(() => {
    const visible = (tree || []).filter((item) => !item.name.startsWith("."));
    return makeTree(visible);
  }, [tree]);
  const favoriteItems = (favorites || []).slice(0, 12);
  const favoriteFolderSet = useMemo(
    () =>
      new Set(
        (favorites || [])
          .filter((item) => item.item_type === "folder")
          .map((item) => item.item_key),
      ),
    [favorites],
  );

  const [contextMenu, setContextMenu] = useState(null);

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

  const openContextMenu = (event, actions) => {
    event.preventDefault();
    setContextMenu({
      actions,
      x: event.clientX,
      y: event.clientY,
    });
  };

  const buildFolderActions = (folderPath, { starred = favoriteFolderSet.has(folderPath) } = {}) => {
    const actions = [{ label: "Open", run: () => onNavigate(folderPath) }];
    if (onShare) {
      actions.push({ label: "Share", run: () => onShare(`.folder:${folderPath}`) });
    }
    if (onToggleFavorite) {
      actions.push({
        label: starred ? "Remove favorite" : "Add to favorites",
        run: () => onToggleFavorite("folder", folderPath, !starred),
      });
    }
    if (onDeleteFolder) {
      actions.push({
        label: "Delete folder",
        run: () => onDeleteFolder(folderPath),
        danger: true,
      });
    }
    return actions;
  };

  const buildFavoriteActions = (item) => {
    if (item.item_type === "folder") {
      return buildFolderActions(item.item_key, { starred: true });
    }
    const parentPath = item.item_key.includes("/") ? item.item_key.split("/").slice(0, -1).join("/") : "";
    const actions = [{ label: "Preview", run: () => onOpenFile?.(item.item_key) }];
    if (onShare) {
      actions.push({ label: "Share", run: () => onShare(item.item_key) });
    }
    actions.push({ label: "Open parent folder", run: () => onNavigate(parentPath) });
    if (onToggleFavorite) {
      actions.push({ label: "Remove favorite", run: () => onToggleFavorite("file", item.item_key, false) });
    }
    return actions;
  };

  return (
    <aside className="sidebar">
      {favoriteItems.length > 0 && (
        <div className="panel">
          <div className="panel-title">Favorites</div>
          {favoriteItems.map((item) => (
            <button
              key={`${item.item_type}:${item.item_key}`}
              type="button"
              className="mini-link"
              onClick={() => openFavoriteItem(item, { onNavigate, onOpenFile })}
              onContextMenu={(event) => openContextMenu(event, buildFavoriteActions(item))}
              title={item.item_key}
            >
              {item.item_type === "folder" ? (
                <Folder size={14} className="tree-icon folder" />
              ) : (
                <FileText size={14} className="tree-icon" />
              )}
              <span className="tree-label">{favoriteLabel(item)}</span>
            </button>
          ))}
        </div>
      )}

      <div className="panel grow">
        <div className="panel-title">Folders</div>
        <button
          type="button"
          className={`tree-node ${currentPath ? "" : "active"}`}
          onClick={() => onNavigate("")}
        >
          <Home size={15} className="tree-icon" />
          <span className="tree-label">Home</span>
        </button>
        {nestedTree.map((node) => (
          <TreeNode
            key={node.path}
            node={node}
            currentPath={currentPath}
            onNavigate={onNavigate}
            onContextMenu={(event, folderNode) => openContextMenu(event, buildFolderActions(folderNode.path))}
          />
        ))}
      </div>

      {contextMenu ? (
        <div
          className="context-menu"
          style={{ left: Math.max(8, contextMenu.x), top: Math.max(8, contextMenu.y) }}
        >
          {(contextMenu.actions || []).map((action) => (
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
    </aside>
  );
}
