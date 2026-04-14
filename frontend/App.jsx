import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ApiError, apiClient } from "./api/client.js";
import { EditorWorkspace } from "./components/EditorWorkspace.jsx";
import { FileTable } from "./components/FileTable.jsx";
import { FolderTree } from "./components/FolderTree.jsx";
import { HeaderBar } from "./components/HeaderBar.jsx";
import { PreviewPanel } from "./components/PreviewPanel.jsx";
import { ShareModal } from "./components/ShareModal.jsx";
import { useDebouncedEffect } from "./hooks/useDebouncedEffect.js";
import { useVaultStore } from "./store.js";
import {
  Upload,
  FilePlus,
  FolderPlus,
  Trash2,
  RefreshCw,
  LayoutList,
  LayoutGrid,
  Rows3,
} from "lucide-react";

function parseCurrentPathFromUrl() {
  const params = new URLSearchParams(window.location.search);
  return params.get("path") || "";
}

function readEditorWindowQuery() {
  const params = new URLSearchParams(window.location.search);
  return {
    enabled: params.get("editor") === "1",
    key: params.get("key") || "",
  };
}

function parentPathFromFileKey(key) {
  return key.includes("/") ? key.split("/").slice(0, -1).join("/") : "";
}

function editorFileIcon(file) {
  if (file.previewType === "code") return "🧠";
  if (file.previewType === "pdf") return "📕";
  if (file.previewType === "video") return "🎬";
  if (file.previewType === "image") return "🖼️";
  return "📄";
}

function readBootUser() {
  try {
    const root = document.getElementById("vault-root");
    const raw = root?.dataset?.user;
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    return {
      ...parsed,
      isAdmin: parsed?.role === "admin" || parsed?.role === "owner",
    };
  } catch {
    return null;
  }
}

function setPathInUrl(path) {
  const params = new URLSearchParams(window.location.search);
  if (path) params.set("path", path);
  else params.delete("path");
  const next = `${window.location.pathname}?${params.toString()}`;
  window.history.replaceState(null, "", next);
}

function readContentTabFromUrl() {
  const pathname = window.location.pathname.replace(/\/+$/, "");
  return pathname === "/vault/admin" ? "audit" : "files";
}

function setContentTabInUrl(tab) {
  const url = new URL(window.location.href);
  url.pathname = tab === "audit" ? "/vault/admin" : "/vault";
  window.history.replaceState(null, "", `${url.pathname}${url.search}`);
}

function toggleFromArray(array, key, enabled) {
  const set = new Set(array);
  if (enabled) set.add(key);
  else set.delete(key);
  return [...set];
}

function noop() {}

export function App() {
  const editorWindowQuery = useMemo(() => readEditorWindowQuery(), []);
  const isEditorWindow = editorWindowQuery.enabled;
  const initialEditorKey = editorWindowQuery.key;

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [bootData, setBootData] = useState({
    user: readBootUser() || { username: "unknown", role: "viewer", isAdmin: false },
    currentPath: parseCurrentPathFromUrl(),
    folders: [],
    files: [],
    tree: [],
    recent: [],
    favorites: [],
    quota: null,
    features: {},
  });
  const [showTrash, setShowTrash] = useState(false);
  const [previewKey, setPreviewKey] = useState("");
  const [shareTargetKey, setShareTargetKey] = useState("");
  const [versionHistoryByKey, setVersionHistoryByKey] = useState({});
  const [activity, setActivity] = useState([]);
  const [activeContentTab, setActiveContentTab] = useState(() => readContentTabFromUrl());
  const [editorSidebarFiles, setEditorSidebarFiles] = useState([]);
  const [editorSidebarLoading, setEditorSidebarLoading] = useState(false);
  const [editorSidebarFilter, setEditorSidebarFilter] = useState("");
  const [editorSidebarRevision, setEditorSidebarRevision] = useState(0);
  const fileInputRef = useRef(null);
  const saveTabRef = useRef(null);
  const initialEditorOpenedRef = useRef("");

  const {
    theme,
    setTheme,
    viewMode,
    setViewMode,
    sortBy,
    sortDir,
    setSort,
    search,
    setSearch,
    selectedKeys,
    setSelectedKeys,
    clearSelection,
    editorTabs,
    setEditorTabs,
    activeTabKey,
    setActiveTabKey,
    offlineQueue,
    enqueueOfflineSave,
    dequeueOfflineSave,
  } = useVaultStore();

  const editableFiles = useMemo(
    () =>
      (bootData.files || [])
        .filter((file) => file.editable && file.access?.canEdit)
        .map((file) => ({ key: file.key })),
    [bootData.files],
  );
  const allEditorQuickOpenOptions = useMemo(
    () =>
      editorSidebarFiles
        .filter((file) => file.editable && file.access?.canEdit)
        .map((file) => ({ key: file.key })),
    [editorSidebarFiles],
  );
  const filteredEditorSidebarFiles = useMemo(() => {
    const query = editorSidebarFilter.trim().toLowerCase();
    if (!query) return editorSidebarFiles;
    return editorSidebarFiles.filter((file) => file.key.toLowerCase().includes(query));
  }, [editorSidebarFiles, editorSidebarFilter]);
  const treePathSignature = useMemo(
    () => (bootData.tree || []).map((folder) => folder.path).sort().join("|"),
    [bootData.tree],
  );

  const currentTab = useMemo(
    () => editorTabs.find((tab) => tab.key === activeTabKey) || null,
    [editorTabs, activeTabKey],
  );
  const shareTargetInfo = useMemo(() => {
    if (!shareTargetKey) {
      return { visibility: "only-me", allowedUsers: "" };
    }

    if (shareTargetKey.startsWith(".folder:")) {
      const folderPath = shareTargetKey.replace(".folder:", "");
      const folder = [...(bootData.folders || []), ...(bootData.tree || [])].find((item) => item.path === folderPath);
      return {
        visibility: folder?.visibility || "only-me",
        allowedUsers: folder?.allowedUsers || "",
      };
    }

    const file = (bootData.files || []).find((item) => item.key === shareTargetKey);
    const allowedUsers = Array.isArray(file?.allowedUsers)
      ? file.allowedUsers.join(", ")
      : file?.allowedUsers || "";
    return {
      visibility: file?.visibility || "only-me",
      allowedUsers,
    };
  }, [shareTargetKey, bootData.files, bootData.folders, bootData.tree]);

  const handleChangeContentTab = useCallback((tab) => {
    const next = tab === "audit" ? "audit" : "files";
    setActiveContentTab(next);
    setContentTabInUrl(next);
  }, []);

  const fetchBootstrap = useCallback(
    async (path = bootData.currentPath) => {
      setLoading(true);
      setError("");
      try {
        const payload = await apiClient.bootstrap({
          path,
          search,
          sortBy,
          sortDir,
          trash: showTrash ? "1" : "",
        });
        setBootData((current) => ({
          ...current,
          ...payload,
          currentPath: path,
        }));
        clearSelection();
        setPathInUrl(path);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    },
    [bootData.currentPath, search, sortBy, sortDir, showTrash, clearSelection],
  );

  useEffect(() => {
    fetchBootstrap(parseCurrentPathFromUrl());
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useDebouncedEffect(
    () => {
      if (loading) return;
      fetchBootstrap(bootData.currentPath);
    },
    [search, sortBy, sortDir, showTrash],
    250,
  );

  useEffect(() => {
    const timer = setInterval(() => {
      fetchBootstrap(bootData.currentPath);
    }, 15000);
    return () => clearInterval(timer);
  }, [bootData.currentPath, fetchBootstrap]);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);

  useEffect(() => {
    const onKeyDown = (event) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "s") {
        event.preventDefault();
        if (activeTabKey) saveTabRef.current?.(activeTabKey, { manual: true });
      }
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "p") {
        event.preventDefault();
        const input = document.querySelector(".quick-open input");
        input?.focus();
      }
      if (event.key === "Delete" && selectedKeys.length > 0 && document.activeElement?.tagName !== "INPUT") {
        event.preventDefault();
        handleBatchDelete();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeTabKey, selectedKeys]);

  useEffect(() => {
    if (!bootData.user?.isAdmin) return noop;
    apiClient
      .getActivity({ limit: 50 })
      .then((payload) => setActivity(payload.events || []))
      .catch(() => {});
    return noop;
  }, [bootData.user?.isAdmin]);

  useEffect(() => {
    if (!bootData.user?.isAdmin || activeContentTab !== "audit") return noop;
    const timer = setInterval(() => {
      apiClient
        .getActivity({ limit: 50 })
        .then((payload) => setActivity(payload.events || []))
        .catch(() => {});
    }, 15000);
    return () => clearInterval(timer);
  }, [bootData.user?.isAdmin, activeContentTab]);

  useEffect(() => {
    if (bootData.user?.isAdmin) return;
    if (activeContentTab !== "audit") return;
    handleChangeContentTab("files");
  }, [bootData.user?.isAdmin, activeContentTab, handleChangeContentTab]);

  const openEditor = useCallback(
    async (key) => {
      const existing = editorTabs.find((tab) => tab.key === key);
      if (existing) {
        setActiveTabKey(key);
        return;
      }

      try {
        const contentPayload = await apiClient.getFileContent(key);
        if (!contentPayload.canEdit) {
          setError("Edit permission denied for this file.");
          return;
        }
        const historyPayload = await apiClient.fileHistory(key);
        const tab = {
          key,
          content: contentPayload.content,
          originalContent: contentPayload.content,
          etag: contentPayload.etag,
          language: contentPayload.language,
          canEdit: contentPayload.canEdit,
          dirty: false,
          saving: false,
          showDiff: false,
          activeEditors: contentPayload.activeEditors || [],
          breadcrumbs: contentPayload.breadcrumbs || [],
        };
        setEditorTabs((tabs) => [...tabs, tab]);
        setActiveTabKey(key);
        setVersionHistoryByKey((current) => ({ ...current, [key]: historyPayload.versions || [] }));
        await apiClient.heartbeatPresence(key, true);
      } catch (err) {
        setError(err.message);
      }
    },
    [editorTabs, setActiveTabKey, setEditorTabs],
  );

  const openEditorInPreferredMode = useCallback(
    async (key) => {
      const parentPath = parentPathFromFileKey(key);
      if (isEditorWindow) {
        await openEditor(key);
        if (parentPath !== bootData.currentPath) {
          fetchBootstrap(parentPath);
        }
        return;
      }

      try {
        const metadata = await apiClient.getFileContent(key, { metadataOnly: true });
        if (!metadata.canEdit) {
          setError("Edit permission denied for this file.");
          return;
        }
      } catch (err) {
        setError(err.message);
        return;
      }

      const params = new URLSearchParams();
      params.set("editor", "1");
      params.set("key", key);
      if (parentPath) params.set("path", parentPath);
      const url = `${window.location.origin}/vault?${params.toString()}`;
      const tab = window.open(url, "_blank");
      if (tab) {
        tab.opener = null;
      } else {
        await openEditor(key);
      }
    },
    [isEditorWindow, openEditor, fetchBootstrap, bootData.currentPath],
  );

  useEffect(() => {
    if (!isEditorWindow || !initialEditorKey || loading) return;
    if (initialEditorOpenedRef.current === initialEditorKey) return;
    initialEditorOpenedRef.current = initialEditorKey;
    openEditorInPreferredMode(initialEditorKey);
  }, [isEditorWindow, initialEditorKey, loading, openEditorInPreferredMode]);

  useEffect(() => {
    if (!isEditorWindow) return noop;
    const treePaths = treePathSignature ? treePathSignature.split("|").filter(Boolean) : [];
    const folderPaths = ["", ...treePaths];
    const uniquePaths = [...new Set(folderPaths)];
    let cancelled = false;
    setEditorSidebarLoading(true);

    Promise.all(
      uniquePaths.map(async (path) => {
        try {
          return await apiClient.listFiles({
            path,
            sortBy: "name",
            sortDir: "asc",
            trash: "0",
          });
        } catch {
          return { files: [] };
        }
      }),
    )
      .then((payloads) => {
        if (cancelled) return;
        const map = new Map();
        for (const payload of payloads) {
          for (const file of payload?.files || []) {
            if (file.trashed) continue;
            if (!file.editable || !file.access?.canEdit) continue;
            if (!map.has(file.key)) map.set(file.key, file);
          }
        }
        setEditorSidebarFiles(
          [...map.values()].sort((a, b) => a.key.localeCompare(b.key)),
        );
      })
      .finally(() => {
        if (!cancelled) setEditorSidebarLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [isEditorWindow, treePathSignature, editorSidebarRevision]);

  const updateTab = useCallback(
    (key, mapper) => {
      setEditorTabs((tabs) => tabs.map((tab) => (tab.key === key ? mapper(tab) : tab)));
    },
    [setEditorTabs],
  );

  const closeTab = useCallback(
    async (key) => {
      setEditorTabs((tabs) => {
        const remaining = tabs.filter((tab) => tab.key !== key);
        if (activeTabKey === key) {
          setActiveTabKey(remaining.length ? remaining[remaining.length - 1].key : null);
        }
        return remaining;
      });
      try {
        await apiClient.heartbeatPresence(key, false);
      } catch {}
    },
    [activeTabKey, setEditorTabs, setActiveTabKey],
  );

  const saveTab = useCallback(
    async (key, options = {}) => {
      const tab = editorTabs.find((item) => item.key === key);
      if (!tab || !tab.canEdit || !tab.dirty) return;

      updateTab(key, (current) => ({ ...current, saving: true }));
      try {
        const result = await apiClient.saveFile({
          key,
          content: tab.content,
          baseEtag: tab.etag,
          message: options.manual ? "Manual save" : "Autosave",
        });
        updateTab(key, (current) => ({
          ...current,
          etag: result.etag,
          originalContent: current.content,
          dirty: false,
          saving: false,
        }));
        const history = await apiClient.fileHistory(key);
        setVersionHistoryByKey((current) => ({ ...current, [key]: history.versions || [] }));
      } catch (err) {
        updateTab(key, (current) => ({ ...current, saving: false }));
        if (err instanceof ApiError && err.status >= 500) {
          enqueueOfflineSave({
            id: crypto.randomUUID(),
            key,
            content: tab.content,
            baseEtag: tab.etag,
            createdAt: Date.now(),
          });
        } else {
          setError(err.message);
        }
      }
    },
    [editorTabs, updateTab, enqueueOfflineSave],
  );

  useEffect(() => {
    saveTabRef.current = saveTab;
  }, [saveTab]);

  useDebouncedEffect(
    () => {
      if (!currentTab || !currentTab.canEdit || !currentTab.dirty) return;
      saveTab(currentTab.key, { manual: false });
    },
    [currentTab?.key, currentTab?.content, currentTab?.dirty, currentTab?.canEdit],
    1200,
  );

  useEffect(() => {
    if (!activeTabKey) return noop;
    const timer = setInterval(async () => {
      try {
        await apiClient.heartbeatPresence(activeTabKey, true);
        const [presence, metadata] = await Promise.all([
          apiClient.getPresence(activeTabKey),
          apiClient.getFileContent(activeTabKey, { metadataOnly: true }),
        ]);
        updateTab(activeTabKey, (current) => {
          const safeCurrent = current || {};
          const shouldUpdateFromRemote = !safeCurrent.dirty && metadata.etag && metadata.etag !== safeCurrent.etag;
          return {
            ...safeCurrent,
            activeEditors: presence.editors || [],
            ...(shouldUpdateFromRemote
              ? {
                etag: metadata.etag,
              }
              : {}),
          };
        });
      } catch {}
    }, 15000);
    return () => clearInterval(timer);
  }, [activeTabKey, updateTab]);

  useEffect(() => {
    if (!offlineQueue.length) return noop;
    const flush = async () => {
      for (const item of offlineQueue) {
        try {
          await apiClient.saveFile(item);
          dequeueOfflineSave(item.id);
          updateTab(item.key, (current) => (current ? { ...current, dirty: false } : current));
        } catch {}
      }
    };
    const onOnline = () => flush();
    window.addEventListener("online", onOnline);
    const interval = setInterval(flush, 12000);
    flush();
    return () => {
      window.removeEventListener("online", onOnline);
      clearInterval(interval);
    };
  }, [offlineQueue, dequeueOfflineSave, updateTab]);

  const handleBatchDelete = useCallback(async () => {
    if (!selectedKeys.length) return;
    const confirmed = window.confirm(`Trash ${selectedKeys.length} selected file(s)?`);
    if (!confirmed) return;
    try {
      await apiClient.batch({ action: "delete", keys: selectedKeys, hardDelete: showTrash });
      clearSelection();
      fetchBootstrap(bootData.currentPath);
    } catch (err) {
      setError(err.message);
    }
  }, [selectedKeys, showTrash, clearSelection, fetchBootstrap, bootData.currentPath]);

  const handleBatchMove = useCallback(async () => {
    if (!selectedKeys.length) return;
    const destination = window.prompt("Move selected files to folder path:", bootData.currentPath || "");
    if (destination === null) return;
    try {
      await apiClient.batch({ action: "move", keys: selectedKeys, destination });
      clearSelection();
      fetchBootstrap(bootData.currentPath);
    } catch (err) {
      setError(err.message);
    }
  }, [selectedKeys, clearSelection, fetchBootstrap, bootData.currentPath]);

  const handleUpload = useCallback(
    async (files) => {
      if (!files?.length) return;
      for (const file of files) {
        try {
          await apiClient.upload(file, { folderPath: bootData.currentPath });
        } catch (err) {
          setError(err.message);
        }
      }
      fetchBootstrap(bootData.currentPath);
    },
    [bootData.currentPath, fetchBootstrap],
  );

  const handleChangeTabContent = useCallback(
    (key, nextContent, options = {}) => {
      updateTab(key, (tab) => ({
        ...tab,
        content: nextContent,
        dirty: tab.originalContent !== nextContent,
        showDiff: options.toggleDiff ? !tab.showDiff : tab.showDiff,
      }));
    },
    [updateTab],
  );

  const handleCreateFolder = useCallback(async () => {
    const name = window.prompt("New folder name:");
    if (!name) return;
    try {
      await apiClient.createFolder({ name, parentPath: bootData.currentPath });
      fetchBootstrap(bootData.currentPath);
    } catch (err) {
      setError(err.message);
    }
  }, [bootData.currentPath, fetchBootstrap]);

  const handleDeleteFolder = useCallback(
    async (folderPath) => {
      if (!folderPath) return;
      const folderName = folderPath.split("/").pop() || folderPath;
      const confirmed = window.confirm(`Delete folder "${folderName}" and all nested files? This cannot be undone.`);
      if (!confirmed) return;

      try {
        await apiClient.deleteFolder(folderPath);
        const parentPath = folderPath.includes("/") ? folderPath.split("/").slice(0, -1).join("/") : "";
        const nextPath =
          bootData.currentPath === folderPath || bootData.currentPath.startsWith(`${folderPath}/`)
            ? parentPath
            : bootData.currentPath;
        await fetchBootstrap(nextPath);
      } catch (err) {
        setError(err.message);
      }
    },
    [bootData.currentPath, fetchBootstrap],
  );

  const handleCreateTextFile = useCallback(async () => {
    const name = window.prompt("New text file name (example: notes.txt):", "untitled.txt");
    if (!name) return;
    const initialContent = window.prompt("Initial content (optional):", "") || "";
    try {
      const payload = await apiClient.createTextFile({
        name,
        parentPath: bootData.currentPath,
        content: initialContent,
      });
      await fetchBootstrap(bootData.currentPath);
      if (payload?.key) {
        await openEditorInPreferredMode(payload.key);
      }
    } catch (err) {
      setError(err.message);
    }
  }, [bootData.currentPath, fetchBootstrap, openEditorInPreferredMode]);

  const handleRename = useCallback(
    async (file) => {
      const nextName = window.prompt("Rename file:", file.displayName || file.key.split("/").pop());
      if (!nextName) return;
      try {
        await apiClient.renameFile(file.key, nextName);
        fetchBootstrap(bootData.currentPath);
      } catch (err) {
        setError(err.message);
      }
    },
    [bootData.currentPath, fetchBootstrap],
  );

  const handleDownload = useCallback((key) => {
    window.open(`/vault/file/${encodeURIComponent(key)}?download=1`, "_blank", "noopener,noreferrer");
  }, []);

  const handleShare = useCallback((key) => {
    setShareTargetKey(key);
  }, []);
  const refreshAfterShareChange = useCallback(async () => {
    await fetchBootstrap(bootData.currentPath);
  }, [fetchBootstrap, bootData.currentPath]);

  const handleToggleFavorite = useCallback(
    async (itemType, itemKey, starred) => {
      try {
        await apiClient.toggleFavorite(itemType, itemKey, starred);
        await fetchBootstrap(bootData.currentPath);
      } catch (err) {
        setError(err.message);
      }
    },
    [fetchBootstrap, bootData.currentPath],
  );

  const handleRestoreVersion = useCallback(
    async (versionId) => {
      try {
        await apiClient.restoreVersion(versionId);
        if (activeTabKey) {
          const refreshed = await apiClient.getFileContent(activeTabKey);
          updateTab(activeTabKey, (tab) => ({
            ...tab,
            content: refreshed.content,
            originalContent: refreshed.content,
            dirty: false,
            etag: refreshed.etag,
          }));
        }
        fetchBootstrap(bootData.currentPath);
      } catch (err) {
        setError(err.message);
      }
    },
    [activeTabKey, updateTab, fetchBootstrap, bootData.currentPath],
  );

  const toggleSelection = (key, enabled) => setSelectedKeys(toggleFromArray(selectedKeys, key, enabled));

  if (isEditorWindow) {
    return (
      <div className="app-root editor-window-root">
        {error ? <div className="error-banner">{error}</div> : null}
        <div className="editor-window-shell">
          <aside className="editor-window-sidebar">
            <div className="panel-title-row">
              <div className="panel-title">All files</div>
              <div className="editor-window-actions">
                <button
                  type="button"
                  className="btn btn-sm btn-muted"
                  onClick={() => setEditorSidebarRevision((value) => value + 1)}
                >
                  Refresh
                </button>
                <a
                  href={`/vault${bootData.currentPath ? `?path=${encodeURIComponent(bootData.currentPath)}` : ""}`}
                  className="btn btn-sm btn-muted"
                >
                  Vault
                </a>
              </div>
            </div>
            <input
              className="editor-window-filter"
              placeholder="Filter files..."
              value={editorSidebarFilter}
              onChange={(event) => setEditorSidebarFilter(event.target.value)}
            />
            <div className="editor-window-file-list">
              {editorSidebarLoading ? <div className="empty-mini">Loading files...</div> : null}
              {!editorSidebarLoading &&
              filteredEditorSidebarFiles.map((file) => (
                <button
                  key={file.key}
                  type="button"
                  className={`editor-window-file ${activeTabKey === file.key ? "active" : ""}`}
                  onClick={() => openEditorInPreferredMode(file.key)}
                  title={file.key}
                >
                  <span>{editorFileIcon(file)}</span>
                  <span>{file.key}</span>
                </button>
              ))}
              {!editorSidebarLoading && !filteredEditorSidebarFiles.length ? (
                <div className="empty-mini">No files found.</div>
              ) : null}
            </div>
          </aside>

          <main className="editor-window-main">
            {editorTabs.length ? (
              <EditorWorkspace
                tabs={editorTabs}
                activeTabKey={activeTabKey}
                onActivateTab={setActiveTabKey}
                onCloseTab={closeTab}
                onChangeTabContent={handleChangeTabContent}
                onSaveTab={saveTab}
                onQuickOpen={openEditorInPreferredMode}
                quickOpenOptions={allEditorQuickOpenOptions}
                versionHistoryByKey={versionHistoryByKey}
                onRestoreVersion={handleRestoreVersion}
                currentUsername={bootData.user.username}
                theme={theme}
                editorHeight="calc(100vh - 230px)"
              />
            ) : (
              <section className="editor-shell empty">
                <div className="empty-editor">Select a file from the sidebar to open the editor.</div>
              </section>
            )}
          </main>
        </div>
      </div>
    );
  }

  return (
    <div className="app-root">
      <HeaderBar
        user={bootData.user}
        currentPath={bootData.currentPath}
        onNavigate={(path) => fetchBootstrap(path)}
        theme={theme}
        onToggleTheme={() => setTheme(theme === "dark" ? "light" : "dark")}
        search={search}
        onSearchChange={(value) => setSearch(value)}
        quota={bootData.quota}
        activeContentTab={activeContentTab}
        onChangeContentTab={handleChangeContentTab}
      />

      {error ? <div className="error-banner">{error}</div> : null}

      <div className="workspace">
        <FolderTree
          tree={bootData.tree}
          currentPath={bootData.currentPath}
          onNavigate={(path) => fetchBootstrap(path)}
          favorites={bootData.favorites}
          onOpenFile={(key) => setPreviewKey(key)}
          onShare={handleShare}
          onToggleFavorite={handleToggleFavorite}
          onDeleteFolder={handleDeleteFolder}
        />

        <main className="content">
          {activeContentTab === "audit" && bootData.user?.isAdmin ? (
            <section className="audit-tab">
              <div className="panel-title-row">
                <div className="panel-title">Audit log</div>
                <button
                  type="button"
                  className="btn btn-sm btn-muted"
                  onClick={() =>
                    apiClient
                      .getActivity({ limit: 50 })
                      .then((payload) => setActivity(payload.events || []))
                      .catch(() => {})
                  }
                >
                  Refresh
                </button>
              </div>
              <div className="audit-list">
                {activity.map((event) => (
                  <div key={event.id} className="audit-row">
                    <span>{new Date(event.created_at).toLocaleString()}</span>
                    <strong>{event.actor}</strong>
                    <span>{event.action}</span>
                    <span className="muted">{event.file_key || "-"}</span>
                  </div>
                ))}
                {!activity.length ? <div className="empty-mini">No audit events yet.</div> : null}
              </div>
            </section>
          ) : (
            <>
              <div className="toolbar">
                <div className="toolbar-left">
                  <button type="button" className="btn" onClick={() => fileInputRef.current?.click()}>
                    <Upload size={15} />
                    Upload
                  </button>
                  <button type="button" className="btn btn-ghost" onClick={handleCreateTextFile}>
                    <FilePlus size={15} />
                    New text file
                  </button>
                  <button type="button" className="btn btn-ghost" onClick={handleCreateFolder}>
                    <FolderPlus size={15} />
                    New folder
                  </button>
                  <button type="button" className="btn btn-ghost" onClick={() => setShowTrash(!showTrash)}>
                    <Trash2 size={15} />
                    {showTrash ? "Hide trash" : "Show trash"}
                  </button>
                  <button type="button" className="btn btn-ghost" onClick={() => fetchBootstrap(bootData.currentPath)}>
                    <RefreshCw size={15} />
                    Refresh
                  </button>
                </div>
                <div className="toolbar-right">
                  {selectedKeys.length ? (
                    <>
                      <button type="button" className="btn btn-muted" onClick={handleBatchMove}>
                        Move selected
                      </button>
                      <button type="button" className="btn btn-danger" onClick={handleBatchDelete}>
                        Delete selected ({selectedKeys.length})
                      </button>
                    </>
                  ) : null}
                  <select
                    className="toolbar-select"
                    value={`${sortBy}:${sortDir}`}
                    onChange={(event) => {
                      const [nextSortBy, nextSortDir] = event.target.value.split(":");
                      setSort(nextSortBy, nextSortDir);
                    }}
                  >
                    <option value="name:asc">Name A-Z</option>
                    <option value="name:desc">Name Z-A</option>
                    <option value="date:desc">Newest</option>
                    <option value="date:asc">Oldest</option>
                    <option value="size:desc">Largest</option>
                    <option value="size:asc">Smallest</option>
                  </select>
                  <select className="toolbar-select" value={viewMode} onChange={(event) => setViewMode(event.target.value)}>
                    <option value="list">List</option>
                    <option value="grid">Grid</option>
                    <option value="compact">Compact</option>
                  </select>
                </div>
              </div>

              <input
                ref={fileInputRef}
                type="file"
                multiple
                style={{ display: "none" }}
                onChange={(event) => handleUpload(Array.from(event.target.files || []))}
              />

              <FileTable
                folders={bootData.folders}
                files={bootData.files}
                selectedKeys={selectedKeys}
                viewMode={viewMode}
                onNavigate={(path) => fetchBootstrap(path)}
                onToggleSelect={toggleSelection}
                onOpenEditor={openEditorInPreferredMode}
                onPreview={setPreviewKey}
                onDownload={handleDownload}
                onDelete={(key) =>
                  apiClient
                    .deleteFile(key)
                    .then(() => fetchBootstrap(bootData.currentPath))
                    .catch((err) => setError(err.message))
                }
                onShare={handleShare}
                onToggleFavorite={handleToggleFavorite}
                onDeleteFolder={handleDeleteFolder}
                onRename={handleRename}
                onDuplicate={(key) =>
                  apiClient
                    .duplicateFile(key)
                    .then(() => fetchBootstrap(bootData.currentPath))
                    .catch((err) => setError(err.message))
                }
                onRestore={(key) =>
                  apiClient
                    .restoreTrash(key)
                    .then(() => fetchBootstrap(bootData.currentPath))
                    .catch((err) => setError(err.message))
                }
                showTrash={showTrash}
                onUpload={(files) => {
                  if (files) {
                    handleUpload(files);
                  } else {
                    fileInputRef.current?.click();
                  }
                }}
              />

              <EditorWorkspace
                tabs={editorTabs}
                activeTabKey={activeTabKey}
                onActivateTab={setActiveTabKey}
                onCloseTab={closeTab}
                onChangeTabContent={handleChangeTabContent}
                onSaveTab={saveTab}
                onQuickOpen={openEditorInPreferredMode}
                quickOpenOptions={editableFiles}
                versionHistoryByKey={versionHistoryByKey}
                onRestoreVersion={handleRestoreVersion}
                currentUsername={bootData.user.username}
                theme={theme}
              />
            </>
          )}
        </main>
      </div>

      <ShareModal
        open={Boolean(shareTargetKey)}
        targetKey={shareTargetKey}
        initialVisibility={shareTargetInfo.visibility}
        initialAllowedUsers={shareTargetInfo.allowedUsers}
        isAdmin={Boolean(bootData.user?.isAdmin)}
        onSaved={refreshAfterShareChange}
        onClose={() => setShareTargetKey("")}
      />
      <PreviewPanel fileKey={previewKey} onClose={() => setPreviewKey("")} />
    </div>
  );
}
