import React, { useMemo, useState } from "react";
import Editor, { DiffEditor, loader } from "@monaco-editor/react";

loader.config({
  paths: {
    vs: "https://cdn.jsdelivr.net/npm/monaco-editor@0.52.2/min/vs",
  },
});

function tabLabel(tab) {
  const marker = tab.dirty ? "●" : "○";
  return `${marker} ${tab.key.split("/").pop()}`;
}

function EditorsBadge({ editors = [], currentUsername }) {
  const active = editors.filter((editor) => editor.username !== currentUsername);
  if (!active.length) {
    return <span className="badge">No other active editors</span>;
  }
  return (
    <span className="badge warn" title="Live collaboration indicator">
      Editing now: {active.map((editor) => editor.username).join(", ")}
    </span>
  );
}

export function EditorWorkspace({
  tabs,
  activeTabKey,
  onActivateTab,
  onCloseTab,
  onChangeTabContent,
  onSaveTab,
  onQuickOpen,
  quickOpenOptions,
  versionHistoryByKey,
  onRestoreVersion,
  currentUsername,
  theme,
  editorHeight = "62vh",
}) {
  const activeTab = useMemo(() => tabs.find((tab) => tab.key === activeTabKey) || null, [tabs, activeTabKey]);
  const [quickOpenQuery, setQuickOpenQuery] = useState("");

  const quickResults = useMemo(() => {
    const query = quickOpenQuery.trim().toLowerCase();
    if (!query) return quickOpenOptions.slice(0, 20);
    return quickOpenOptions.filter((file) => file.key.toLowerCase().includes(query)).slice(0, 30);
  }, [quickOpenOptions, quickOpenQuery]);

  if (!tabs.length) {
    return null;
  }

  return (
    <section className="editor-shell">
      <div className="tabs-row">
        <div className="tabs-scroll">
          {tabs.map((tab) => (
            <button
              key={tab.key}
              type="button"
              className={`tab ${tab.key === activeTabKey ? "active" : ""}`}
              onClick={() => onActivateTab(tab.key)}
            >
              {tabLabel(tab)}
              <span
                className="tab-close"
                onClick={(event) => {
                  event.stopPropagation();
                  onCloseTab(tab.key);
                }}
              >
                ×
              </span>
            </button>
          ))}
        </div>
        <div className="quick-open">
          <input
            value={quickOpenQuery}
            onChange={(event) => setQuickOpenQuery(event.target.value)}
            placeholder="Quick open (⌘/Ctrl+P)"
          />
          {quickOpenQuery ? (
            <div className="quick-open-list">
              {quickResults.map((file) => (
                <button
                  key={file.key}
                  type="button"
                  className="quick-open-item"
                  onClick={() => {
                    onQuickOpen(file.key);
                    setQuickOpenQuery("");
                  }}
                >
                  {file.key}
                </button>
              ))}
              {!quickResults.length ? <div className="quick-open-empty">No matching files.</div> : null}
            </div>
          ) : null}
        </div>
      </div>

      {activeTab ? (
        <>
          <div className="editor-meta">
            <div className="breadcrumbs-inline">
              {activeTab.breadcrumbs?.map((crumb, index) => (
                <React.Fragment key={crumb.value}>
                  {index > 0 ? <span>/</span> : null}
                  <span className={crumb.isFile ? "crumb-file" : ""}>{crumb.label}</span>
                </React.Fragment>
              ))}
            </div>
            <div className="editor-meta-right">
              <EditorsBadge editors={activeTab.activeEditors} currentUsername={currentUsername} />
              <span className={`badge ${activeTab.canEdit ? "good" : "muted"}`}>
                {activeTab.canEdit ? "Editable" : "View only"}
              </span>
              <button
                type="button"
                className="btn btn-sm btn-muted"
                onClick={() => onSaveTab(activeTab.key, { manual: true })}
                disabled={!activeTab.canEdit || activeTab.saving}
              >
                {activeTab.saving ? "Saving..." : "Save now"}
              </button>
            </div>
          </div>

          <div className="editor-main">
            <div className="editor-column">
              {activeTab.showDiff ? (
                <DiffEditor
                  language={activeTab.language || "plaintext"}
                  original={activeTab.originalContent}
                  modified={activeTab.content}
                  theme={theme === "dark" ? "vs-dark" : "vs"}
                  height={editorHeight}
                  options={{
                    readOnly: !activeTab.canEdit,
                    renderSideBySide: true,
                    automaticLayout: true,
                    minimap: { enabled: false },
                  }}
                  onChange={(value) => onChangeTabContent(activeTab.key, value || "")}
                />
              ) : (
                <Editor
                  value={activeTab.content}
                  language={activeTab.language || "plaintext"}
                  theme={theme === "dark" ? "vs-dark" : "vs"}
                  height={editorHeight}
                  onChange={(value) => onChangeTabContent(activeTab.key, value || "")}
                  options={{
                    automaticLayout: true,
                    tabSize: 2,
                    wordWrap: "on",
                    minimap: { enabled: false },
                    readOnly: !activeTab.canEdit,
                    renderValidationDecorations: "on",
                  }}
                />
              )}
              <div className="editor-toolbar">
                <button
                  type="button"
                  className="btn btn-sm btn-muted"
                  onClick={() => onChangeTabContent(activeTab.key, activeTab.content, { toggleDiff: true })}
                >
                  {activeTab.showDiff ? "Hide diff" : "Preview diff"}
                </button>
                <span className="muted">
                  {activeTab.dirty ? "Unsaved changes" : "All changes saved"} · {activeTab.language || "plaintext"}
                </span>
              </div>
            </div>

            <aside className="history-column">
              <div className="panel-title">Version history</div>
              {(versionHistoryByKey[activeTab.key] || []).map((version) => (
                <div key={version.id} className="history-item">
                  <div>
                    <strong>v{version.version_number}</strong> by {version.saved_by}
                  </div>
                  <div className="muted">{new Date(version.saved_at).toLocaleString()}</div>
                  {version.summary ? <div className="muted">{version.summary}</div> : null}
                  <button type="button" className="btn btn-sm btn-muted" onClick={() => onRestoreVersion(version.id)}>
                    Restore
                  </button>
                </div>
              ))}
              {!versionHistoryByKey[activeTab.key]?.length ? (
                <div className="empty-mini">No historical versions yet.</div>
              ) : null}
            </aside>
          </div>
        </>
      ) : null}
    </section>
  );
}
