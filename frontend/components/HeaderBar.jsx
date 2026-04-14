import React, { useEffect, useRef, useState } from "react";
import {
  Search,
  Sun,
  Moon,
  ChevronDown,
  User,
  Settings,
  LogOut,
  Layers,
  Activity,
} from "lucide-react";

function formatBytes(bytes) {
  if (!Number.isFinite(bytes)) return "0 B";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

function roleLabel(role) {
  if (role === "admin" || role === "owner") return "Owner";
  if (role === "editor") return "Editor";
  if (role === "member") return "Member";
  if (role === "commenter") return "Commenter";
  if (role === "viewer-download-disabled") return "Viewer (No Download)";
  return "Viewer";
}

function Breadcrumbs({ path, onNavigate }) {
  const parts = path ? path.split("/") : [];
  return (
    <nav className="breadcrumbs" aria-label="Breadcrumb">
      <button type="button" className="crumb" onClick={() => onNavigate("")}>
        Home
      </button>
      {parts.map((part, index) => {
        const segment = parts.slice(0, index + 1).join("/");
        return (
          <React.Fragment key={segment}>
            <span className="crumb-sep">/</span>
            <button type="button" className="crumb" onClick={() => onNavigate(segment)}>
              {part}
            </button>
          </React.Fragment>
        );
      })}
    </nav>
  );
}

export function HeaderBar({
  user,
  currentPath,
  onNavigate,
  theme,
  onToggleTheme,
  search,
  onSearchChange,
  quota,
  activeContentTab,
  onChangeContentTab,
}) {
  const used = Number(quota?.used_bytes ?? 0) || 0;
  const max = Number(quota?.max_bytes ?? 10 * 1024 * 1024 * 1024) || 10 * 1024 * 1024 * 1024;
  const bandwidth = Number(quota?.bandwidth_bytes ?? 0) || 0;
  const pct = Math.min(100, Math.round((used / Math.max(max, 1)) * 100));
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef(null);

  useEffect(() => {
    function closeOnOutsideClick(event) {
      if (menuRef.current && !menuRef.current.contains(event.target)) {
        setMenuOpen(false);
      }
    }
    function closeOnEscape(event) {
      if (event.key === "Escape") {
        setMenuOpen(false);
      }
    }
    document.addEventListener("click", closeOnOutsideClick);
    document.addEventListener("keydown", closeOnEscape);
    return () => {
      document.removeEventListener("click", closeOnOutsideClick);
      document.removeEventListener("keydown", closeOnEscape);
    };
  }, []);

  const initials = (user?.username || "?").slice(0, 2).toUpperCase();

  return (
    <header className="header">
      <div className="header-main">
        <div className="header-left">
          <a href="/" className="brand">
            <div className="brand-icon">111</div>
            <div className="brand-text">
              <span className="brand-name">
                iridescence <span className="brand-vault">Vault</span>
              </span>
            </div>
          </a>

          <nav className="header-tabs">
            <button
              type="button"
              className={`header-tab ${activeContentTab === "files" ? "active" : ""}`}
              onClick={() => onChangeContentTab?.("files")}
            >
              Files
            </button>
            {user?.isAdmin ? (
              <button
                type="button"
                className={`header-tab ${activeContentTab === "audit" ? "active" : ""}`}
                onClick={() => onChangeContentTab?.("audit")}
              >
                Logs
              </button>
            ) : null}
          </nav>
        </div>

        <div className="header-center">
          <div className="search-wrap">
            <Search size={16} className="search-icon" />
            <input
              className="search-input"
              placeholder="Search files, tags, and content..."
              value={search}
              onChange={(event) => onSearchChange(event.target.value)}
            />
          </div>
        </div>

        <div className="header-right">
          <div className="storage-indicator">
            <div className="storage-bar-wrap">
              <div className="storage-fill" style={{ width: `${pct}%` }} />
            </div>
            <span className="storage-text">
              {formatBytes(used)} / {formatBytes(max)}
            </span>
          </div>

          <div className="bandwidth-stat">
            <Activity size={12} />
            <span>{formatBytes(bandwidth)}</span>
          </div>

          <button type="button" className="icon-btn" onClick={onToggleTheme} aria-label="Toggle theme">
            {theme === "dark" ? <Sun size={18} /> : <Moon size={18} />}
          </button>

          <div className={`user-wrap ${menuOpen ? "open" : ""}`} ref={menuRef}>
            <button
              type="button"
              className="user-btn"
              onClick={() => setMenuOpen((open) => !open)}
              aria-expanded={menuOpen}
            >
              <div className="user-avatar">{initials}</div>
              {user.username}
              <ChevronDown size={14} className="caret" />
            </button>
            {menuOpen ? (
              <div className="user-dropdown">
                <div className="user-dropdown-header">
                  <div className="uname">{user.username}</div>
                  <div className="role">{roleLabel(user.role)} &middot; Vault</div>
                </div>
                <a href="/auth/account" className="ddl">
                  <User size={15} />
                  Account Preferences
                </a>
                {user?.isAdmin ? (
                  <a
                    href="/auth/admin"
                    className="ddl"
                    onClick={() => setMenuOpen(false)}
                  >
                    <Layers size={15} />
                    Admin Panel
                  </a>
                ) : null}
                <div className="dd-sep" />
                <a href="/auth/logout" className="ddl out">
                  <LogOut size={15} />
                  Sign Out
                </a>
              </div>
            ) : null}
          </div>
        </div>
      </div>

      <div className="meta-row">
        <Breadcrumbs path={currentPath} onNavigate={onNavigate} />
      </div>
    </header>
  );
}
