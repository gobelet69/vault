/**
 * VAULT SYSTEM
 * Features: File Visibility, Permissions, Admin Panel, Role Management
 * Routes under /vault path
 */

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const method = req.method;

    // --- 1. SESSION CHECK ---
    const cookie = req.headers.get('Cookie');
    const sessionId = cookie ? cookie.split(';').find(c => c.trim().startsWith('sess='))?.split('=')[1] : null;
    let user = null;

    if (sessionId) {
      try {
        const session = await env.AUTH_DB.prepare('SELECT * FROM sessions WHERE id = ? AND expires > ?').bind(sessionId, Date.now()).first();
        if (session) {
          user = session;
          const dbUser = await env.AUTH_DB.prepare('SELECT role FROM users WHERE username = ?').bind(user.username).first();
          user.role = dbUser ? (dbUser.role || 'guest') : 'guest';
        }
      } catch (e) { console.error("Session DB Error:", e); }
    }

    // --- 2. AUTH GUARD ---
    if (!user) {
      return new Response(null, {
        status: 302,
        headers: { 'Location': `/auth/login?redirect=${encodeURIComponent(url.pathname)}` }
      });
    }

    // --- API: UPLOAD ---
    if (url.pathname === '/vault/api/upload' && method === 'POST') {
      const originalName = req.headers.get('X-File-Name');
      if (!originalName) return new Response("Missing name", { status: 400 });

      const isPdf = originalName.toLowerCase().endsWith('.pdf');
      if (user.role === 'guest' && !isPdf) {
        return new Response("Guest users can only upload PDF files.", { status: 403 });
      }

      // Parse visibility + allowed_users from headers
      const visibility = req.headers.get('X-Visibility') || 'private';
      const allowedUsers = req.headers.get('X-Allowed-Users') || '';

      try {
        let safeName = originalName.replace(/[^\x00-\x7F]/g, "").trim();
        let finalName = safeName;
        let counter = 1;

        while (true) {
          const existing = await env.BUCKET.head(finalName);
          if (!existing) break;
          const dotIndex = safeName.lastIndexOf('.');
          if (dotIndex !== -1) {
            finalName = `${safeName.substring(0, dotIndex)} (${counter})${safeName.substring(dotIndex)}`;
          } else {
            finalName = `${safeName} (${counter})`;
          }
          counter++;
        }

        await env.BUCKET.put(finalName, req.body, {
          customMetadata: {
            uploader: user.username,
            role: user.role,
            visibility: visibility,        // private | public | specific
            allowed_users: allowedUsers    // comma-separated usernames
          }
        });
        return new Response("OK");
      } catch (e) { return new Response("Upload Failed: " + e.message, { status: 500 }); }
    }

    // --- API: DELETE ---
    if (url.pathname.startsWith('/vault/api/delete/')) {
      const fname = decodeURIComponent(url.pathname.replace('/vault/api/delete/', ''));
      const obj = await env.BUCKET.head(fname);
      if (!obj) return new Response("Not found", { status: 404 });

      const fileOwner = obj.customMetadata?.uploader || '';
      let canDelete = false;
      if (user.role === 'admin') canDelete = true;
      else if (fileOwner === user.username) canDelete = true;

      if (!canDelete) return new Response("Permission Denied", { status: 403 });
      await env.BUCKET.delete(fname);
      return new Response("Deleted");
    }

    // --- API: USER MANAGEMENT (admin only) ---
    if (url.pathname === '/vault/api/users' && method === 'POST') {
      if (user.role !== 'admin') return new Response("Forbidden", { status: 403 });
      try {
        const fd = await req.formData();
        const action = fd.get('action');

        if (action === 'create') {
          const hashPw = await hash(fd.get('p'));
          await env.AUTH_DB.prepare('INSERT OR REPLACE INTO users (username, password, role) VALUES (?, ?, ?)').bind(fd.get('u'), hashPw, fd.get('r')).run();
        }
        if (action === 'delete') {
          await env.AUTH_DB.prepare('DELETE FROM users WHERE username = ?').bind(fd.get('u')).run();
        }
        if (action === 'update-role') {
          await env.AUTH_DB.prepare('UPDATE users SET role = ? WHERE username = ?').bind(fd.get('r'), fd.get('u')).run();
        }
        return new Response("OK");
      } catch (e) {
        return new Response("DB Error: " + e.message, { status: 500 });
      }
    }

    // --- RENDER ADMIN PANEL ---
    if (url.pathname === '/vault/admin') {
      if (user.role !== 'admin') return new Response("Forbidden", { status: 403 });
      try {
        const { results: userList } = await env.AUTH_DB.prepare('SELECT username, role FROM users ORDER BY username').all();
        const list = await env.BUCKET.list({ include: ['customMetadata'] });
        const allFiles = list.objects.map(o => ({
          key: o.key,
          size: o.size,
          uploader: o.customMetadata?.uploader || '?',
          visibility: o.customMetadata?.visibility || 'private',
          allowed_users: o.customMetadata?.allowed_users || ''
        }));
        return new Response(renderAdmin(user, userList, allFiles), {
          headers: { 'Content-Type': 'text/html; charset=utf-8' }
        });
      } catch (e) { return new Response("Admin Error: " + e.message, { status: 500 }); }
    }

    // --- RENDER DASHBOARD ---
    if (url.pathname === '/vault' || url.pathname === '/vault/') {
      try {
        const list = await env.BUCKET.list({ include: ['customMetadata'] });

        // Filter files by visibility rules
        const files = list.objects
          .map(o => ({
            key: o.key,
            size: o.size,
            uploader: o.customMetadata?.uploader || '?',
            role: o.customMetadata?.role || '?',
            visibility: o.customMetadata?.visibility || 'private',
            allowed_users: o.customMetadata?.allowed_users || ''
          }))
          .filter(f => {
            if (user.role === 'admin') return true;                                   // admins see all
            if (f.visibility === 'public') return true;                               // public = everyone
            if (f.uploader === user.username) return true;                            // own files
            if (f.visibility === 'specific') {
              const allowed = f.allowed_users.split(',').map(u => u.trim());
              return allowed.includes(user.username);                                  // named users
            }
            return false;                                                             // private = owner only
          });

        let userList = [];
        if (user.role === 'admin') {
          try {
            const { results } = await env.AUTH_DB.prepare('SELECT username, role FROM users ORDER BY username').all();
            userList = results;
          } catch (e) { console.log("User table error", e); }
        }

        return new Response(renderDash(user, files, userList), {
          headers: { 'Content-Type': 'text/html; charset=utf-8' }
        });
      } catch (e) { return new Response("Render Error: " + e.message, { status: 500 }); }
    }

    // SERVE FILES
    if (url.pathname.startsWith('/vault/file/')) {
      const fname = decodeURIComponent(url.pathname.replace('/vault/file/', ''));
      const obj = await env.BUCKET.get(fname);
      if (!obj) return new Response("404", { status: 404 });

      // Check access on file serving too
      const meta = obj.customMetadata || {};
      const vis = meta.visibility || 'private';
      const owner = meta.uploader || '';
      let canAccess = user.role === 'admin' || vis === 'public' || owner === user.username;
      if (!canAccess && vis === 'specific') {
        canAccess = (meta.allowed_users || '').split(',').map(u => u.trim()).includes(user.username);
      }
      if (!canAccess) return new Response("Access Denied", { status: 403 });

      const h = new Headers();
      obj.writeHttpMetadata(h);
      h.set('etag', obj.httpEtag);
      let type = 'application/octet-stream';
      if (fname.endsWith('.pdf')) type = 'application/pdf';
      else if (fname.endsWith('.jpg') || fname.endsWith('.jpeg')) type = 'image/jpeg';
      else if (fname.endsWith('.png')) type = 'image/png';
      else if (fname.endsWith('.txt')) type = 'text/plain';
      h.set('Content-Type', type);
      return new Response(obj.body, { headers: h });
    }

    return new Response("404", { status: 404 });
  }
};

// --- HELPERS ---
async function hash(str) {
  const buf = new TextEncoder().encode(str);
  const h = await crypto.subtle.digest('SHA-256', buf);
  return Array.from(new Uint8Array(h)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// --- STYLES ---
const CSS = `
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
:root{--bg:#0f1117;--card:#161b22;--txt-main:#f8fafc;--txt-muted:#94a3b8;--p:#6366f1;--p-hover:#4f46e5;--s:#0ea5e9;--err:#f43f5e;--good:#10b981;--border:rgba(255,255,255,0.08);--ring:rgba(99,102,241,0.5)}
body{font-family:'Inter',system-ui,sans-serif;background:var(--bg);color:var(--txt-main);max-width:960px;margin:0 auto;padding:24px;line-height:1.5;box-sizing:border-box}
input,select{background:rgba(0,0,0,0.2);border:1px solid var(--border);color:var(--txt-main);padding:10px 14px;border-radius:8px;margin:5px 0;transition:all 0.2s;font-family:inherit;font-size:0.95em;width:100%}
input:focus,select:focus{outline:none;border-color:var(--p);box-shadow:0 0 0 3px var(--ring)}
button{cursor:pointer;background:var(--p);color:#fff;font-weight:600;border:none;padding:10px 16px;border-radius:8px;transition:all 0.2s;font-family:inherit;font-size:0.95em;box-shadow:0 4px 12px rgba(99,102,241,0.2)}
button:hover{background:var(--p-hover);transform:translateY(-1px);box-shadow:0 6px 16px rgba(99,102,241,0.3)}
.card{background:var(--card);padding:24px;border-radius:16px;margin-bottom:24px;border:1px solid var(--border);box-shadow:0 8px 32px rgba(0,0,0,0.2)}
.row{display:flex;justify-content:space-between;align-items:center;padding:14px 0;border-bottom:1px solid var(--border);transition:background 0.2s}
.row:last-child{border-bottom:none}
.tag{font-size:0.72em;padding:3px 9px;border-radius:20px;font-weight:600;letter-spacing:0.02em;vertical-align:middle;white-space:nowrap}
.tag.admin{background:rgba(244,63,94,0.15);color:var(--err);border:1px solid rgba(244,63,94,0.25)}
.tag.guest\\+{background:rgba(14,165,233,0.15);color:var(--s);border:1px solid rgba(14,165,233,0.25)}
.tag.guest{background:rgba(148,163,184,0.12);color:var(--txt-muted);border:1px solid rgba(148,163,184,0.2)}
.vis-badge{font-size:0.7em;padding:2px 8px;border-radius:10px;font-weight:600;margin-left:6px}
.vis-public{background:rgba(16,185,129,0.12);color:var(--good);border:1px solid rgba(16,185,129,0.2)}
.vis-private{background:rgba(148,163,184,0.08);color:var(--txt-muted);border:1px solid var(--border)}
.vis-specific{background:rgba(14,165,233,0.12);color:var(--s);border:1px solid rgba(14,165,233,0.2)}
.bar-wrap{height:6px;background:rgba(0,0,0,0.3);margin-top:12px;border-radius:3px;overflow:hidden;border:1px solid var(--border)}
.bar{height:100%;background:var(--p);width:0%;transition:0.3s ease-out;box-shadow:0 0 10px var(--p)}
a{color:var(--p);text-decoration:none;transition:color 0.2s} a:hover{color:var(--s)}
header{display:flex;justify-content:space-between;align-items:center;min-height:64px;padding:0 24px!important;background:var(--card)!important;border-bottom:1px solid var(--border)!important;margin-bottom:30px!important;border-radius:16px!important;box-shadow:0 4px 20px rgba(0,0,0,0.2)!important;flex-wrap:nowrap;gap:12px}
.user-wrap{position:relative}
.user-btn{display:flex;align-items:center;gap:8px;color:var(--txt-main);font-size:0.9em;font-weight:500;padding:8px 14px;border-radius:10px;background:rgba(255,255,255,0.06);border:1px solid var(--border);cursor:pointer;transition:background 0.2s;white-space:nowrap;font-family:inherit}
.user-btn:hover{background:rgba(255,255,255,0.1)}
.user-btn .caret{transition:transform 0.2s;margin-left:4px;opacity:0.6}
.user-wrap.open .user-btn .caret{transform:rotate(180deg)}
.user-dropdown{display:none;position:absolute;right:0;top:calc(100% + 8px);background:#1a2030;border:1px solid var(--border);border-radius:14px;min-width:210px;box-shadow:0 24px 48px rgba(0,0,0,0.5);z-index:999;overflow:hidden}
.user-wrap.open .user-dropdown{display:block;animation:fadeInD 0.15s ease-out}
@keyframes fadeInD{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:translateY(0)}}
.user-dropdown-header{padding:14px 16px 10px;border-bottom:1px solid var(--border)}
.user-dropdown-header .uname{font-weight:700;color:var(--txt-main);font-size:0.95em}
.user-dropdown-header .role{color:var(--txt-muted);font-size:0.78em;margin-top:2px}
.user-dropdown a{display:flex;align-items:center;gap:10px;padding:11px 16px;color:var(--txt-main);text-decoration:none;font-size:0.9em;font-weight:500;transition:background 0.15s}
.user-dropdown a:hover{background:rgba(255,255,255,0.06)}
.user-dropdown .sep{height:1px;background:var(--border);margin:4px 0}
.user-dropdown .signout{color:var(--err)}
.user-dropdown .signout:hover{background:rgba(244,63,94,0.08)}
h3{font-size:1.2em;margin-bottom:20px;font-weight:700;letter-spacing:-0.01em}
.form-grid{display:grid;grid-template-columns:1fr 1fr auto;gap:8px;align-items:end}
.form-grid-4{display:grid;grid-template-columns:1fr 1fr 1fr auto;gap:8px;align-items:end}
.role-select{padding:8px 12px;font-size:0.85em;cursor:pointer}
.btn-sm{padding:8px 12px;font-size:0.85em}
.btn-danger{background:rgba(244,63,94,0.12);color:var(--err);border:1px solid rgba(244,63,94,0.2);box-shadow:none}
.btn-danger:hover{background:rgba(244,63,94,0.2);transform:none;box-shadow:none}
.btn-secondary{background:rgba(255,255,255,0.06);color:var(--txt-muted);border:1px solid var(--border);box-shadow:none}
.btn-secondary:hover{background:rgba(255,255,255,0.1);transform:none;box-shadow:none}
table{width:100%;border-collapse:collapse}
th{text-align:left;padding:10px 12px;font-size:0.78em;font-weight:600;color:var(--txt-muted);letter-spacing:0.05em;text-transform:uppercase;border-bottom:1px solid var(--border)}
td{padding:12px;border-bottom:1px solid var(--border);font-size:0.9em;vertical-align:middle}
tr:last-child td{border-bottom:none}
tr:hover td{background:rgba(255,255,255,0.02)}
`;

const FAVICON = `data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Cdefs%3E%3ClinearGradient id='g' x1='0' y1='0' x2='1' y2='1'%3E%3Cstop offset='0' stop-color='%236366f1'/%3E%3Cstop offset='1' stop-color='%23f43f5e'/%3E%3C/linearGradient%3E%3C/defs%3E%3Crect width='32' height='32' rx='8' fill='url(%23g)'/%3E%3Ctext x='16' y='21' font-family='Arial,sans-serif' font-weight='900' font-size='12' fill='white' text-anchor='middle'%3E111%3C/text%3E%3C/svg%3E`;

function renderHeader(user, showAdmin = false) {
  const id = 'vuw';
  return `
  <a href="/" style="text-decoration:none;display:flex;align-items:center;gap:10px;flex-shrink:0">
    <span style="width:36px;height:36px;background:linear-gradient(135deg,#6366f1,#f43f5e);border-radius:10px;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:0.9em;color:#fff;flex-shrink:0;box-shadow:0 0 18px rgba(99,102,241,0.55)">111</span>
    <div style="display:flex;flex-direction:column;line-height:1.25">
      <span style="font-weight:700;font-size:1.1em;color:#fff;letter-spacing:-0.02em">111<span style="color:#6366f1;text-shadow:0 0 20px rgba(99,102,241,0.6)">iridescence</span></span>
      <span style="font-size:0.72em;color:#94a3b8;font-weight:500;letter-spacing:0.03em">Vault</span>
    </div>
  </a>
  <div style="display:flex;gap:8px;align-items:center;flex-shrink:0">
    ${showAdmin ? `<a href="/vault/admin" style="font-size:0.85em;font-weight:600;padding:7px 13px;border-radius:8px;background:rgba(244,63,94,0.1);color:var(--err);border:1px solid rgba(244,63,94,0.2);text-decoration:none;display:inline-flex;align-items:center;gap:6px"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg>Admin</a>` : ''}
    <div class="user-wrap" id="${id}">
      <button class="user-btn" onclick="document.getElementById('${id}').classList.toggle('open')">
        ${user.username}
        <svg class="caret" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="6 9 12 15 18 9"/></svg>
      </button>
      <div class="user-dropdown">
        <div class="user-dropdown-header">
          <div class="uname">${user.username}</div>
          <div style="margin-top:6px">
            ${{
      admin: `<span style="display:inline-block;font-size:0.72em;font-weight:700;padding:2px 9px;border-radius:20px;background:rgba(244,63,94,0.15);color:#f43f5e;border:1px solid rgba(244,63,94,0.25);letter-spacing:0.03em">admin</span>`,
      'guest+': `<span style="display:inline-block;font-size:0.72em;font-weight:700;padding:2px 9px;border-radius:20px;background:rgba(14,165,233,0.15);color:#0ea5e9;border:1px solid rgba(14,165,233,0.25);letter-spacing:0.03em">guest+</span>`,
      guest: `<span style="display:inline-block;font-size:0.72em;font-weight:700;padding:2px 9px;border-radius:20px;background:rgba(148,163,184,0.12);color:#94a3b8;border:1px solid rgba(148,163,184,0.2);letter-spacing:0.03em">guest</span>`
    }[user.role] || `<span style="font-size:0.78em;color:#94a3b8">${user.role}</span>`}
          </div>
          <div style="margin-top:8px;font-size:0.75em;color:#64748b;line-height:1.5">
            ${{
      admin: '🔑 Upload all · Delete any · Manage users',
      'guest+': '📁 Upload all files · Delete own files',
      guest: '📄 Upload PDF only · Delete own files'
    }[user.role] || ''}
          </div>
        </div>
        <a href="/auth/account">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 4-7 8-7s8 3 8 7"/></svg>
          Account Preferences
        </a>
        ${user.role === 'admin' ? `<a href="/vault/admin"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg>Admin Panel</a>` : ''}
        <div class="sep"></div>
        <a href="/auth/logout" class="signout">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
          Sign Out
        </a>
      </div>
    </div>
    <script>document.addEventListener('click',e=>{const w=document.getElementById('${id}');if(w&&!w.contains(e.target))w.classList.remove('open')});</script>
  </div>`;
}

// ── VISIBILITY BADGE ──────────────────────────────
function visBadge(visibility) {
  if (visibility === 'public') return `<span class="vis-badge vis-public">🌐 Public</span>`;
  if (visibility === 'specific') return `<span class="vis-badge vis-specific">👥 Shared</span>`;
  return `<span class="vis-badge vis-private">🔒 Private</span>`;
}

// ── MAIN DASHBOARD ───────────────────────────────
function renderDash(user, files, userList) {
  const isAdm = user.role === 'admin';
  const acceptAttr = user.role === 'guest' ? 'accept=".pdf"' : '';

  const fileRows = files.length === 0
    ? `<p style="text-align:center;color:var(--txt-muted);padding:24px 0">No files yet.</p>`
    : files.map(f => {
      const canDel = isAdm || f.uploader === user.username;
      const uploaderTag = `<span class="tag ${f.role === 'admin' ? 'admin' : f.role === 'guest+' ? 'guest+' : 'guest'}">${f.uploader}</span>`;
      return `
      <div class="row">
        <div style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0;flex:1">
          <a href="/vault/file/${encodeURIComponent(f.key)}" target="_blank">📄 ${f.key}</a>
          ${uploaderTag}
          ${visBadge(f.visibility)}
        </div>
        <div style="display:flex;align-items:center;gap:10px;flex-shrink:0;margin-left:12px">
          <small style="color:var(--txt-muted)">${(f.size / 1024).toFixed(1)} KB</small>
          ${canDel ? `<button onclick="delFile('${f.key}')" class="btn-sm btn-danger" style="padding:4px 10px;font-size:11px">✕</button>` : ''}
        </div>
      </div>`;
    }).join('');

  const usernames = userList.map(u => u.username).join(',');

  return `<!DOCTYPE html><html lang="en"><head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>111 Vault</title><link rel="icon" type="image/svg+xml" href="${FAVICON}">
  <style>${CSS}</style></head>
  <body>
    <header>${renderHeader(user, isAdm)}</header>

    <div class="card">
      <h3>📤 Upload ${user.role === 'guest' ? '(PDF Only)' : ''}</h3>
      <div style="display:grid;grid-template-columns:1fr auto;gap:12px;align-items:start;margin-bottom:14px">
        <input type="file" id="f" ${acceptAttr} style="margin:0">
        <button onclick="uploadFile()" style="height:42px;margin-top:5px">Upload</button>
      </div>
      <div style="margin-bottom:12px">
        <label style="font-size:0.85em;color:var(--txt-muted);font-weight:500;display:block;margin-bottom:8px">Visibility</label>
        <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px">
          <label style="display:flex;align-items:center;gap:8px;padding:10px 14px;border-radius:10px;border:1px solid var(--border);cursor:pointer;background:rgba(255,255,255,0.03);transition:border-color 0.2s" id="lbl-private">
            <input type="radio" name="vis" value="private" checked onchange="onVisChange(this)" style="width:auto;margin:0;padding:0;background:none;border:none"> 🔒 <span style="font-size:0.9em">Private</span>
          </label>
          <label style="display:flex;align-items:center;gap:8px;padding:10px 14px;border-radius:10px;border:1px solid var(--border);cursor:pointer;background:rgba(255,255,255,0.03);transition:border-color 0.2s" id="lbl-public">
            <input type="radio" name="vis" value="public" onchange="onVisChange(this)" style="width:auto;margin:0;padding:0;background:none;border:none"> 🌐 <span style="font-size:0.9em">Public</span>
          </label>
          <label style="display:flex;align-items:center;gap:8px;padding:10px 14px;border-radius:10px;border:1px solid var(--border);cursor:pointer;background:rgba(255,255,255,0.03);transition:border-color 0.2s" id="lbl-specific">
            <input type="radio" name="vis" value="specific" onchange="onVisChange(this)" style="width:auto;margin:0;padding:0;background:none;border:none"> 👥 <span style="font-size:0.9em">Specific users</span>
          </label>
        </div>
        <div id="specific-wrap" style="display:none;margin-top:10px">
          <select id="allowed-users" multiple style="height:100px;font-size:0.88em">
            ${userList.filter(u => u.username !== user.username).map(u => `<option value="${u.username}">${u.username} (${u.role})</option>`).join('')}
          </select>
          <small style="color:var(--txt-muted);display:block;margin-top:4px">Hold Ctrl/Cmd to select multiple</small>
        </div>
      </div>
      <div class="bar-wrap"><div id="pb" class="bar"></div></div>
      <div style="display:flex;justify-content:space-between;margin-top:8px">
        <small id="st" style="color:var(--txt-muted)">Ready</small>
      </div>
    </div>

    <div class="card">
      <h3>Files <span style="font-size:0.7em;color:var(--txt-muted);font-weight:400">${files.length} file${files.length !== 1 ? 's' : ''}</span></h3>
      ${fileRows}
    </div>

    <script>
      const ALL_USERNAMES = '${usernames}';

      function onVisChange(radio) {
        document.getElementById('specific-wrap').style.display = radio.value === 'specific' ? 'block' : 'none';
        ['private','public','specific'].forEach(v => {
          const lbl = document.getElementById('lbl-' + v);
          lbl.style.borderColor = v === radio.value ? '#6366f1' : 'rgba(255,255,255,0.08)';
          lbl.style.background = v === radio.value ? 'rgba(99,102,241,0.08)' : 'rgba(255,255,255,0.03)';
        });
      }

      function uploadFile() {
        const f = document.getElementById('f').files[0];
        if (!f) return alert('Select a file first');
        const vis = document.querySelector('input[name="vis"]:checked')?.value || 'private';
        const sel = document.getElementById('allowed-users');
        const allowedUsers = Array.from(sel.selectedOptions).map(o => o.value).join(',');

        const xhr = new XMLHttpRequest();
        xhr.open('POST', '/vault/api/upload', true);
        xhr.setRequestHeader('X-File-Name', f.name);
        xhr.setRequestHeader('X-Visibility', vis);
        xhr.setRequestHeader('X-Allowed-Users', allowedUsers);

        xhr.upload.onprogress = e => {
          if (e.lengthComputable) {
            const p = (e.loaded / e.total) * 100;
            document.getElementById('pb').style.width = p + '%';
            document.getElementById('st').innerText = Math.round(p) + '% uploaded';
          }
        };
        xhr.onload = () => {
          if (xhr.status === 200) location.reload();
          else alert('Error: ' + xhr.responseText);
        };
        xhr.send(f);
      }

      async function delFile(key) {
        if (!confirm('Delete ' + key + '?')) return;
        const res = await fetch('/vault/api/delete/' + encodeURIComponent(key));
        if (res.ok) location.reload();
        else alert('Error: ' + await res.text());
      }
    </script>
  </body></html>`;
}

// ── ADMIN PANEL ───────────────────────────────────
function renderAdmin(user, userList, allFiles) {
  const roleOptions = r => ['guest', 'guest+', 'admin'].map(v =>
    `<option value="${v}" ${v === r ? 'selected' : ''}>${v}</option>`).join('');

  const userRows = userList.map(u => `
    <tr>
      <td><strong>${u.username}</strong></td>
      <td>
        <form onsubmit="event.preventDefault();updateRole(this)" style="display:flex;gap:8px;align-items:center">
          <input type="hidden" name="action" value="update-role">
          <input type="hidden" name="u" value="${u.username}">
          <select name="r" class="role-select" style="width:auto;padding:6px 10px;font-size:0.85em">${roleOptions(u.role)}</select>
          <button class="btn-sm" type="submit" style="padding:6px 12px;font-size:0.83em">Save</button>
        </form>
      </td>
      <td>${u.username !== user.username ? `<button onclick="deleteUser('${u.username}')" class="btn-sm btn-danger" style="padding:6px 12px;font-size:0.82em">Delete</button>` : '<span style="color:var(--txt-muted);font-size:0.85em">You</span>'}</td>
    </tr>`).join('');

  const fileRows = allFiles.map(f => `
    <tr>
      <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
        <a href="/vault/file/${encodeURIComponent(f.key)}" target="_blank">📄 ${f.key}</a>
      </td>
      <td><span class="tag ${f.uploader === 'admin' ? 'admin' : 'guest'}">${f.uploader}</span></td>
      <td>${visBadge(f.visibility)}${f.visibility === 'specific' && f.allowed_users ? `<small style="color:var(--txt-muted);margin-left:6px">${f.allowed_users}</small>` : ''}</td>
      <td><small style="color:var(--txt-muted)">${(f.size / 1024).toFixed(1)} KB</small></td>
      <td><button onclick="delFile('${f.key}')" class="btn-sm btn-danger" style="padding:4px 10px;font-size:11px">✕</button></td>
    </tr>`).join('');

  return `<!DOCTYPE html><html lang="en"><head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>111 Vault — Admin</title><link rel="icon" type="image/svg+xml" href="${FAVICON}">
  <style>${CSS}</style></head>
  <body>
    <header>${renderHeader(user, true)}</header>

    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px">
        <h3 style="margin:0">👥 Users <span style="font-size:0.65em;color:var(--txt-muted);font-weight:400">${userList.length} total</span></h3>
        <a href="/vault" class="btn-secondary" style="padding:8px 14px;font-size:0.85em;border-radius:8px;text-decoration:none;color:var(--txt-muted)">← Back to Vault</a>
      </div>
      <div style="margin-bottom:20px">
        <p style="font-size:0.85em;color:var(--txt-muted);margin-bottom:12px">Create new user</p>
        <form onsubmit="event.preventDefault();createUser(this)">
          <div style="display:grid;grid-template-columns:1fr 1fr 1fr auto;gap:8px">
            <input type="hidden" name="action" value="create">
            <input type="text" name="u" placeholder="Username" required style="margin:0">
            <input type="password" name="p" placeholder="Password" required style="margin:0">
            <select name="r" style="margin:0">
              <option value="guest">guest — PDF only</option>
              <option value="guest+">guest+ — All files</option>
              <option value="admin">admin</option>
            </select>
            <button type="submit">Create</button>
          </div>
        </form>
      </div>
      <table>
        <thead><tr><th>Username</th><th>Role</th><th>Actions</th></tr></thead>
        <tbody>${userRows}</tbody>
      </table>
    </div>

    <div class="card">
      <h3>📂 All Files <span style="font-size:0.65em;color:var(--txt-muted);font-weight:400">${allFiles.length} total</span></h3>
      <table>
        <thead><tr><th>File</th><th>Uploaded by</th><th>Visibility</th><th>Size</th><th></th></tr></thead>
        <tbody>${fileRows}</tbody>
      </table>
    </div>

    <script>
      async function createUser(form) {
        const res = await fetch('/vault/api/users', {method:'POST', body: new FormData(form)});
        if (res.ok) location.reload(); else alert('Error: ' + await res.text());
      }
      async function updateRole(form) {
        const res = await fetch('/vault/api/users', {method:'POST', body: new FormData(form)});
        if (res.ok) { const btn = form.querySelector('button'); btn.textContent = '✓'; btn.style.background='var(--good)'; setTimeout(() => location.reload(), 600); }
        else alert('Error: ' + await res.text());
      }
      async function deleteUser(name) {
        if (!confirm('Remove user ' + name + '? This cannot be undone.')) return;
        const fd = new FormData(); fd.append('action','delete'); fd.append('u', name);
        const res = await fetch('/vault/api/users', {method:'POST', body: fd});
        if (res.ok) location.reload(); else alert('Error: ' + await res.text());
      }
      async function delFile(key) {
        if (!confirm('Delete ' + key + '?')) return;
        const res = await fetch('/vault/api/delete/' + encodeURIComponent(key));
        if (res.ok) location.reload(); else alert('Error: ' + await res.text());
      }
    </script>
  </body></html>`;
}