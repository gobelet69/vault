/**
 * VAULT SYSTEM — v3
 * Roles: owner / member / viewer (with backward-compat for admin / guest+ / guest)
 * Sharing: only-me / vault / people
 */

// ── ROLE HELPERS ──────────────────────────────────────────────────────────────
function normalizeRole(r) {
  if (r === 'admin') return 'owner';
  if (r === 'guest+') return 'member';
  if (r === 'guest') return 'viewer';
  return r || 'viewer';
}
function isOwner(user) { return normalizeRole(user.role) === 'owner'; }
function isMember(user) { return ['owner', 'member'].includes(normalizeRole(user.role)); }

const ROLE_META = {
  owner: { label: 'Owner', color: '#f43f5e', bg: 'rgba(244,63,94,0.15)', border: 'rgba(244,63,94,0.3)', icon: '🔑' },
  member: { label: 'Member', color: '#6366f1', bg: 'rgba(99,102,241,0.15)', border: 'rgba(99,102,241,0.3)', icon: '📁' },
  viewer: { label: 'Viewer', color: '#94a3b8', bg: 'rgba(148,163,184,0.1)', border: 'rgba(148,163,184,0.2)', icon: '👁' }
};

const ROLE_PERMS = {
  owner: ['Upload any file type', 'Delete any file', 'Share files', 'Manage users & roles', 'Access admin panel'],
  member: ['Upload any file type', 'Delete own files', 'Share files'],
  viewer: ['Upload PDF files only', 'Delete own files']
};

// ── SHARING HELPERS ──────────────────────────────────────────────────────────
// Normalize old visibility values to new ones
function normalizeVis(v) {
  if (v === 'public') return 'vault';
  if (v === 'specific') return 'people';
  if (v === 'private') return 'only-me';
  return v || 'only-me';
}

const VIS_META = {
  'only-me': { label: 'Only me', icon: '🔒', color: '#94a3b8', desc: 'Private' },
  'vault': { label: 'Everyone in vault', icon: '🏢', color: '#10b981', desc: 'Vault' },
  'people': { label: 'Specific people', icon: '👥', color: '#6366f1', desc: 'Shared' }
};

// ── WORKER ───────────────────────────────────────────────────────────────────
export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const method = req.method;

    // Session
    const cookie = req.headers.get('Cookie') || '';
    const sessionId = cookie.split(';').find(c => c.trim().startsWith('sess='))?.split('=')[1];
    let user = null;

    if (sessionId) {
      try {
        const sess = await env.AUTH_DB
          .prepare('SELECT * FROM sessions WHERE id = ? AND expires > ?')
          .bind(sessionId, Date.now()).first();
        if (sess) {
          user = sess;
          const dbUser = await env.AUTH_DB.prepare('SELECT role FROM users WHERE username = ?').bind(sess.username).first();
          user.role = dbUser?.role || 'viewer';
        }
      } catch (e) { console.error(e); }
    }

    if (!user) {
      return new Response(null, { status: 302, headers: { Location: `/auth/login?redirect=${encodeURIComponent(url.pathname)}` } });
    }

    // ── API: UPLOAD ──────────────────────────────────────────────────────────
    if (url.pathname === '/vault/api/upload' && method === 'POST') {
      const originalName = req.headers.get('X-File-Name');
      if (!originalName) return new Response('Missing filename', { status: 400 });

      const isPdf = originalName.toLowerCase().endsWith('.pdf');
      if (!isMember(user) && !isPdf)
        return new Response('Viewers can only upload PDF files.', { status: 403 });

      const visibility = req.headers.get('X-Visibility') || 'only-me';
      const allowedUsers = req.headers.get('X-Allowed-Users') || '';

      try {
        let safeName = originalName.replace(/[^\x00-\x7F]/g, '').trim();
        let finalName = safeName, counter = 1;
        while (await env.BUCKET.head(finalName)) {
          const dot = safeName.lastIndexOf('.');
          finalName = dot !== -1
            ? `${safeName.slice(0, dot)} (${counter})${safeName.slice(dot)}`
            : `${safeName} (${counter})`;
          counter++;
        }
        await env.BUCKET.put(finalName, req.body, {
          customMetadata: {
            uploader: user.username,
            role: normalizeRole(user.role),
            visibility,
            allowed_users: allowedUsers
          }
        });
        return new Response('OK');
      } catch (e) { return new Response('Upload failed: ' + e.message, { status: 500 }); }
    }

    // ── API: DELETE ──────────────────────────────────────────────────────────
    if (url.pathname.startsWith('/vault/api/delete/')) {
      const fname = decodeURIComponent(url.pathname.replace('/vault/api/delete/', ''));
      const obj = await env.BUCKET.head(fname);
      if (!obj) return new Response('Not found', { status: 404 });

      const owner = obj.customMetadata?.uploader || '';
      if (!isOwner(user) && owner !== user.username)
        return new Response('Permission denied', { status: 403 });

      await env.BUCKET.delete(fname);
      return new Response('Deleted');
    }

    // ── API: UPDATE VISIBILITY ───────────────────────────────────────────────
    if (url.pathname === '/vault/api/update-visibility' && method === 'POST') {
      try {
        const { key, visibility, allowed_users } = await req.json();
        const obj = await env.BUCKET.get(key);
        if (!obj) return new Response('Not found', { status: 404 });
        const fileOwner = obj.customMetadata?.uploader || '';
        if (!isOwner(user) && fileOwner !== user.username)
          return new Response('Permission denied', { status: 403 });
        const newMeta = { ...obj.customMetadata, visibility, allowed_users: allowed_users || '' };
        // Re-put with updated metadata (R2 has no metadata-only update)
        await env.BUCKET.put(key, obj.body, { customMetadata: newMeta });
        return new Response('OK');
      } catch (e) { return new Response(e.message, { status: 500 }); }
    }

    // ── API: USER MANAGEMENT ─────────────────────────────────────────────────
    if (url.pathname === '/vault/api/users' && method === 'POST') {
      if (!isOwner(user)) return new Response('Forbidden', { status: 403 });
      try {
        const fd = await req.formData();
        const action = fd.get('action');
        if (action === 'create') {
          const pw = await hash(fd.get('p'));
          await env.AUTH_DB.prepare('INSERT OR REPLACE INTO users (username, password, role, created_at) VALUES (?, ?, ?, ?)').bind(fd.get('u'), pw, fd.get('r'), new Date().toISOString()).run();
        }
        if (action === 'delete')
          await env.AUTH_DB.prepare('DELETE FROM users WHERE username = ?').bind(fd.get('u')).run();
        if (action === 'update-role')
          await env.AUTH_DB.prepare('UPDATE users SET role = ? WHERE username = ?').bind(fd.get('r'), fd.get('u')).run();
        return new Response('OK');
      } catch (e) { return new Response(e.message, { status: 500 }); }
    }

    // ── ADMIN PANEL ──────────────────────────────────────────────────────────
    if (url.pathname === '/vault/admin') {
      if (!isOwner(user)) return new Response('Forbidden', { status: 403 });
      const { results: userList } = await env.AUTH_DB.prepare('SELECT username, role FROM users ORDER BY username').all();
      const list = await env.BUCKET.list({ include: ['customMetadata'] });
      const allFiles = list.objects.map(o => ({
        key: o.key,
        size: o.size,
        uploader: o.customMetadata?.uploader || '?',
        uploaderRole: o.customMetadata?.role || 'viewer',
        visibility: normalizeVis(o.customMetadata?.visibility || 'only-me'),
        allowed_users: o.customMetadata?.allowed_users || ''
      }));
      return new Response(renderAdmin(user, userList, allFiles), {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }

    // ── DASHBOARD ────────────────────────────────────────────────────────────
    if (url.pathname === '/vault' || url.pathname === '/vault/') {
      const list = await env.BUCKET.list({ include: ['customMetadata'] });

      const files = list.objects
        .map(o => ({
          key: o.key,
          size: o.size,
          uploader: o.customMetadata?.uploader || '?',
          uploaderRole: normalizeRole(o.customMetadata?.role || 'viewer'),
          visibility: normalizeVis(o.customMetadata?.visibility || 'only-me'),
          allowed_users: o.customMetadata?.allowed_users || ''
        }))
        .filter(f => {
          if (isOwner(user)) return true;
          if (f.uploader === user.username) return true;
          if (f.visibility === 'vault') return true;
          if (f.visibility === 'people') {
            return f.allowed_users.split(',').map(s => s.trim()).includes(user.username);
          }
          return false;
        });

      let userList = [];
      if (isOwner(user)) {
        const { results } = await env.AUTH_DB.prepare('SELECT username, role FROM users ORDER BY username').all();
        userList = results;
      }

      return new Response(renderDash(user, files, userList), {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }

    // ── SERVE FILE ───────────────────────────────────────────────────────────
    if (url.pathname.startsWith('/vault/file/')) {
      const fname = decodeURIComponent(url.pathname.replace('/vault/file/', ''));
      const obj = await env.BUCKET.get(fname);
      if (!obj) return new Response('404', { status: 404 });

      const meta = obj.customMetadata || {};
      const vis = normalizeVis(meta.visibility || 'only-me');
      const owner = meta.uploader || '';
      let ok = isOwner(user) || vis === 'vault' || owner === user.username;
      if (!ok && vis === 'people')
        ok = (meta.allowed_users || '').split(',').map(s => s.trim()).includes(user.username);
      if (!ok) return new Response('Access denied', { status: 403 });

      const h = new Headers();
      obj.writeHttpMetadata(h);
      h.set('etag', obj.httpEtag);
      const ext = fname.split('.').pop().toLowerCase();
      const types = { pdf: 'application/pdf', jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', gif: 'image/gif', txt: 'text/plain', mp4: 'video/mp4' };
      h.set('Content-Type', types[ext] || 'application/octet-stream');
      return new Response(obj.body, { headers: h });
    }

    return new Response('404', { status: 404 });
  }
};

async function hash(str) {
  const buf = new TextEncoder().encode(str);
  const h = await crypto.subtle.digest('SHA-256', buf);
  return Array.from(new Uint8Array(h)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── STYLES ────────────────────────────────────────────────────────────────────
const CSS = `
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
:root{--bg:#0f1117;--card:#161b22;--card2:#1c2130;--txt-main:#f8fafc;--txt-muted:#94a3b8;--txt-dim:#475569;--p:#6366f1;--p-h:#4f46e5;--s:#0ea5e9;--err:#f43f5e;--good:#10b981;--warn:#f59e0b;--border:rgba(255,255,255,0.07);--ring:rgba(99,102,241,0.4)}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Inter',system-ui,sans-serif;background:var(--bg);color:var(--txt-main);max-width:960px;margin:0 auto;padding:24px;line-height:1.5}
a{color:var(--p);text-decoration:none;transition:color 0.2s} a:hover{color:var(--s)}
input,select{background:rgba(0,0,0,0.25);border:1px solid var(--border);color:var(--txt-main);padding:10px 14px;border-radius:10px;font-family:inherit;font-size:0.93em;transition:border-color 0.2s,box-shadow 0.2s;width:100%}
input:focus,select:focus{outline:none;border-color:var(--p);box-shadow:0 0 0 3px var(--ring)}
button{cursor:pointer;background:var(--p);color:#fff;font-weight:600;border:none;padding:10px 18px;border-radius:10px;transition:all 0.2s;font-family:inherit;font-size:0.93em;white-space:nowrap}
button:hover{background:var(--p-h);transform:translateY(-1px)}
.card{background:var(--card);padding:24px;border-radius:18px;margin-bottom:20px;border:1px solid var(--border);box-shadow:0 8px 32px rgba(0,0,0,0.2)}
.section-title{font-size:1em;font-weight:700;color:var(--txt-main);margin-bottom:16px;letter-spacing:-0.01em;display:flex;align-items:center;gap:8px}
/* HEADER */
header{display:flex;justify-content:space-between;align-items:center;min-height:64px;padding:0 24px;background:var(--card);border:1px solid var(--border);margin-bottom:28px;border-radius:18px;box-shadow:0 4px 24px rgba(0,0,0,0.25);gap:12px}
.user-wrap{position:relative}
.user-btn{display:flex;align-items:center;gap:8px;color:var(--txt-main);font-size:0.9em;font-weight:500;padding:8px 14px;border-radius:10px;background:rgba(255,255,255,0.05);border:1px solid var(--border);cursor:pointer;transition:background 0.2s;font-family:inherit}
.user-btn:hover{background:rgba(255,255,255,0.09)}
.user-btn .caret{opacity:0.5;transition:transform 0.2s;margin-left:2px}
.user-wrap.open .user-btn .caret{transform:rotate(180deg)}
.user-dropdown{display:none;position:absolute;right:0;top:calc(100% + 10px);background:#151c28;border:1px solid var(--border);border-radius:16px;min-width:240px;box-shadow:0 24px 60px rgba(0,0,0,0.6);z-index:999;overflow:hidden}
.user-wrap.open .user-dropdown{display:block;animation:dd 0.15s ease-out}
@keyframes dd{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:translateY(0)}}
.dd-header{padding:16px 18px 14px;border-bottom:1px solid var(--border)}
.dd-username{font-weight:700;font-size:1em;color:var(--txt-main);margin-bottom:8px}
.role-badge{display:inline-flex;align-items:center;gap:5px;font-size:0.73em;font-weight:700;padding:3px 10px;border-radius:20px;letter-spacing:0.03em;margin-bottom:10px}
.perm-list{list-style:none;margin-top:6px}
.perm-list li{font-size:0.78em;color:var(--txt-muted);padding:2px 0;display:flex;align-items:center;gap:6px}
.perm-list li.allowed{color:#cbd5e1}
.perm-check{width:14px;height:14px;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;flex-shrink:0;font-size:9px;font-weight:700}
.perm-check.yes{background:rgba(16,185,129,0.2);color:var(--good)}
.perm-check.no{background:rgba(148,163,184,0.1);color:var(--txt-dim)}
.dd-link{display:flex;align-items:center;gap:10px;padding:11px 18px;color:var(--txt-main);text-decoration:none;font-size:0.9em;font-weight:500;transition:background 0.15s}
.dd-link:hover{background:rgba(255,255,255,0.05);color:var(--txt-main)}
.dd-sep{height:1px;background:var(--border);margin:4px 0}
.dd-signout{color:var(--err)!important}
.dd-signout:hover{background:rgba(244,63,94,0.08)!important}
/* FILE LIST */
.file-row{display:flex;justify-content:space-between;align-items:center;padding:13px 0;border-bottom:1px solid var(--border);gap:12px}
.file-row:last-child{border-bottom:none}
.file-name{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:0.93em;min-width:0;flex:1}
.file-meta{display:flex;align-items:center;gap:10px;flex-shrink:0}
.uploader-tag{font-size:0.72em;font-weight:600;padding:2px 9px;border-radius:20px;letter-spacing:0.02em;white-space:nowrap}
.vis-pill{font-size:0.7em;font-weight:600;padding:3px 9px;border-radius:20px;letter-spacing:0.02em;display:inline-flex;align-items:center;gap:4px;white-space:nowrap}
.vis-only-me{background:rgba(148,163,184,0.1);color:#64748b;border:1px solid rgba(148,163,184,0.15)}
.vis-vault{background:rgba(16,185,129,0.1);color:var(--good);border:1px solid rgba(16,185,129,0.2)}
.vis-people{background:rgba(99,102,241,0.12);color:#a5b4fc;border:1px solid rgba(99,102,241,0.2)}
.btn-del{background:rgba(244,63,94,0.1);color:var(--err);border:1px solid rgba(244,63,94,0.2);padding:5px 10px;font-size:0.78em;font-weight:600;border-radius:8px}
.btn-del:hover{background:rgba(244,63,94,0.2);transform:none}
.btn-edit{background:rgba(255,255,255,0.05);color:var(--txt-muted);border:1px solid var(--border);padding:5px 8px;font-size:0.78em;border-radius:8px}
.btn-edit:hover{background:rgba(255,255,255,0.1);transform:none}
/* SHARING CARDS */
.share-cards{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin:14px 0}
.share-card{position:relative;padding:14px 16px;border-radius:12px;border:2px solid var(--border);background:rgba(255,255,255,0.02);cursor:pointer;transition:all 0.18s;user-select:none}
.share-card:hover{background:rgba(255,255,255,0.04);border-color:rgba(255,255,255,0.14)}
.share-card.active-only-me{border-color:#64748b;background:rgba(148,163,184,0.08)}
.share-card.active-vault{border-color:var(--good);background:rgba(16,185,129,0.07)}
.share-card.active-people{border-color:var(--p);background:rgba(99,102,241,0.08)}
.share-card input[type=radio]{position:absolute;opacity:0;pointer-events:none}
.share-icon{font-size:1.4em;margin-bottom:6px;display:block}
.share-title{font-size:0.88em;font-weight:700;color:var(--txt-main);margin-bottom:3px}
.share-desc{font-size:0.75em;color:var(--txt-muted);line-height:1.4}
/* TOOLTIP */
.tip-wrap{position:relative;display:inline-flex;align-items:center;gap:4px;cursor:default}
.tip-icon{width:15px;height:15px;border-radius:50%;background:rgba(255,255,255,0.08);border:1px solid var(--border);display:inline-flex;align-items:center;justify-content:center;font-size:10px;font-weight:700;color:var(--txt-muted);cursor:help;flex-shrink:0}
.tip-box{display:none;position:absolute;left:50%;transform:translateX(-50%);top:calc(100% + 8px);background:#0d1117;border:1px solid rgba(255,255,255,0.12);border-radius:10px;padding:10px 13px;width:220px;font-size:0.78em;color:#cbd5e1;line-height:1.5;z-index:100;box-shadow:0 16px 40px rgba(0,0,0,0.5);pointer-events:none}
.tip-box::before{content:'';position:absolute;top:-5px;left:50%;transform:translateX(-50%);width:8px;height:8px;background:#0d1117;border-left:1px solid rgba(255,255,255,0.12);border-top:1px solid rgba(255,255,255,0.12);rotate:45deg}
.tip-wrap:hover .tip-box{display:block}
/* PEOPLE SELECT */
.people-select{display:none;margin-top:10px;animation:fadeIn 0.2s ease-out}
@keyframes fadeIn{from{opacity:0;transform:translateY(-4px)}to{opacity:1;transform:translateY(0)}}
select[multiple]{height:110px;font-size:0.88em}
/* ADMIN TABLE */
table{width:100%;border-collapse:collapse}
th{text-align:left;padding:10px 12px;font-size:0.75em;font-weight:600;color:var(--txt-muted);letter-spacing:0.06em;text-transform:uppercase;border-bottom:1px solid var(--border)}
td{padding:12px;border-bottom:1px solid var(--border);font-size:0.9em;vertical-align:middle}
tr:last-child td{border-bottom:none}
tr:hover td{background:rgba(255,255,255,0.015)}
.btn-sm{padding:6px 12px;font-size:0.82em;border-radius:8px}
.btn-ghost{background:rgba(255,255,255,0.05);color:var(--txt-muted);border:1px solid var(--border)}
.btn-ghost:hover{background:rgba(255,255,255,0.1);transform:none}
.form-row{display:grid;gap:8px;align-items:end}
`;

const FAVICON = `data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Cdefs%3E%3ClinearGradient id='g' x1='0' y1='0' x2='1' y2='1'%3E%3Cstop offset='0' stop-color='%236366f1'/%3E%3Cstop offset='1' stop-color='%23f43f5e'/%3E%3C/linearGradient%3E%3C/defs%3E%3Crect width='32' height='32' rx='8' fill='url(%23g)'/%3E%3Ctext x='16' y='21' font-family='Arial,sans-serif' font-weight='900' font-size='12' fill='white' text-anchor='middle'%3E111%3C/text%3E%3C/svg%3E`;

const HEAD = (title) =>
  `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title><link rel="icon" type="image/svg+xml" href="${FAVICON}"><style>${CSS}</style></head>`;

// ── HEADER ────────────────────────────────────────────────────────────────────
function renderHeader(user) {
  const role = normalizeRole(user.role);
  const rm = ROLE_META[role] || ROLE_META.viewer;
  const perms = ROLE_PERMS[role] || [];
  const allPerms = [
    'Upload any file type',
    'Delete any file',
    'Share files',
    'Manage users & roles',
    'Access admin panel'
  ];
  const id = 'vuw';

  return `
  <a href="/" style="text-decoration:none;display:flex;align-items:center;gap:10px;flex-shrink:0">
    <span style="width:36px;height:36px;background:linear-gradient(135deg,#6366f1,#f43f5e);border-radius:10px;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:0.9em;color:#fff;flex-shrink:0;box-shadow:0 0 18px rgba(99,102,241,0.5)">111</span>
    <div style="display:flex;flex-direction:column;line-height:1.25">
      <span style="font-weight:700;font-size:1.1em;color:#fff;letter-spacing:-0.02em">111<span style="color:#6366f1;text-shadow:0 0 20px rgba(99,102,241,0.6)">iridescence</span></span>
      <span style="font-size:0.72em;color:#94a3b8;font-weight:500;letter-spacing:0.03em">Vault</span>
    </div>
  </a>
  <div style="display:flex;gap:8px;align-items:center;flex-shrink:0">
    ${isOwner(user) ? `<a href="/vault/admin" style="font-size:0.82em;font-weight:600;padding:7px 13px;border-radius:8px;background:rgba(244,63,94,0.1);color:#f43f5e;border:1px solid rgba(244,63,94,0.2);text-decoration:none;display:inline-flex;align-items:center;gap:5px"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg>Admin</a>` : ''}
    <div class="user-wrap" id="${id}">
      <button class="user-btn" onclick="document.getElementById('${id}').classList.toggle('open')">
        ${user.username}
        <svg class="caret" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="6 9 12 15 18 9"/></svg>
      </button>
      <div class="user-dropdown">
        <div class="dd-header">
          <div class="dd-username">${user.username}</div>
          <span class="role-badge" style="background:${rm.bg};color:${rm.color};border:1px solid ${rm.border}">${rm.icon} ${rm.label}</span>
          <ul class="perm-list">
            ${allPerms.map(p => {
    const has = perms.includes(p);
    return `<li class="${has ? 'allowed' : ''}">
                <span class="perm-check ${has ? 'yes' : 'no'}">${has ? '✓' : '✕'}</span>
                ${p}
              </li>`;
  }).join('')}
          </ul>
        </div>
        <a href="/auth/account" class="dd-link">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 4-7 8-7s8 3 8 7"/></svg>
          Account Preferences
        </a>
        ${isOwner(user) ? `<a href="/vault/admin" class="dd-link"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg>Admin Panel</a>` : ''}
        <div class="dd-sep"></div>
        <a href="/auth/logout" class="dd-link dd-signout">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
          Sign Out
        </a>
      </div>
    </div>
    <script>document.addEventListener('click',e=>{const w=document.getElementById('${id}');if(w&&!w.contains(e.target))w.classList.remove('open')});<\/script>
  </div>`;
}

// ── VIS BADGE ─────────────────────────────────────────────────────────────────
function visPill(vis) {
  const m = VIS_META[vis] || VIS_META['only-me'];
  return `<span class="vis-pill vis-${vis}">${m.icon} ${m.label}</span>`;
}

// ── UPLOADER TAG ──────────────────────────────────────────────────────────────
function uploaderTag(uploaderName, uploaderRole) {
  const rm = ROLE_META[uploaderRole] || ROLE_META.viewer;
  return `<span class="uploader-tag" style="background:${rm.bg};color:${rm.color};border:1px solid ${rm.border}">${uploaderName}</span>`;
}

// ── TOOLTIP ───────────────────────────────────────────────────────────────────
function tooltip(text) {
  return `<span class="tip-wrap"><span class="tip-icon">?</span><span class="tip-box">${text}</span></span>`;
}

// ── DASHBOARD ─────────────────────────────────────────────────────────────────
function renderDash(user, files, userList) {
  const acceptAttr = isMember(user) ? '' : 'accept=".pdf"';

  const fileRows = files.length === 0
    ? `<p style="text-align:center;color:var(--txt-dim);padding:28px 0">No files yet.</p>`
    : files.map(f => {
      const canDel = isOwner(user) || f.uploader === user.username;
      return `<div class="file-row">
        <div class="file-name">
          <a href="/vault/file/${encodeURIComponent(f.key)}" target="_blank">📄 ${f.key}</a>
        </div>
        <div class="file-meta">
          ${uploaderTag(f.uploader, f.uploaderRole)}
          <span class="vis-pill vis-${f.visibility}" style="cursor:default">${VIS_META[f.visibility]?.icon || '🔒'} ${VIS_META[f.visibility]?.label || 'Only me'}</span>
          <small style="color:var(--txt-dim)">${(f.size / 1024).toFixed(1)} KB</small>
          ${(isOwner(user) || f.uploader === user.username) ? `<button class="btn-edit" onclick="openVisModal('${f.key.replace(/'/g, "&#39;")}','${f.visibility}','${f.allowed_users.replace(/'/g, "&#39;")}')" title="Edit visibility">✏️</button>` : ''}
          ${canDel ? `<button class="btn-del" onclick="delFile('${f.key.replace(/'/g, "&#39;")}')">✕</button>` : ''}
        </div>
      </div>`;
    }).join('');

  const otherUsers = userList.filter(u => u.username !== user.username);

  return HEAD('111 Vault') + `<body>
    <header>${renderHeader(user)}</header>

    <div class="card">
      <div class="section-title">
        📤 Upload a file
        ${!isMember(user) ? `<span style="font-size:0.8em;color:var(--txt-dim);font-weight:400">(PDF only for your account)</span>` : ''}
      </div>

      <div style="display:grid;grid-template-columns:1fr auto;gap:10px;align-items:center;margin-bottom:20px">
        <input type="file" id="fileInput" ${acceptAttr} style="cursor:pointer">
        <button onclick="uploadFile()" style="height:42px">Upload</button>
      </div>

      <div>
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:12px">
          <span style="font-size:0.88em;font-weight:600;color:var(--txt-muted)">Who can access this file?</span>
          ${tooltip("Choose who can see and download this file after upload. You can't change it after uploading — delete and re-upload to change visibility.")}
        </div >

    <div class="share-cards">

      <label class="share-card active-only-me" id="card-only-me" onclick="selectVis('only-me')">
        <input type="radio" name="vis" value="only-me" checked>
          <span class="share-icon">🔒</span>
          <div class="share-title">Only me</div>
          <div class="share-desc">Completely private. Only you${isOwner(user) ? '' : ' and vault owners'} can see and open this file.</div>
      </label>

      <label class="share-card" id="card-vault" onclick="selectVis('vault')">
        <input type="radio" name="vis" value="vault">
          <span class="share-icon">🏢</span>
          <div class="share-title">Everyone in vault</div>
          <div class="share-desc">All members and viewers who have a vault account can see and download this.</div>
      </label>

      <label class="share-card" id="card-people" onclick="selectVis('people')">
        <input type="radio" name="vis" value="people">
          <span class="share-icon">👥</span>
          <div class="share-title">Specific people</div>
          <div class="share-desc">Only the people you select can access this. Everyone else is excluded.</div>
      </label>

    </div>

        ${otherUsers.length > 0 ? `
        <div class="people-select" id="people-select">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
            <span style="font-size:0.85em;font-weight:600;color:var(--txt-muted)">Select people</span>
            ${tooltip('Hold Ctrl (Windows) or ⌘ (Mac) to select multiple people. Only selected people will be able to see this file.')}
          </div>
          <select id="allowed-users" multiple>
            ${otherUsers.map(u => {
    const rm = ROLE_META[normalizeRole(u.role)] || ROLE_META.viewer;
    return `<option value="${u.username}">${u.username} — ${rm.label}</option>`;
  }).join('')}
          </select>
        </div>` : ''
    }

  <div class="bar-wrap" style="height:5px;background:rgba(0,0,0,0.3);margin-top:16px;border-radius:3px;overflow:hidden;border:1px solid var(--border)">
  <div id="pb" style="height:100%;background:var(--p);width:0%;transition:width 0.2s;box-shadow:0 0 8px var(--p)"></div>
        </div >
    <div style="display:flex;justify-content:space-between;margin-top:6px">
      <small id="st" style="color:var(--txt-dim)">Ready to upload</small>
    </div>
      </div >
    </div >

    <div class="card">
      <div class="section-title">
        Files
        <span style="font-size:0.75em;color:var(--txt-dim);font-weight:400">${files.length} file${files.length !== 1 ? 's' : ''}</span>
      </div>
      ${fileRows}
    </div>

    <!-- Visibility Edit Modal -->
    <div id="vis-modal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.75);z-index:1000;align-items:center;justify-content:center;padding:20px;backdrop-filter:blur(4px)" onclick="if(event.target===this)closeVisModal()">
      <div style="background:#161b22;border:1px solid rgba(255,255,255,0.1);border-radius:20px;padding:28px;width:100%;max-width:520px;box-shadow:0 32px 80px rgba(0,0,0,0.7)">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
          <span style="font-weight:700;font-size:1em">Edit Visibility</span>
          <button onclick="closeVisModal()" style="background:none;border:none;color:#94a3b8;font-size:1.1em;padding:4px 8px;cursor:pointer;line-height:1">✕</button>
        </div>
        <div id="vm-filename" style="font-size:0.82em;color:#64748b;margin-bottom:18px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"></div>
        <div class="share-cards">
          <label class="share-card" id="vm-card-only-me" onclick="vmSelectVis('only-me')">
            <input type="radio" name="mvis" value="only-me">
            <span class="share-icon">🔒</span>
            <div class="share-title">Only me</div>
            <div class="share-desc">Private — only you and owners can see this.</div>
          </label>
          <label class="share-card" id="vm-card-vault" onclick="vmSelectVis('vault')">
            <input type="radio" name="mvis" value="vault">
            <span class="share-icon">🏢</span>
            <div class="share-title">Everyone in vault</div>
            <div class="share-desc">All vault members can see and download this.</div>
          </label>
          <label class="share-card" id="vm-card-people" onclick="vmSelectVis('people')">
            <input type="radio" name="mvis" value="people">
            <span class="share-icon">👥</span>
            <div class="share-title">Specific people</div>
            <div class="share-desc">Only the people you select can access this.</div>
          </label>
        </div>
        <div id="vm-people" style="display:none;margin-top:12px">
          <div style="font-size:0.83em;color:#94a3b8;font-weight:500;margin-bottom:6px">Select people</div>
          <select id="vm-users" multiple>
            ${userList.filter(u => u.username !== user.username).map(u => {
      const rm = ROLE_META[normalizeRole(u.role)] || ROLE_META.viewer;
      return `<option value="${u.username}">${u.username} \u2014 ${rm.label}</option>`;
    }).join('')}
          </select>
          <small style="color:#475569;display:block;margin-top:4px">Hold Ctrl / \u2318 to select multiple</small>
        </div>
        <div style="display:flex;gap:10px;justify-content:flex-end;margin-top:20px">
          <button onclick="closeVisModal()" style="background:rgba(255,255,255,0.05);color:#94a3b8;border:1px solid rgba(255,255,255,0.08)">Cancel</button>
          <button id="vm-save-btn" onclick="saveVisibility()">Save changes</button>
        </div>
      </div>
    </div>

    <script>
      function selectVis(val) {
        ['only-me','vault','people'].forEach(v => {
          const card = document.getElementById('card-' + v);
          card.className = 'share-card' + (v === val ? ' active-' + v : '');
          card.querySelector('input').checked = v === val;
        });
        const ps = document.getElementById('people-select');
        if (ps) ps.style.display = val === 'people' ? 'block' : 'none';
      }

      function uploadFile() {
        const fileEl = document.getElementById('fileInput');
        const f = fileEl?.files[0];
        if (!f) return alert('Please select a file first.');
        const vis = document.querySelector('input[name="vis"]:checked')?.value || 'only-me';
        const sel = document.getElementById('allowed-users');
        const allowedUsers = sel ? Array.from(sel.selectedOptions).map(o => o.value).join(',') : '';

        if (vis === 'people' && sel && !allowedUsers) {
          return alert('Please select at least one person to share with, or choose a different visibility option.');
        }

        const xhr = new XMLHttpRequest();
        xhr.open('POST', '/vault/api/upload', true);
        xhr.setRequestHeader('X-File-Name', f.name);
        xhr.setRequestHeader('X-Visibility', vis);
        xhr.setRequestHeader('X-Allowed-Users', allowedUsers);
        xhr.upload.onprogress = e => {
          if (e.lengthComputable) {
            const p = (e.loaded / e.total) * 100;
            document.getElementById('pb').style.width = p + '%';
            document.getElementById('st').textContent = Math.round(p) + '% — ' + f.name;
          }
        };
        xhr.onload = () => {
          if (xhr.status === 200) location.reload();
          else alert('Upload error: ' + xhr.responseText);
        };
        xhr.send(f);
      }

      async function delFile(key) {
        if (!confirm('Delete "' + key + '"? This cannot be undone.')) return;
        const res = await fetch('/vault/api/delete/' + encodeURIComponent(key));
        if (res.ok) location.reload(); else alert(await res.text());
      }

      // ── VISIBILITY MODAL ──────────────────────────────────────────────────
      let _modalKey = '';

      function openVisModal(key, currentVis, currentAllowed) {
        _modalKey = key;
        document.getElementById('vm-filename').textContent = '📄 ' + key;
        // Select current card
        ['only-me','vault','people'].forEach(v => {
          const card = document.getElementById('vm-card-' + v);
          card.className = 'share-card' + (v === currentVis ? ' active-' + v : '');
          card.querySelector('input').checked = v === currentVis;
        });
        // Pre-select allowed users
        const sel = document.getElementById('vm-users');
        if (sel && currentAllowed) {
          const names = currentAllowed.split(',').map(s => s.trim());
          Array.from(sel.options).forEach(o => o.selected = names.includes(o.value));
        }
        vmSelectVis(currentVis);
        document.getElementById('vis-modal').style.display = 'flex';
        document.body.style.overflow = 'hidden';
      }

      function closeVisModal() {
        document.getElementById('vis-modal').style.display = 'none';
        document.body.style.overflow = '';
      }

      function vmSelectVis(val) {
        ['only-me','vault','people'].forEach(v => {
          const card = document.getElementById('vm-card-' + v);
          if (!card) return;
          card.className = 'share-card' + (v === val ? ' active-' + v : '');
          card.querySelector('input').checked = v === val;
        });
        const pp = document.getElementById('vm-people');
        if (pp) pp.style.display = val === 'people' ? 'block' : 'none';
      }

      async function saveVisibility() {
        const vis = document.querySelector('#vis-modal input[name=mvis]:checked')?.value || 'only-me';
        const sel = document.getElementById('vm-users');
        const allowed = sel ? Array.from(sel.selectedOptions).map(o => o.value).join(',') : '';
        if (vis === 'people' && sel && !allowed) {
          return alert('Please select at least one person, or choose a different visibility.');
        }
        const btn = document.getElementById('vm-save-btn');
        btn.textContent = 'Saving…'; btn.disabled = true;
        const res = await fetch('/vault/api/update-visibility', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ key: _modalKey, visibility: vis, allowed_users: allowed })
        });
        if (res.ok) location.reload();
        else { alert('Error: ' + await res.text()); btn.textContent = 'Save'; btn.disabled = false; }
      }
    <\/script>
  </body></html > `;
}

// ── ADMIN PANEL ────────────────────────────────────────────────────────────────
function renderAdmin(user, userList, allFiles) {
  const roleOpts = (current) => ['viewer', 'member', 'owner'].map(v => {
    const rm = ROLE_META[v];
    return `<option value="${v}" ${normalizeRole(current) === v ? 'selected' : ''}>${rm.icon} ${rm.label}</option>`;
  }).join('');

  const userRows = userList.map(u => {
    const nr = normalizeRole(u.role);
    const rm = ROLE_META[nr] || ROLE_META.viewer;
    const isMe = u.username === user.username;
    return `<tr>
      <td>
        <strong>${u.username}</strong>
        ${isMe ? `<span style="font-size:0.75em;color:var(--txt-dim);margin-left:6px">(you)</span>` : ''}
      </td>
      <td>
        <span class="role-badge" style="background:${rm.bg};color:${rm.color};border:1px solid ${rm.border}">${rm.icon} ${rm.label}</span>
      </td>
      <td>
        ${!isMe ? `
        <form onsubmit="event.preventDefault();updateRole(this)" style="display:flex;gap:6px">
          <input type="hidden" name="action" value="update-role">
          <input type="hidden" name="u" value="${u.username}">
          <select name="r" style="width:auto;padding:6px 10px;font-size:0.83em;height:auto">${roleOpts(u.role)}</select>
          <button class="btn-sm" type="submit">Save</button>
          <button type="button" class="btn-sm btn-del" onclick="deleteUser('${u.username}')">Delete</button>
        </form>` : `<span style="color:var(--txt-dim);font-size:0.85em">Cannot edit yourself</span>`}
      </td>
    </tr>`;
  }).join('');

  const fileRows = allFiles.map(f => {
    const rm = ROLE_META[f.uploaderRole] || ROLE_META.viewer;
    return `<tr>
      <td style="max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
        <a href="/vault/file/${encodeURIComponent(f.key)}" target="_blank">📄 ${f.key}</a>
      </td>
      <td><span class="uploader-tag" style="background:${rm.bg};color:${rm.color};border:1px solid ${rm.border}">${f.uploader}</span></td>
      <td>${visPill(f.visibility)}${f.visibility === 'people' && f.allowed_users ? `<small style="color:var(--txt-dim);margin-left:6px">${f.allowed_users}</small>` : ''}</td>
      <td><small style="color:var(--txt-dim)">${(f.size / 1024).toFixed(1)} KB</small></td>
      <td><button class="btn-del btn-sm" onclick="delFile('${f.key}')">✕</button></td>
    </tr>`;
  }).join('');

  return HEAD('111 Vault — Admin') + `<body>
    <header>${renderHeader(user)}</header>

    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px">
        <div class="section-title" style="margin:0">👥 Users <span style="font-size:0.7em;color:var(--txt-dim);font-weight:400">${userList.length} accounts</span></div>
        <a href="/vault" class="btn-ghost" style="padding:8px 14px;font-size:0.85em;border-radius:8px;text-decoration:none;color:var(--txt-muted);border:1px solid var(--border);background:rgba(255,255,255,0.04)">← Back to Vault</a>
      </div>

      <div style="background:var(--card2);border-radius:12px;padding:16px;margin-bottom:20px;border:1px solid var(--border)">
        <div style="font-size:0.85em;font-weight:600;color:var(--txt-muted);margin-bottom:12px">Create new account</div>
        <form onsubmit="event.preventDefault();createUser(this)">
          <div style="display:grid;grid-template-columns:1fr 1fr 1fr auto;gap:8px">
            <input type="hidden" name="action" value="create">
            <input type="text"     name="u" placeholder="Username"  required style="margin:0">
            <input type="password" name="p" placeholder="Password"  required style="margin:0">
            <select name="r" style="margin:0">
              <option value="viewer" >👁 Viewer — PDF only</option>
              <option value="member">📁 Member — All files</option>
              <option value="owner" >🔑 Owner — Full control</option>
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
      <div class="section-title" style="margin-bottom:16px">📂 All Files <span style="font-size:0.7em;color:var(--txt-dim);font-weight:400">${allFiles.length} files</span></div>
      <table>
        <thead><tr><th>File</th><th>Owner</th><th>Visibility</th><th>Size</th><th></th></tr></thead>
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
        if (res.ok) {
          const btn = form.querySelector('button[type=submit]');
          btn.textContent = '✓'; btn.style.background = '#10b981';
          setTimeout(() => location.reload(), 700);
        } else alert('Error: ' + await res.text());
      }
      async function deleteUser(name) {
        if (!confirm('Delete user "' + name + '"? This cannot be undone.')) return;
        const fd = new FormData(); fd.append('action','delete'); fd.append('u', name);
        const res = await fetch('/vault/api/users', {method:'POST', body: fd});
        if (res.ok) location.reload(); else alert(await res.text());
      }
      async function delFile(key) {
        if (!confirm('Delete "' + key + '"?')) return;
        const res = await fetch('/vault/api/delete/' + encodeURIComponent(key));
        if (res.ok) location.reload(); else alert(await res.text());
      }
    <\/script>
  </body></html>`;
}