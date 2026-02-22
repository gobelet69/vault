/**
 * VAULT — Cloud Storage with Folders
 * Folders: R2 key prefixes + .folder:{path} metadata objects
 * Permissions: file → parent folder → ancestor → private (recursive)
 */

// ── ROLE HELPERS ──────────────────────────────────────────────────────────────
function normalizeRole(r) { if (r === 'admin') return 'owner'; if (r === 'guest+') return 'member'; if (r === 'guest') return 'viewer'; return r || 'viewer'; }
function isOwner(u) { return normalizeRole(u.role) === 'owner'; }
function isMember(u) { return ['owner', 'member'].includes(normalizeRole(u.role)); }
const ROLE_META = { owner: { label: 'Owner', color: '#f43f5e', bg: 'rgba(244,63,94,0.15)', border: 'rgba(244,63,94,0.3)', icon: '🔑' }, member: { label: 'Member', color: '#6366f1', bg: 'rgba(99,102,241,0.15)', border: 'rgba(99,102,241,0.3)', icon: '📁' }, viewer: { label: 'Viewer', color: '#94a3b8', bg: 'rgba(148,163,184,0.1)', border: 'rgba(148,163,184,0.2)', icon: '👁' } };
const ROLE_PERMS = { owner: ['Upload any file type', 'Delete any file', 'Share files', 'Manage users & roles', 'Access admin panel'], member: ['Upload any file type', 'Delete own files', 'Share files'], viewer: ['Upload PDF files only', 'Delete own files'] };
const VIS_META = {
  'only-me': { label: 'Only me', icon: '🔒', color: '#64748b' },
  'vault': { label: 'Everyone in vault', icon: '🏢', color: '#10b981' },
  'people': { label: 'Specific people', icon: '👥', color: '#6366f1' },
  'public': { label: 'Public (anyone)', icon: '🌐', color: '#f59e0b' }
};

// ── VISIBILITY HELPERS ────────────────────────────────────────────────────────
function normalizeVis(v) { if (v === 'specific') return 'people'; if (v === 'private') return 'only-me'; if (v === 'inherit') return 'only-me'; return v || 'only-me'; }
function chkVis(user, vis, au, owner) {
  if (vis === 'public' || vis === 'vault') return true;
  if (!user) return false;
  if ((owner || '') === user.username) return true;
  if (vis === 'people') return (au || '').split(',').map(s => s.trim()).filter(Boolean).includes(user.username);
  return false;
}
// Get effective visibility for a key (folder overrides file for files inside folders)
async function effVis(key, meta, env) {
  let vis = normalizeVis(meta.visibility || 'only-me'), au = meta.allowed_users || '', owner = meta.uploader || '';
  if (key.includes('/')) {
    try {
      const fm = await env.BUCKET.head('.folder:' + key.split('/').slice(0, -1).join('/'));
      if (fm?.customMetadata?.visibility) { vis = normalizeVis(fm.customMetadata.visibility); au = fm.customMetadata.allowed_users || ''; owner = fm.customMetadata.uploader || ''; }
    } catch (e) { }
  }
  return { vis, au, owner };
}
async function resolveAccess(user, key, meta, env) {
  const e = await effVis(key, meta, env);
  if (e.vis === 'public') return true;
  if (!user) return false;
  if (isOwner(user)) return true;
  return chkVis(user, e.vis, e.au, e.owner);
}

function canSeeFolder(user, f) {
  if (isOwner(user)) return true;
  const vis = normalizeVis(f.visibility || 'only-me');
  if (vis === 'public' || vis === 'vault') return true;
  if ((f.uploader || '') === user.username) return true;
  if (vis === 'people') return (f.allowed_users || '').split(',').map(s => s.trim()).filter(Boolean).includes(user.username);
  return false;
}

// ── WORKER ────────────────────────────────────────────────────────────────────
export default {
  async fetch(req, env) {
    const url = new URL(req.url), method = req.method;
    const cookie = req.headers.get('Cookie') || '';
    const sid = cookie.split(';').find(c => c.trim().startsWith('sess='))?.split('=')[1];
    let user = null;
    if (sid) { try { const sess = await env.AUTH_DB.prepare('SELECT * FROM sessions WHERE id=? AND expires>?').bind(sid, Date.now()).first(); if (sess) { user = sess; const du = await env.AUTH_DB.prepare('SELECT role FROM users WHERE username=?').bind(sess.username).first(); user.role = du?.role || 'viewer'; } } catch (e) { } }

    // SERVE FILE (before auth — public files work without login)
    if (url.pathname.startsWith('/vault/file/')) {
      const key = decodeURIComponent(url.pathname.replace('/vault/file/', ''));
      const obj = await env.BUCKET.get(key);
      if (!obj) return new Response('404', { status: 404 });
      const m = obj.customMetadata || {};
      const ev = await effVis(key, m, env);
      if (ev.vis !== 'public' && !user) return new Response(null, { status: 302, headers: { Location: `/auth/login?redirect=${encodeURIComponent(url.pathname)}` } });
      if (ev.vis !== 'public' && !isOwner(user) && !chkVis(user, ev.vis, ev.au, ev.owner)) return new Response('Access denied', { status: 403 });
      const h = new Headers(); obj.writeHttpMetadata(h); h.set('etag', obj.httpEtag);
      const ext = key.split('.').pop().toLowerCase();
      const types = { pdf: 'application/pdf', jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', gif: 'image/gif', txt: 'text/plain', mp4: 'video/mp4', webp: 'image/webp' };
      h.set('Content-Type', types[ext] || 'application/octet-stream');
      return new Response(obj.body, { headers: h });
    }

    if (!user) return new Response(null, { status: 302, headers: { Location: `/auth/login?redirect=${encodeURIComponent(url.pathname)}` } });

    // UPLOAD
    if (url.pathname === '/vault/api/upload' && method === 'POST') {
      const orig = req.headers.get('X-File-Name');
      if (!orig) return new Response('Missing filename', { status: 400 });
      if (!isMember(user) && !orig.toLowerCase().endsWith('.pdf')) return new Response('Viewers can only upload PDF files.', { status: 403 });
      const folder = (req.headers.get('X-Folder') || '').trim().replace(/\/$/, '');
      // Folder permission overrides whatever the user chose
      let vis = req.headers.get('X-Visibility') || 'only-me';
      let au = req.headers.get('X-Allowed-Users') || '';
      if (folder) {
        try {
          const fm = await env.BUCKET.head('.folder:' + folder);
          if (fm?.customMetadata?.visibility) { vis = normalizeVis(fm.customMetadata.visibility); au = fm.customMetadata.allowed_users || ''; }
        } catch (e) { }
      }
      try {
        let base = orig.replace(/[^\x00-\x7F]/g, '').trim();
        let key = folder ? `${folder}/${base}` : base, c = 1;
        while (await env.BUCKET.head(key)) { const d = base.lastIndexOf('.'); const b = d !== -1 ? `${base.slice(0, d)} (${c})${base.slice(d)}` : `${base} (${c})`; key = folder ? `${folder}/${b}` : b; c++; }
        await env.BUCKET.put(key, req.body, { customMetadata: { uploader: user.username, role: normalizeRole(user.role), visibility: vis, allowed_users: au } });
        return new Response('OK');
      } catch (e) { return new Response('Upload failed: ' + e.message, { status: 500 }); }
    }

    // CREATE FOLDER
    if (url.pathname === '/vault/api/create-folder' && method === 'POST') {
      try {
        const { name, parentPath } = await req.json();
        if (!name || name.includes('/') || name.startsWith('.')) return new Response('Invalid folder name', { status: 400 });
        const path = parentPath ? `${parentPath}/${name}` : name;
        await env.BUCKET.put('.folder:' + path, '', { customMetadata: { uploader: user.username, visibility: 'only-me', allowed_users: '' } });
        return new Response(path);
      } catch (e) { return new Response(e.message, { status: 500 }); }
    }

    // DELETE FOLDER
    if (url.pathname === '/vault/api/delete-folder' && method === 'POST') {
      try {
        const { path } = await req.json();
        const fm = await env.BUCKET.head('.folder:' + path);
        if (fm && !isOwner(user) && fm.customMetadata?.uploader !== user.username) return new Response('Forbidden', { status: 403 });
        let cur;
        do { const lst = await env.BUCKET.list({ prefix: path + '/', cursor: cur }); for (const o of lst.objects) await env.BUCKET.delete(o.key); cur = lst.truncated ? lst.cursor : null; } while (cur);
        const ml = await env.BUCKET.list({ prefix: '.folder:' + path }); for (const o of ml.objects) await env.BUCKET.delete(o.key);
        return new Response('OK');
      } catch (e) { return new Response(e.message, { status: 500 }); }
    }

    // DELETE FILE
    if (url.pathname.startsWith('/vault/api/delete/')) {
      const key = decodeURIComponent(url.pathname.replace('/vault/api/delete/', ''));
      const obj = await env.BUCKET.head(key);
      if (!obj) return new Response('Not found', { status: 404 });
      if (!isOwner(user) && obj.customMetadata?.uploader !== user.username) return new Response('Permission denied', { status: 403 });
      await env.BUCKET.delete(key); return new Response('Deleted');
    }

    // UPDATE VISIBILITY
    if (url.pathname === '/vault/api/update-visibility' && method === 'POST') {
      try {
        const { key, visibility, allowed_users } = await req.json();
        const obj = await env.BUCKET.get(key);
        if (!obj) return new Response('Not found', { status: 404 });
        if (!isOwner(user) && obj.customMetadata?.uploader !== user.username) return new Response('Permission denied', { status: 403 });
        await env.BUCKET.put(key, obj.body, { customMetadata: { ...obj.customMetadata, visibility, allowed_users: allowed_users || '' } });
        return new Response('OK');
      } catch (e) { return new Response(e.message, { status: 500 }); }
    }

    // USER MANAGEMENT
    if (url.pathname === '/vault/api/users' && method === 'POST') {
      if (!isOwner(user)) return new Response('Forbidden', { status: 403 });
      try {
        const fd = await req.formData(), action = fd.get('action');
        if (action === 'create') { const pw = await hash(fd.get('p')); await env.AUTH_DB.prepare('INSERT OR REPLACE INTO users(username,password,role,created_at)VALUES(?,?,?,?)').bind(fd.get('u'), pw, fd.get('r'), new Date().toISOString()).run(); }
        if (action === 'delete') await env.AUTH_DB.prepare('DELETE FROM users WHERE username=?').bind(fd.get('u')).run();
        if (action === 'update-role') await env.AUTH_DB.prepare('UPDATE users SET role=? WHERE username=?').bind(fd.get('r'), fd.get('u')).run();
        return new Response('OK');
      } catch (e) { return new Response(e.message, { status: 500 }); }
    }

    // MOVE FILE
    if (url.pathname === '/vault/api/move' && method === 'POST') {
      try {
        const { oldKey, newFolder } = await req.json();
        const obj = await env.BUCKET.get(oldKey);
        if (!obj) return new Response('Not found', { status: 404 });
        if (!isOwner(user) && obj.customMetadata?.uploader !== user.username) return new Response('Forbidden', { status: 403 });
        const fname = oldKey.split('/').pop();
        const newKey = newFolder ? newFolder + '/' + fname : fname;
        if (newKey === oldKey) return new Response('Same location', { status: 400 });
        await env.BUCKET.put(newKey, obj.body, { customMetadata: obj.customMetadata });
        await env.BUCKET.delete(oldKey);
        return new Response('OK');
      } catch (e) { return new Response(e.message, { status: 500 }); }
    }

    // ADMIN PANEL
    if (url.pathname === '/vault/admin') {
      if (!isOwner(user)) return new Response('Forbidden', { status: 403 });
      const { results: ul } = await env.AUTH_DB.prepare('SELECT username,role FROM users ORDER BY username').all();
      const lst = await env.BUCKET.list({ include: ['customMetadata'] });
      const af = lst.objects.filter(o => !o.key.startsWith('.folder:')).map(o => ({ key: o.key, size: o.size, uploader: o.customMetadata?.uploader || '?', uploaderRole: normalizeRole(o.customMetadata?.role || 'viewer'), visibility: normalizeVis(o.customMetadata?.visibility || 'only-me'), allowed_users: o.customMetadata?.allowed_users || '' }));
      return new Response(renderAdmin(user, ul, af), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }

    // DASHBOARD
    if (url.pathname === '/vault' || url.pathname === '/vault/') {
      const cp = url.searchParams.get('path') || '';
      // Guard: check user can access the requested folder path
      if (cp) {
        const cfm = await env.BUCKET.head('.folder:' + cp);
        const cfMeta = { visibility: cfm?.customMetadata?.visibility || 'only-me', allowed_users: cfm?.customMetadata?.allowed_users || '', uploader: cfm?.customMetadata?.uploader || '' };
        if (!canSeeFolder(user, cfMeta)) return new Response(null, { status: 302, headers: { Location: '/vault' } });
      }
      const prefix = cp ? cp + '/' : '';
      const listing = await env.BUCKET.list({ prefix, delimiter: '/', include: ['customMetadata'] });
      const foldersRaw = await Promise.all((listing.delimitedPrefixes || []).map(async fp => {
        const p = fp.slice(0, -1), name = p.replace(prefix, '');
        const fm = await env.BUCKET.head('.folder:' + p);
        return { name, path: p, visibility: normalizeVis(fm?.customMetadata?.visibility || 'only-me'), allowed_users: fm?.customMetadata?.allowed_users || '', uploader: fm?.customMetadata?.uploader || '' };
      }));
      // Filter to only show folders the user can access
      const folders = foldersRaw.filter(f => canSeeFolder(user, f));
      const vf = [];
      for (const o of listing.objects) {
        if (o.key.startsWith('.folder:')) continue;
        const m = o.customMetadata || {};
        if (await resolveAccess(user, o.key, m, env)) vf.push({ key: o.key, size: o.size, uploader: m.uploader || '?', uploaderRole: normalizeRole(m.role || 'viewer'), visibility: normalizeVis(m.visibility || 'only-me'), allowed_users: m.allowed_users || '' });
      }
      const { results: ul } = await env.AUTH_DB.prepare('SELECT username,role FROM users ORDER BY username').all();
      return new Response(renderDash(user, vf, folders, ul, cp), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }


    return new Response('404', { status: 404 });
  }
};

async function hash(str) { const buf = new TextEncoder().encode(str); const h = await crypto.subtle.digest('SHA-256', buf); return Array.from(new Uint8Array(h)).map(b => b.toString(16).padStart(2, '0')).join(''); }

// ── STYLES ────────────────────────────────────────────────────────────────────
const CSS = `
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
:root{--bg:#0f1117;--card:#161b22;--card2:#1c2130;--txt:#f8fafc;--muted:#94a3b8;--dim:#475569;--p:#6366f1;--ph:#4f46e5;--s:#0ea5e9;--err:#f43f5e;--good:#10b981;--warn:#f59e0b;--border:rgba(255,255,255,0.07);--ring:rgba(99,102,241,0.4)}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Inter',sans-serif;background:var(--bg);color:var(--txt);max-width:1020px;margin:0 auto;padding:24px;line-height:1.5}
a{color:var(--p);text-decoration:none} a:hover{color:var(--s)}
input,select{background:rgba(0,0,0,0.25);border:1px solid var(--border);color:var(--txt);padding:9px 13px;border-radius:9px;font-family:inherit;font-size:0.92em;transition:border-color .2s,box-shadow .2s;width:100%}
input:focus,select:focus{outline:none;border-color:var(--p);box-shadow:0 0 0 3px var(--ring)}
button{cursor:pointer;background:var(--p);color:#fff;font-weight:600;border:none;padding:9px 16px;border-radius:9px;transition:all .2s;font-family:inherit;font-size:0.92em}
button:hover{background:var(--ph);transform:translateY(-1px)}
.card{background:var(--card);padding:22px;border-radius:16px;margin-bottom:18px;border:1px solid var(--border);box-shadow:0 6px 28px rgba(0,0,0,0.2)}
header{display:flex;justify-content:space-between;align-items:center;min-height:64px;padding:0 24px;background:var(--card);border:1px solid var(--border);margin-bottom:24px;border-radius:16px;box-shadow:0 4px 20px rgba(0,0,0,0.25);gap:12px}
.user-wrap{position:relative}
.user-btn{display:flex;align-items:center;gap:8px;color:var(--txt);font-size:0.9em;font-weight:500;padding:8px 13px;border-radius:9px;background:rgba(255,255,255,0.05);border:1px solid var(--border);cursor:pointer;transition:background .2s;font-family:inherit}
.user-btn:hover{background:rgba(255,255,255,0.09)}
.caret{opacity:.5;transition:transform .2s;margin-left:2px}
.user-wrap.open .caret{transform:rotate(180deg)}
.dd{display:none;position:absolute;right:0;top:calc(100% + 10px);background:#151c28;border:1px solid var(--border);border-radius:14px;min-width:240px;box-shadow:0 20px 56px rgba(0,0,0,0.6);z-index:999;overflow:hidden}
.user-wrap.open .dd{display:block;animation:dd .15s ease-out}
@keyframes dd{from{opacity:0;transform:translateY(-5px)}to{opacity:1;transform:translateY(0)}}
.dd-hdr{padding:15px 17px 13px;border-bottom:1px solid var(--border)}
.dd-name{font-weight:700;font-size:.98em;margin-bottom:7px}
.role-badge{display:inline-flex;align-items:center;gap:5px;font-size:.72em;font-weight:700;padding:3px 10px;border-radius:20px;letter-spacing:.03em;margin-bottom:9px}
.perm-list{list-style:none}
.perm-list li{font-size:.77em;color:var(--muted);padding:2px 0;display:flex;align-items:center;gap:6px}
.perm-list li.ok{color:#cbd5e1}
.pcheck{width:14px;height:14px;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;flex-shrink:0;font-size:9px;font-weight:700}
.pcheck.y{background:rgba(16,185,129,.2);color:var(--good)} .pcheck.n{background:rgba(148,163,184,.1);color:var(--dim)}
.ddl{display:flex;align-items:center;gap:10px;padding:11px 17px;color:var(--txt);text-decoration:none;font-size:.9em;font-weight:500;transition:background .15s}
.ddl:hover{background:rgba(255,255,255,.05);color:var(--txt)}
.dd-sep{height:1px;background:var(--border);margin:4px 0}
.ddl.out{color:var(--err)!important} .ddl.out:hover{background:rgba(244,63,94,.08)!important}
/* BREADCRUMB */
.bc{display:flex;align-items:center;gap:4px;font-size:.85em;color:var(--muted);margin-bottom:16px;flex-wrap:wrap}
.bc a{color:var(--muted);font-weight:500} .bc a:hover{color:var(--txt)}
.bc-sep{color:var(--dim)}
/* TOOLBAR */
.toolbar{display:flex;gap:8px;align-items:center;margin-bottom:16px;flex-wrap:wrap}
.btn-ghost{background:rgba(255,255,255,.05);color:var(--muted);border:1px solid var(--border);box-shadow:none}
.btn-ghost:hover{background:rgba(255,255,255,.1);transform:none}
/* FOLDER GRID */
.folder-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:10px;margin-bottom:20px}
.folder-card{background:var(--card2);border:1px solid var(--border);border-radius:12px;padding:14px 16px;cursor:pointer;transition:all .18s;position:relative;display:flex;flex-direction:column;gap:6px}
.folder-card:hover{border-color:var(--p);background:#212840}
.folder-icon{font-size:1.8em;line-height:1}
.folder-name{font-weight:600;font-size:.88em;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.folder-actions{display:flex;gap:4px;position:absolute;top:8px;right:8px;opacity:0;transition:opacity .15s}
.folder-card:hover .folder-actions{opacity:1}
/* FILE TABLE */
.ftable{width:100%;border-collapse:collapse}
.ftable th{text-align:left;padding:9px 12px;font-size:.74em;font-weight:600;color:var(--muted);letter-spacing:.06em;text-transform:uppercase;border-bottom:1px solid var(--border)}
.ftable td{padding:11px 12px;border-bottom:1px solid var(--border);font-size:.9em;vertical-align:middle}
.ftable tr:last-child td{border-bottom:none}
.ftable tr:hover td{background:rgba(255,255,255,.015)}
.ftable tr.crow{cursor:pointer}.ftable tr.fcrow{cursor:grab}.ftable tr.fcrow:active{cursor:grabbing}
.ftable tr.dr td{background:rgba(99,102,241,.1)!important;outline:2px dashed var(--p)}
.bc-link{padding:3px 8px;border-radius:8px;transition:background .15s}
.bc-link.bc-hi{background:rgba(99,102,241,.18);outline:2px dashed var(--p)}
/* TAGS + PILLS */
.tag{font-size:.72em;font-weight:600;padding:2px 9px;border-radius:20px;letter-spacing:.02em;white-space:nowrap}
.vpill{font-size:.7em;font-weight:600;padding:3px 9px;border-radius:20px;display:inline-flex;align-items:center;gap:4px;white-space:nowrap}
.vp-only-me{background:rgba(100,116,139,.1);color:#64748b;border:1px solid rgba(100,116,139,.2)}
.vp-vault{background:rgba(16,185,129,.1);color:var(--good);border:1px solid rgba(16,185,129,.2)}
.vp-people{background:rgba(99,102,241,.12);color:#a5b4fc;border:1px solid rgba(99,102,241,.2)}
.vp-inherit{background:rgba(245,158,11,.1);color:var(--warn);border:1px solid rgba(245,158,11,.2)}
.vp-public{background:rgba(245,158,11,.1);color:var(--warn);border:1px solid rgba(245,158,11,.2)}
/* BTNS */
.btn-sm{padding:5px 10px;font-size:.8em;border-radius:7px}
.btn-del{background:rgba(244,63,94,.1);color:var(--err);border:1px solid rgba(244,63,94,.2)} .btn-del:hover{background:rgba(244,63,94,.2);transform:none}
.btn-edit{background:rgba(255,255,255,.05);color:var(--muted);border:1px solid var(--border)} .btn-edit:hover{background:rgba(255,255,255,.1);transform:none}
.btn-share{background:rgba(99,102,241,.1);color:#a5b4fc;border:1px solid rgba(99,102,241,.25)} .btn-share:hover{background:rgba(99,102,241,.2);transform:none}
/* USER CHECKBOXES */
.user-check-list{display:flex;flex-direction:column;gap:6px;max-height:180px;overflow-y:auto;padding:4px 0}
.ucl-item{display:flex;align-items:center;gap:9px;padding:7px 10px;border-radius:8px;background:rgba(255,255,255,.03);border:1px solid var(--border);cursor:pointer;transition:background .15s}
.ucl-item:hover{background:rgba(99,102,241,.07)}
.ucl-item input[type=checkbox]{width:15px;height:15px;accent-color:var(--p);cursor:pointer;flex-shrink:0}
.ucl-item .ucl-name{font-size:.88em;font-weight:500}
.ucl-item .ucl-role{font-size:.73em;color:var(--muted);margin-left:auto}
/* SHARE MODAL URL BOX */
.share-url-box{display:flex;gap:6px;align-items:center;background:rgba(0,0,0,.25);border:1px solid var(--border);border-radius:9px;padding:8px 12px;margin-bottom:14px}
.share-url-box span{flex:1;font-size:.8em;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:monospace}
.share-url-box button{flex-shrink:0;padding:5px 11px;font-size:.78em}
/* SHARE CARDS */
.scards{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin:12px 0}
.scard{position:relative;padding:12px 14px;border-radius:11px;border:2px solid var(--border);background:rgba(255,255,255,.02);cursor:pointer;transition:all .18s;user-select:none}
.scard:hover{background:rgba(255,255,255,.04)}
.scard input[type=radio]{position:absolute;opacity:0;pointer-events:none}
.scard.ac-only-me{border-color:#64748b;background:rgba(100,116,139,.08)}
.scard.ac-vault{border-color:var(--good);background:rgba(16,185,129,.07)}
.scard.ac-people{border-color:var(--p);background:rgba(99,102,241,.08)}
.scard.ac-public{border-color:var(--warn);background:rgba(245,158,11,.07)}
.si{font-size:1.3em;margin-bottom:4px;display:block}
.st{font-size:.82em;font-weight:700;color:var(--txt);margin-bottom:2px}
.sd{font-size:.71em;color:var(--muted);line-height:1.35}
/* TOOLTIP */
.tipw{position:relative;display:inline-flex;align-items:center;gap:4px}
.tipi{width:15px;height:15px;border-radius:50%;background:rgba(255,255,255,.08);border:1px solid var(--border);display:inline-flex;align-items:center;justify-content:center;font-size:10px;font-weight:700;color:var(--muted);cursor:help}
.tipb{display:none;position:absolute;left:50%;transform:translateX(-50%);top:calc(100% + 7px);background:#0d1117;border:1px solid rgba(255,255,255,.12);border-radius:9px;padding:9px 12px;width:210px;font-size:.77em;color:#cbd5e1;line-height:1.5;z-index:100;box-shadow:0 14px 36px rgba(0,0,0,.5);pointer-events:none}
.tipw:hover .tipb{display:block}
/* MODALS */
.modal-bg{display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:1000;align-items:center;justify-content:center;padding:20px;backdrop-filter:blur(4px)}
.modal-box{background:#161b22;border:1px solid rgba(255,255,255,.1);border-radius:18px;padding:26px;width:100%;max-width:520px;box-shadow:0 28px 72px rgba(0,0,0,.7)}
/* UPLOAD PROGRESS */
.bar-wrap{height:5px;background:rgba(0,0,0,.3);margin-top:12px;border-radius:3px;overflow:hidden;border:1px solid var(--border)}
.bar{height:100%;background:var(--p);width:0%;transition:width .2s;box-shadow:0 0 8px var(--p)}
/* DRAG DROP */
.dz{border:2px dashed var(--border);border-radius:14px;padding:36px 24px;text-align:center;cursor:pointer;transition:all .2s;background:rgba(255,255,255,.01)}
.dz:hover{border-color:rgba(99,102,241,.5);background:rgba(99,102,241,.04)}
.dz.over{border-color:var(--p);background:rgba(99,102,241,.08);transform:scale(1.01)}
.drop-overlay{display:none;position:fixed;inset:0;background:rgba(99,102,241,.12);z-index:2000;align-items:center;justify-content:center;flex-direction:column;gap:16px;pointer-events:none}
.drop-overlay.show{display:flex}
.drop-ring{width:160px;height:160px;border-radius:50%;border:4px dashed rgba(99,102,241,.7);display:flex;align-items:center;justify-content:center;font-size:3em;animation:pulse 1s infinite alternate}
@keyframes pulse{from{transform:scale(1);opacity:.8}to{transform:scale(1.06);opacity:1}}
.drop-label{color:#a5b4fc;font-size:1.3em;font-weight:700;letter-spacing:-.01em}
/* NEW FOLDER FORM */
.nf-form{display:none;background:var(--card2);border:1px solid var(--border);border-radius:12px;padding:16px;margin-bottom:14px;align-items:center;gap:8px;flex-wrap:wrap}
.nf-form.open{display:flex}
/* ADMIN */
table{width:100%;border-collapse:collapse}
th{text-align:left;padding:10px 12px;font-size:.75em;font-weight:600;color:var(--muted);letter-spacing:.06em;text-transform:uppercase;border-bottom:1px solid var(--border)}
td{padding:11px 12px;border-bottom:1px solid var(--border);font-size:.9em;vertical-align:middle}
tr:last-child td{border-bottom:none} tr:hover td{background:rgba(255,255,255,.015)}
`;

const FAVICON = `data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Cdefs%3E%3ClinearGradient id='g' x1='0' y1='0' x2='1' y2='1'%3E%3Cstop offset='0' stop-color='%236366f1'/%3E%3Cstop offset='1' stop-color='%23f43f5e'/%3E%3C/linearGradient%3E%3C/defs%3E%3Crect width='32' height='32' rx='8' fill='url(%23g)'/%3E%3Ctext x='16' y='21' font-family='Arial,sans-serif' font-weight='900' font-size='12' fill='white' text-anchor='middle'%3E111%3C/text%3E%3C/svg%3E`;
const HEAD = t => `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${t}</title><link rel="icon" type="image/svg+xml" href="${FAVICON}"><style>${CSS}</style></head>`;

// ── COMPONENTS ────────────────────────────────────────────────────────────────
function visPill(v) { const m = VIS_META[v] || VIS_META['only-me']; return `<span class="vpill vp-${v}">${m.icon} ${m.label}</span>`; }
function utag(name, role) { const rm = ROLE_META[role] || ROLE_META.viewer; return `<span class="tag" style="background:${rm.bg};color:${rm.color};border:1px solid ${rm.border}">${name}</span>`; }
function tip(t) { return `<span class="tipw"><span class="tipi">?</span><span class="tipb">${t}</span></span>`; }
function esc(s) { return (s || '').replace(/'/g, "&#39;"); }

function renderHeader(user) {
  const role = normalizeRole(user.role), rm = ROLE_META[role] || ROLE_META.viewer, perms = ROLE_PERMS[role] || [];
  const all = ['Upload any file type', 'Delete any file', 'Share files', 'Manage users & roles', 'Access admin panel'];
  const id = 'vuw';
  return `<a href="/" style="text-decoration:none;display:flex;align-items:center;gap:10px;flex-shrink:0">
    <span style="width:36px;height:36px;background:linear-gradient(135deg,#6366f1,#f43f5e);border-radius:10px;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:.9em;color:#fff;flex-shrink:0;box-shadow:0 0 18px rgba(99,102,241,.5)">111</span>
    <div style="display:flex;flex-direction:column;line-height:1.25">
      <span style="font-weight:700;font-size:1.1em;color:#fff;letter-spacing:-.02em">111<span style="color:#6366f1;text-shadow:0 0 20px rgba(99,102,241,.6)">iridescence</span></span>
      <span style="font-size:.72em;color:#94a3b8;font-weight:500;letter-spacing:.03em">Vault</span>
    </div>
  </a>
  <div style="display:flex;gap:8px;align-items:center;flex-shrink:0">
    ${isOwner(user) ? `<a href="/vault/admin" style="font-size:.82em;font-weight:600;padding:7px 13px;border-radius:8px;background:rgba(244,63,94,.1);color:#f43f5e;border:1px solid rgba(244,63,94,.2);display:inline-flex;align-items:center;gap:5px;text-decoration:none"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg>Admin</a>` : ''}
    <div class="user-wrap" id="${id}">
      <button class="user-btn" onclick="document.getElementById('${id}').classList.toggle('open')">
        ${user.username}<svg class="caret" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="6 9 12 15 18 9"/></svg>
      </button>
      <div class="dd">
        <div class="dd-hdr">
          <div class="dd-name">${user.username}</div>
          <span class="role-badge" style="background:${rm.bg};color:${rm.color};border:1px solid ${rm.border}">${rm.icon} ${rm.label}</span>
          <ul class="perm-list">${all.map(p => { const h = perms.includes(p); return `<li class="${h ? 'ok' : ''}"><span class="pcheck ${h ? 'y' : 'n'}">${h ? '✓' : '✕'}</span>${p}</li>`; }).join('')}</ul>
        </div>
        <a href="/auth/account" class="ddl"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 4-7 8-7s8 3 8 7"/></svg>Account Preferences</a>
        ${isOwner(user) ? `<a href="/vault/admin" class="ddl"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg>Admin Panel</a>` : ''}
        <div class="dd-sep"></div>
        <a href="/auth/logout" class="ddl out"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>Sign Out</a>
      </div>
    </div>
    <script>document.addEventListener('click',e=>{const w=document.getElementById('${id}');if(w&&!w.contains(e.target))w.classList.remove('open')});<\/script>
  </div>`;
}

function shareCards(currentVis, idPrefix) {
  const opts = ['only-me', 'vault', 'people', 'public'];
  const descs = { 'only-me': 'Only you and owners can open this.', 'vault': 'All vault members can see and download.', 'people': 'Only the people you select have access.', 'public': 'Anyone with the link can access — no login required.' };
  return opts.map(v => `<label class="scard${v === currentVis ? ' ac-' + v : ''}" id="${idPrefix}-${v}" onclick="${idPrefix}Sel('${v}')"><input type="radio" name="${idPrefix}vis" value="${v}"${v === currentVis ? ' checked' : ''}><span class="si">${VIS_META[v]?.icon}</span><div class="st">${VIS_META[v]?.label}</div><div class="sd">${descs[v]}</div></label>`).join('');
}

// ── DASHBOARD ─────────────────────────────────────────────────────────────────
function renderDash(user, files, folders, userList, currentPath) {
  const inFolder = currentPath.length > 0;
  const parts = currentPath ? currentPath.split('/') : [], prefix = currentPath ? currentPath + '/' : '';
  const bcLinks = [`<a href="/vault" class="bc-link" ondragover="event.preventDefault();this.classList.add('bc-hi')" ondragleave="this.classList.remove('bc-hi')" ondrop="dropMove(event,'')">🏠 Home</a>`, ...parts.map((_, i) => { const p = parts.slice(0, i + 1).join('/'); return `<span class="bc-sep">/</span><a href="/vault?path=${encodeURIComponent(p)}" class="bc-link" ondragover="event.preventDefault();this.classList.add('bc-hi')" ondragleave="this.classList.remove('bc-hi')" ondrop="dropMove(event,'${p}')">${parts[i]}</a>`; })].join('');
  const otherUsers = userList.filter(u => u.username !== user.username);
  const userOpts = otherUsers.map(u => { const rm = ROLE_META[normalizeRole(u.role)] || ROLE_META.viewer; return `<option value="${esc(u.username)}">${u.username} — ${rm.label}</option>`; }).join('');

  const folderCards = folders.map(f => `<div class="folder-card" onclick="navigate('${esc(f.path)}')">
    <div style="display:flex;align-items:flex-start;justify-content:space-between">
      <span class="folder-icon">📁</span>
      <div class="folder-actions">
        <button class="btn-sm btn-share" onclick="event.stopPropagation();openShare('.folder:${esc(f.path)}','${f.visibility}','${esc(f.allowed_users)}',true)" title="Share">🔗</button>
        ${isOwner(user) || f.uploader === user.username ? `<button class="btn-sm btn-del" onclick="event.stopPropagation();delFolder('${esc(f.path)}')" title="Delete folder">✕</button>` : ''}
      </div>
    </div>
    <div class="folder-name" title="${esc(f.name)}">${f.name}</div>
    ${visPill(f.visibility)}
  </div>`).join('');

  const fileRows = files.length === 0 ? `<tr><td colspan="5" style="text-align:center;color:var(--dim);padding:28px">No files here yet.</td></tr>` : files.map(f => {
    const canDel = isOwner(user) || f.uploader === user.username;
    const dispKey = inFolder ? f.key.replace(prefix, '') : f.key;
    return `<tr>
      <td style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"><a href="/vault/file/${encodeURIComponent(f.key)}" target="_blank">📄 ${dispKey}</a></td>
      <td>${utag(f.uploader, f.uploaderRole)}</td>
      <td>${visPill(f.visibility)}</td>
      <td style="color:var(--dim)">${(f.size / 1024).toFixed(1)} KB</td>
      <td><div style="display:flex;gap:4px">${(isOwner(user) || f.uploader === user.username) ? `<button class="btn-sm btn-edit" onclick="openVis('${esc(f.key)}','${f.visibility}','${esc(f.allowed_users)}')">✏️</button>` : ''} ${canDel ? `<button class="btn-sm btn-del" onclick="delFile('${esc(f.key)}')">✕</button>` : ''}</div></td>
    </tr>`;
  }).join('');

  const allRows = [
    ...folders.map(f => {
      const fOwnerRole = normalizeRole(userList.find(u => u.username === f.uploader)?.role || 'viewer');
      return `<tr class="crow" onclick="navigate('${esc(f.path)}')" ondragover="event.stopPropagation();event.preventDefault();this.classList.add('dr')" ondragleave="this.classList.remove('dr')" ondrop="dropMove(event,'${esc(f.path)}');this.classList.remove('dr')">
      <td><span style="margin-right:8px;font-size:1.1em">📁</span><strong>${f.name}</strong></td>
      <td>${f.uploader ? utag(f.uploader, fOwnerRole) : '<span style="color:var(--dim)">—</span>'}</td><td>${visPill(f.visibility)}</td><td style="color:var(--dim)">—</td>
      <td onclick="event.stopPropagation()"><span style="display:flex;gap:4px">
        <button class="btn-sm btn-share" onclick="openShare('.folder:${esc(f.path)}','${f.visibility}','${esc(f.allowed_users)}',true)" title="Share">🔗</button>
        ${isOwner(user) || f.uploader === user.username ? `<button class="btn-sm btn-del" onclick="delFolder('${esc(f.path)}')" title="Delete">✕</button>` : ''}
      </span></td>
    </tr>`;
    }),
    ...files.map(f => {
      const canAct = isOwner(user) || f.uploader === user.username;
      const disp = inFolder ? f.key.replace(prefix, '') : f.key;
      const icon = /\.(pdf)$/i.test(f.key) ? '📕' : /\.(png|jpg|jpeg|gif|webp)$/i.test(f.key) ? '🖼️' : /\.(mp4|mov|avi)$/i.test(f.key) ? '🎬' : '📄';
      return `<tr class="crow${canAct ? ' fcrow' : ''}" ${canAct ? `draggable="true" ondragstart="fileDrag(event,'${esc(f.key)}')"` : ''}>
        <td style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"><span style="margin-right:8px">${icon}</span><a href="/vault/file/${encodeURIComponent(f.key)}" target="_blank">${disp}</a></td>
        <td>${utag(f.uploader, f.uploaderRole)}</td><td>${visPill(f.visibility)}</td>
        <td style="color:var(--dim)">${(f.size / 1024).toFixed(1)} KB</td>
        <td><span style="display:flex;gap:4px">
          <button class="btn-sm btn-share" onclick="openShare('${esc(f.key)}','${f.visibility}','${esc(f.allowed_users)}',false)" title="Share">🔗</button>
          ${canAct ? `<button class="btn-sm btn-del" onclick="delFile('${esc(f.key)}')" title="Delete">✕</button>` : ''}
        </span></td>
      </tr>`;
    })
  ].join('');
  const emptyRow = `<tr><td colspan="5" style="text-align:center;color:var(--dim);padding:40px;cursor:pointer" onclick="document.getElementById('fi').click()"><div style="font-size:2em;margin-bottom:8px">☁️</div><div>Drop files here or <span style="color:var(--p)">click to upload</span></div>${!isMember(user) ? '<div style="font-size:.8em;margin-top:4px">PDF files only for your account</div>' : ''}</td></tr>`;

  return HEAD('111 Vault') + `<body>
  <header>${renderHeader(user)}</header>
  <div class="bc">${bcLinks}</div>

  <div class="toolbar">
    <button onclick="document.getElementById('fi').click()">⬆ Upload</button>
    <button class="btn-ghost" onclick="toggleNF()">📁 New Folder</button>
    ${inFolder ? `<span style="font-size:.82em;color:var(--dim)">Folder: <strong style="color:var(--muted)">${currentPath}</strong></span>` : ''}
  </div>
  <input type="file" id="fi" style="display:none" ${!isMember(user) ? 'accept=".pdf"' : ''} multiple onchange="filesSelected(this.files)">

  <div class="nf-form" id="nf-form">
    <input id="nf-name" placeholder="Folder name" style="flex:1;min-width:160px" onkeydown="if(event.key==='Enter')createFolder()">
    <button onclick="createFolder()">Create</button>
    <button class="btn-ghost" onclick="toggleNF()">Cancel</button>
  </div>

  <div id="up-settings" style="display:none" class="card">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
      <span id="up-filelist" style="font-size:.88em;font-weight:600;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:70%"></span>
      <button class="btn-ghost btn-sm" onclick="cancelUpload()">Cancel</button>
    </div>
    <div style="font-size:.85em;font-weight:600;color:var(--muted);margin-bottom:8px">Who can access?</div>
    <div class="scards" id="up-cards">${shareCards('only-me', 'up')}</div>
    <div id="up-picker" style="display:none;margin-top:8px">
      <div style="font-size:.83em;color:var(--muted);font-weight:500;margin-bottom:6px">Select people</div>
      <div class="user-check-list" id="up-users-list">${otherUsers.map(u => { const rm = ROLE_META[normalizeRole(u.role)] || ROLE_META.viewer; return `<label class="ucl-item"><input type="checkbox" name="up-user" value="${esc(u.username)}"><span class="ucl-name">${u.username}</span><span class="ucl-role">${rm.icon} ${rm.label}</span></label>`; }).join('')}</div>
    </div>
    <div class="bar-wrap"><div id="pb" class="bar"></div></div>
    <div style="display:flex;justify-content:space-between;align-items:center;margin-top:8px">
      <small id="st" style="color:var(--dim)">Ready</small>
      <button onclick="startUpload()">Start Upload</button>
    </div>
  </div>

  <div class="card" id="filedrop" ondragover="event.preventDefault();this.style.outline='2px dashed var(--p)'" ondragleave="this.style.outline=''" ondrop="handleFileDrop(event)">
    <table class="ftable"><thead><tr><th>Name</th><th>Owner</th><th>Access</th><th>Size</th><th></th></tr></thead>
    <tbody>${allRows || emptyRow}</tbody></table>
  </div>

  <!-- Share modal (unified) -->
  <div class="modal-bg" id="share-modal" onclick="if(event.target===this)closeShare()">
    <div class="modal-box">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px"><span style="font-weight:700">🔗 Share / Access</span><button onclick="closeShare()" style="background:none;border:none;color:var(--muted);font-size:1.1em;padding:4px 8px;cursor:pointer">✕</button></div>
      <div id="sm-fn" style="font-size:.82em;color:var(--dim);margin-bottom:14px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"></div>
      <div id="sm-url-wrap">
        <div style="font-size:.8em;font-weight:600;color:var(--muted);margin-bottom:6px">Link</div>
        <div class="share-url-box"><span id="sm-url" style="cursor:text;user-select:all"></span><button class="btn-sm" onclick="copyShareUrl()" id="sm-copy-btn">Copy</button></div>
      </div>
      <div style="font-size:.85em;font-weight:600;color:var(--muted);margin-bottom:8px">Who can access?</div>
      <div class="scards" id="sm-cards">${shareCards('only-me', 'sm')}</div>
      <div id="sm-picker" style="display:none;margin-top:8px">
        <div style="font-size:.83em;color:var(--muted);font-weight:500;margin-bottom:6px">Select people</div>
        <div class="user-check-list" id="sm-users-list"></div>
      </div>
      <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:18px">
        <button onclick="closeShare()" class="btn-ghost">Cancel</button>
        <button id="sm-save" onclick="saveShare()">Save changes</button>
      </div>
    </div>
  </div>

  <script>
    const CUR_PATH='${esc(currentPath)}';
    const IN_FOLDER=${inFolder};

    function navigate(p){location.href='/vault?path='+encodeURIComponent(p);}

    // Upload
    let _files=null;
    function filesSelected(fl){if(!fl||!fl.length)return;_files=fl;const names=Array.from(fl).map(f=>f.name).join(', ');document.getElementById('up-filelist').textContent=fl.length+' file'+(fl.length>1?'s':'')+': '+names;document.getElementById('up-settings').style.display='block';document.getElementById('up-settings').scrollIntoView({behavior:'smooth',block:'nearest'});}
    function cancelUpload(){_files=null;document.getElementById('up-settings').style.display='none';document.getElementById('pb').style.width='0%';document.getElementById('st').textContent='Ready';}
    function handleDrop(e){e.preventDefault();document.getElementById('dz').classList.remove('over');filesSelected(e.dataTransfer.files);}
    function upSel(v){
      ['only-me','vault','people','public'].forEach(x=>{const c=document.getElementById('up-'+x);if(c){c.className='scard'+(x===v?' ac-'+x:'');c.querySelector('input').checked=x===v;}});
      document.getElementById('up-picker').style.display=v==='people'?'block':'none';
    }
    async function startUpload(){
      if(!_files||!_files.length)return;
      const vis=document.querySelector('input[name=upvis]:checked')?.value||'inherit';
      const checked=document.querySelectorAll('input[name=up-user]:checked');
      const au=Array.from(checked).map(o=>o.value).join(',');
      if(vis==='people'&&!au)return alert('Select at least one person or choose a different option.');
      const files=Array.from(_files);
      let done=0;
      for(const f of files){
        document.getElementById('st').textContent='Uploading '+f.name+' ('+(done+1)+'/'+files.length+')';
        await new Promise((resolve,reject)=>{
          const xhr=new XMLHttpRequest();
          xhr.open('POST','/vault/api/upload',true);
          xhr.setRequestHeader('X-File-Name',f.name);
          xhr.setRequestHeader('X-Visibility',vis);
          xhr.setRequestHeader('X-Allowed-Users',au);
          xhr.setRequestHeader('X-Folder',CUR_PATH);
          xhr.upload.onprogress=e=>{if(e.lengthComputable){const p=e.loaded/e.total*100;document.getElementById('pb').style.width=((done/files.length+p/100/files.length)*100)+'%';}};
          xhr.onload=()=>{if(xhr.status===200){done++;resolve();}else reject(xhr.responseText);};
          xhr.onerror=()=>reject('Network error');
          xhr.send(f);
        }).catch(err=>{alert('Error uploading '+f.name+': '+err);});
      }
      location.reload();
    }
    // Full-page drag overlay
    let _dc=0,_dragKey=null;
    document.addEventListener('dragenter',e=>{if(e.dataTransfer.types.includes('Files')){_dc++;document.getElementById('drop-overlay').classList.add('show');}});
    document.addEventListener('dragleave',()=>{_dc--;if(_dc<=0){_dc=0;document.getElementById('drop-overlay').classList.remove('show');}});
    document.addEventListener('dragover',e=>e.preventDefault());
    document.addEventListener('drop',e=>{e.preventDefault();_dc=0;document.getElementById('drop-overlay').classList.remove('show');if(e.dataTransfer.files.length)filesSelected(e.dataTransfer.files);});
    // Handle drop on file table card
    function handleFileDrop(e){e.currentTarget.style.outline='';if(e.dataTransfer.files.length){filesSelected(e.dataTransfer.files);}}
    // File move by drag
    function fileDrag(e,key){_dragKey=key;e.dataTransfer.effectAllowed='move';e.dataTransfer.setData('text/plain',key);}
    function dropMove(e,targetFolder){
      e.preventDefault();e.stopPropagation();
      if(e.currentTarget.classList)e.currentTarget.classList.remove('dr','bc-hi');
      if(!_dragKey){return;}
      const srcDir=_dragKey.includes('/')?_dragKey.split('/').slice(0,-1).join('/'):'';
      if(srcDir===targetFolder){_dragKey=null;return;}
      const k=_dragKey;_dragKey=null;
      fetch('/vault/api/move',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({oldKey:k,newFolder:targetFolder})})
        .then(r=>r.ok?location.reload():r.text().then(t=>alert('Move failed: '+t)));
    }

    // New folder
    function toggleNF(){const f=document.getElementById('nf-form');f.classList.toggle('open');if(f.classList.contains('open'))document.getElementById('nf-name').focus();}
    async function createFolder(){
      const name=document.getElementById('nf-name').value.trim();
      if(!name)return alert('Enter a folder name.');
      const res=await fetch('/vault/api/create-folder',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,parentPath:CUR_PATH})});
      if(res.ok){const p=await res.text();location.href='/vault?path='+encodeURIComponent(p);}else alert(await res.text());
    }
    async function delFolder(path){
      if(!confirm('Delete folder "'+path+'" and ALL its contents? This cannot be undone.'))return;
      const res=await fetch('/vault/api/delete-folder',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path})});
      if(res.ok)location.reload();else alert(await res.text());
    }
    async function delFile(key){
      if(!confirm('Delete "'+key+'"?'))return;
      const res=await fetch('/vault/api/delete/'+encodeURIComponent(key));
      if(res.ok)location.reload();else alert(await res.text());
    }

    // Unified Share modal
    const ALL_USERS = ${JSON.stringify(otherUsers.map(u => ({ username: u.username, role: normalizeRole(u.role), label: (ROLE_META[normalizeRole(u.role)] || ROLE_META.viewer).label, icon: (ROLE_META[normalizeRole(u.role)] || ROLE_META.viewer).icon })))};
    let _smKey='';
    function openShare(key,curVis,curAU,isFolder){
      _smKey=key;
      const label=key.startsWith('.folder:')?key.replace('.folder:',''):key.split('/').pop();
      document.getElementById('sm-fn').textContent=(isFolder?'📁 ':'📄 ')+label;
      // URL — always shown: file URL for files, vault path URL for folders
      const urlEl=document.getElementById('sm-url');
      if(isFolder){
        const folderPath=key.replace('.folder:','');
        urlEl.textContent=location.origin+'/vault?path='+encodeURIComponent(folderPath);
      } else {
        urlEl.textContent=location.origin+'/vault/file/'+encodeURIComponent(key);
      }
      document.getElementById('sm-copy-btn').textContent='Copy';
      document.getElementById('sm-copy-btn').style.color='';
      // Build people list dynamically (avoids label nesting issues)
      const list=document.getElementById('sm-users-list');
      const selectedUsers=curAU?curAU.split(',').map(x=>x.trim()).filter(Boolean):[];
      list.innerHTML='';
      ALL_USERS.forEach(u=>{
        const row=document.createElement('div');
        row.className='ucl-item';
        const cb=document.createElement('input');
        cb.type='checkbox';
        cb.value=u.username;
        cb.checked=selectedUsers.includes(u.username);
        cb.style.cssText='width:15px;height:15px;accent-color:var(--p);cursor:pointer;flex-shrink:0';
        const nm=document.createElement('span');
        nm.className='ucl-name';
        nm.textContent=u.username;
        const rl=document.createElement('span');
        rl.className='ucl-role';
        rl.textContent=u.icon+' '+u.label;
        row.appendChild(cb);
        row.appendChild(nm);
        row.appendChild(rl);
        row.addEventListener('click',e=>{ if(e.target!==cb){cb.checked=!cb.checked;} });
        list.appendChild(row);
      });
      smSel(curVis);
      document.getElementById('share-modal').style.display='flex';document.body.style.overflow='hidden';
    }
    function smSel(v){
      ['only-me','vault','people','public'].forEach(x=>{const c=document.getElementById('sm-'+x);if(c){c.className='scard'+(x===v?' ac-'+x:'');c.querySelector('input').checked=x===v;}});
      const pp=document.getElementById('sm-picker');if(pp)pp.style.display=v==='people'?'block':'none';
    }
    function closeShare(){document.getElementById('share-modal').style.display='none';document.body.style.overflow='';}
    async function copyShareUrl(){
      const url=document.getElementById('sm-url').textContent;
      try{await navigator.clipboard.writeText(url);const btn=document.getElementById('sm-copy-btn');btn.textContent='Copied!';btn.style.color='var(--good)';setTimeout(()=>{btn.textContent='Copy';btn.style.color='';},2000);}catch(e){alert('Copy failed: '+e);}
    }
    async function saveShare(){
      const vis=document.querySelector('input[name=smvis]:checked')?.value||'only-me';
      const au=Array.from(document.querySelectorAll('#sm-users-list input[type=checkbox]:checked')).map(cb=>cb.value).join(',');
      if(vis==='people'&&!au)return alert('Select at least one person.');
      const btn=document.getElementById('sm-save');btn.textContent='Saving…';btn.disabled=true;
      const res=await fetch('/vault/api/update-visibility',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({key:_smKey,visibility:vis,allowed_users:au})});
      if(res.ok)location.reload();else{alert(await res.text());btn.textContent='Save changes';btn.disabled=false;}
    }
  <\/script>
  <div class="drop-overlay" id="drop-overlay"><div class="drop-ring">☁️</div><div class="drop-label">Drop files to upload</div></div>
</body></html>`;


}

// ── ADMIN PANEL ────────────────────────────────────────────────────────────────
function renderAdmin(user, userList, allFiles) {
  const ropts = cur => ['viewer', 'member', 'owner'].map(v => { const rm = ROLE_META[v]; return `<option value="${v}"${normalizeRole(cur) === v ? ' selected' : ''}>${rm.icon} ${rm.label}</option>`; }).join('');
  const urows = userList.map(u => { const nr = normalizeRole(u.role), rm = ROLE_META[nr] || ROLE_META.viewer, isMe = u.username === user.username; return `<tr><td><strong>${u.username}</strong>${isMe ? ` <span style="font-size:.75em;color:var(--dim)">(you)</span>` : ''}</td><td><span class="role-badge" style="background:${rm.bg};color:${rm.color};border:1px solid ${rm.border}">${rm.icon} ${rm.label}</span></td><td>${!isMe ? `<form onsubmit="event.preventDefault();updRole(this)" style="display:flex;gap:6px"><input type="hidden" name="action" value="update-role"><input type="hidden" name="u" value="${u.username}"><select name="r" style="width:auto;padding:5px 9px;font-size:.83em">${ropts(u.role)}</select><button class="btn-sm" type="submit">Save</button><button type="button" class="btn-sm btn-del" onclick="delUser('${esc(u.username)}')">Delete</button></form>` : `<span style="color:var(--dim);font-size:.85em">Cannot edit yourself</span>`}</td></tr>`; }).join('');
  const frows = allFiles.map(f => { const rm = ROLE_META[f.uploaderRole] || ROLE_META.viewer; return `<tr><td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"><a href="/vault/file/${encodeURIComponent(f.key)}" target="_blank">📄 ${f.key}</a></td><td>${utag(f.uploader, f.uploaderRole)}</td><td>${visPill(f.visibility)}</td><td style="color:var(--dim)">${(f.size / 1024).toFixed(1)} KB</td><td><button class="btn-sm btn-del" onclick="delFile('${esc(f.key)}')">✕</button></td></tr>`; }).join('');
  return HEAD('111 Vault — Admin') + `<body>
  <header>${renderHeader(user)}</header>
  <div class="card">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:18px"><span style="font-weight:700">👥 Users <span style="font-size:.7em;color:var(--dim);font-weight:400">${userList.length}</span></span><a href="/vault" style="font-size:.85em;color:var(--muted);background:rgba(255,255,255,.05);border:1px solid var(--border);padding:7px 13px;border-radius:8px">← Back to Vault</a></div>
    <div style="background:var(--card2);border-radius:11px;padding:14px;margin-bottom:18px;border:1px solid var(--border)">
      <div style="font-size:.84em;font-weight:600;color:var(--muted);margin-bottom:11px">Create new account</div>
      <form onsubmit="event.preventDefault();crUser(this)"><div style="display:grid;grid-template-columns:1fr 1fr 1fr auto;gap:8px"><input type="hidden" name="action" value="create"><input type="text" name="u" placeholder="Username" required style="margin:0"><input type="password" name="p" placeholder="Password" required style="margin:0"><select name="r" style="margin:0"><option value="viewer">👁 Viewer</option><option value="member">📁 Member</option><option value="owner">🔑 Owner</option></select><button>Create</button></div></form>
    </div>
    <table><thead><tr><th>User</th><th>Role</th><th>Actions</th></tr></thead><tbody>${urows}</tbody></table>
  </div>
  <div class="card"><div style="font-weight:700;margin-bottom:14px">📂 All Files <span style="font-size:.7em;color:var(--dim);font-weight:400">${allFiles.length}</span></div>
    <table><thead><tr><th>File</th><th>Owner</th><th>Visibility</th><th>Size</th><th></th></tr></thead><tbody>${frows}</tbody></table>
  </div>
  <script>
    async function crUser(f){const r=await fetch('/vault/api/users',{method:'POST',body:new FormData(f)});if(r.ok)location.reload();else alert(await r.text());}
    async function updRole(f){const r=await fetch('/vault/api/users',{method:'POST',body:new FormData(f)});if(r.ok){const b=f.querySelector('button[type=submit]');b.textContent='✓';b.style.background='#10b981';setTimeout(()=>location.reload(),700);}else alert(await r.text());}
    async function delUser(n){if(!confirm('Delete "'+n+'"?'))return;const fd=new FormData();fd.append('action','delete');fd.append('u',n);const r=await fetch('/vault/api/users',{method:'POST',body:fd});if(r.ok)location.reload();else alert(await r.text());}
    async function delFile(k){if(!confirm('Delete "'+k+'"?'))return;const r=await fetch('/vault/api/delete/'+encodeURIComponent(k));if(r.ok)location.reload();else alert(await r.text());}
  <\/script>
</body></html>`;
}