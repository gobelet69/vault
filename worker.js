/**
 * FINAL SECURE VAULT SYSTEM
 * Features: Auto-Renaming, Permissions, Role Management
 * Modified for /vault path
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
          // Fetch role from users table since central sessions may not store role
          const dbUser = await env.AUTH_DB.prepare('SELECT role FROM users WHERE username = ?').bind(user.username).first();
          user.role = dbUser ? (dbUser.role || 'guest') : 'guest';
        }
      } catch (e) { console.error("Session DB Error:", e); }
    }

    // --- 2. PROTECTED ROUTES ---
    if (!user) {
      return new Response(null, {
        status: 302,
        headers: { 'Location': `/auth/login?redirect=${encodeURIComponent(url.pathname)}` }
      });
    }

    // API: UPLOAD
    // Correction: Check for /vault/api/upload
    if (url.pathname === '/vault/api/upload' && method === 'POST') {

      const originalName = req.headers.get('X-File-Name');
      if (!originalName) return new Response("Missing name", { status: 400 });

      const isPdf = originalName.toLowerCase().endsWith('.pdf');
      if (user.role === 'guest' && !isPdf) {
        return new Response("Guest users can only upload PDF files.", { status: 403 });
      }

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
          customMetadata: { uploader: user.username, role: user.role }
        });
        return new Response("OK");

      } catch (e) { return new Response("Upload Failed: " + e.message, { status: 500 }); }
    }

    // API: DELETE
    // Correction: Check for /vault/api/delete/
    if (url.pathname.startsWith('/vault/api/delete/')) {
      const fname = decodeURIComponent(url.pathname.replace('/vault/api/delete/', ''));
      const obj = await env.BUCKET.head(fname);

      if (!obj) return new Response("Not found", { status: 404 });

      const fileOwner = obj.customMetadata?.uploader || '';
      let canDelete = false;

      if (user.role === 'admin') canDelete = true;
      else if (user.role === 'guest+' && fileOwner === user.username) canDelete = true;
      else if (user.role === 'guest' && fileOwner === user.username) canDelete = true; // Added guest self-delete consistency

      if (!canDelete) return new Response("Permission Denied: You can only delete your own files.", { status: 403 });

      await env.BUCKET.delete(fname);
      return new Response("Deleted");
    }

    // API: USER MANAGEMENT
    // Correction: Check for /vault/api/users
    if (url.pathname === '/vault/api/users' && method === 'POST') {
      if (user.role !== 'admin') return new Response("Forbidden", { status: 403 });

      try {
        const fd = await req.formData();
        const action = fd.get('action');

        if (action === 'create') {
          const hashPw = await hash(fd.get('p'));
          // Use AUTH_DB for user management
          await env.AUTH_DB.prepare('INSERT OR REPLACE INTO users (username, password, role) VALUES (?, ?, ?)').bind(fd.get('u'), hashPw, fd.get('r')).run();
        }
        if (action === 'delete') {
          // Use AUTH_DB for user management
          await env.AUTH_DB.prepare('DELETE FROM users WHERE username = ?').bind(fd.get('u')).run();
        }
        return new Response("OK");
      } catch (e) {
        return new Response("DB Error: " + e.message, { status: 500 });
      }
    }

    // --- 4. RENDER DASHBOARD ---
    // Correction: Check for /vault or /vault/
    if (url.pathname === '/vault' || url.pathname === '/vault/') {
      try {
        const list = await env.BUCKET.list({ include: ['customMetadata'] });

        const files = list.objects.map(o => ({
          key: o.key,
          size: o.size,
          uploader: o.customMetadata?.uploader || '?',
          role: o.customMetadata?.role || '?'
        }));

        let userList = [];
        if (user.role === 'admin') {
          try {
            // Get users from AUTH_DB
            const { results } = await env.AUTH_DB.prepare('SELECT username, role FROM users').all();
            userList = results;
          } catch (e) { console.log("User table error", e); }
        }

        return new Response(renderDash(user, files, userList), {
          headers: { 'Content-Type': 'text/html; charset=utf-8' }
        });
      } catch (e) { return new Response("Render Error: " + e.message, { status: 500 }); }
    }

    // SERVE FILES
    // Correction: Check for /vault/file/
    if (url.pathname.startsWith('/vault/file/')) {
      const fname = decodeURIComponent(url.pathname.replace('/vault/file/', ''));
      const obj = await env.BUCKET.get(fname);
      if (!obj) return new Response("404", { status: 404 });

      const h = new Headers();
      obj.writeHttpMetadata(h);
      h.set('etag', obj.httpEtag);

      let type = 'application/octet-stream';
      if (fname.endsWith('.pdf')) type = 'application/pdf';
      else if (fname.endsWith('.jpg') || fname.endsWith('.png')) type = 'image/' + fname.split('.').pop();
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
  const hash = await crypto.subtle.digest('SHA-256', buf);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// --- HTML TEMPLATES ---
const CSS = `
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
:root{--bg:#0f1117;--card:#161b22;--txt-main:#f8fafc;--txt-muted:#94a3b8;--p:#6366f1;--p-hover:#4f46e5;--s:#0ea5e9;--err:#f43f5e;--good:#10b981;--border:rgba(255,255,255,0.08);--ring:rgba(99,102,241,0.5)}
body{font-family:'Inter',system-ui,sans-serif;background:var(--bg);color:var(--txt-main);max-width:900px;margin:0 auto;padding:24px;line-height:1.5;box-sizing:border-box}
input,select,button{background:rgba(0,0,0,0.2);border:1px solid var(--border);color:var(--txt-main);padding:10px 14px;border-radius:8px;margin:5px 0;transition:all 0.2s;font-family:inherit;font-size:0.95em}
input:focus,select:focus{outline:none;border-color:var(--p);box-shadow:0 0 0 3px var(--ring)}
button{cursor:pointer;background:var(--p);color:#fff;font-weight:600;border:none;padding:10px 16px;border-radius:8px;transition:all 0.2s;font-family:inherit;font-size:0.95em;box-shadow:0 4px 12px rgba(99,102,241,0.2)}
button:hover{background:var(--p-hover);transform:translateY(-1px);box-shadow:0 6px 16px rgba(99,102,241,0.3)}
.card{background:var(--card);padding:24px;border-radius:16px;margin-bottom:24px;border:1px solid var(--border);box-shadow:0 8px 32px rgba(0,0,0,0.2)}
.row{display:flex;justify-content:space-between;align-items:center;padding:14px 16px;border-bottom:1px solid var(--border);margin:-14px -16px 14px;transition:background 0.2s;border-radius:8px}
.row:hover{background:rgba(255,255,255,0.02)}
.card > .row:last-child{border-bottom:none;margin-bottom:-14px}
.tag{font-size:0.75em;padding:4px 10px;border-radius:12px;background:rgba(255,255,255,0.1);margin-left:8px;vertical-align:middle;font-weight:600}
.tag.admin{background:rgba(244,63,94,0.15);color:var(--err);border:1px solid rgba(244,63,94,0.2)} 
.tag.guest\\+{background:rgba(14,165,233,0.15);color:var(--s);border:1px solid rgba(14,165,233,0.2)}
.bar-wrap{height:6px;background:rgba(0,0,0,0.3);margin-top:8px;border-radius:3px;overflow:hidden;border:1px solid var(--border)}
.bar{height:100%;background:var(--p);width:0%;transition:0.3s ease-out;box-shadow:0 0 10px var(--p)}
a{color:var(--p);text-decoration:none;transition:color 0.2s} a:hover{color:var(--s)}
header{display:flex;justify-content:space-between;align-items:center;padding:16px 24px!important;background:var(--card)!important;border-bottom:1px solid var(--border)!important;margin-bottom:30px!important;border-radius:16px!important;box-shadow:0 4px 20px rgba(0,0,0,0.2)!important}
header strong{font-size:1.2em;letter-spacing:-0.02em}
h3{font-size:1.3em;margin-bottom:20px;font-weight:700;letter-spacing:-0.01em}
`;

// Removed local renderLogin and renderRegister as they are now handled by global-auth.

function renderDash(user, files, users) {
  const isAdm = user.role === 'admin';
  const isGuestPlus = user.role === 'guest+';
  const acceptAttr = user.role === 'guest' ? 'accept=".pdf"' : '';

  const fileRows = files.map(f => {
    let canDel = false;
    if (isAdm) canDel = true;
    else if (f.uploader === user.username) canDel = true;

    const tagHtml = f.uploader !== '?'
      ? `<span class="tag ${f.role === 'admin' ? 'admin' : 'guest+'}">${f.uploader}</span>`
      : `<span class="tag" style="background:#444;color:#aaa">Legacy</span>`;

    // MODIFICATION: /vault/file/...
    return `
    <div class="row">
      <div style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:80%">
        <a href="/vault/file/${encodeURIComponent(f.key)}" target="_blank">📄 ${f.key}</a>
        ${tagHtml}
      </div>
      <div style="display:flex;align-items:center;gap:10px">
        <small style="color:#666">${(f.size / 1024).toFixed(1)} KB</small>
        ${canDel ? `<button onclick="delFile('${f.key}')" style="background:var(--err);padding:2px 8px;font-size:12px">✕</button>` : ''}
      </div>
    </div>`;
  }).join('') || '<p style="text-align:center;color:#666">No files yet.</p>';

  const userPanel = isAdm ? `
  <div class="card">
    <h3>👥 User Management</h3>
    <form onsubmit="event.preventDefault();saveUser(this)" style="display:grid;grid-template-columns:1fr 1fr auto auto;gap:5px">
      <input type="hidden" name="action" value="create">
      <input type="text" name="u" placeholder="Username" required>
      <input type="password" name="p" placeholder="Password" required>
      <select name="r"><option value="guest">Guest (PDF only)</option><option value="guest+">Guest + (All files)</option><option value="admin">Admin</option></select>
      <button>Save</button>
    </form>
    <div style="max-height:150px;overflow-y:auto;margin-top:10px">
    ${users.map(u => `
      <div class="row" style="padding:5px 0">
        <small>${u.username} <span style="color:#666">(${u.role})</span></small> 
        ${u.username !== 'admin' ? `<button onclick="deleteUser('${u.username}')" style="background:#333;color:#fff;font-size:10px">✕</button>` : ''}
      </div>`).join('')}
    </div>
  </div>` : '';

  const uploadPanel = `
  <div class="card">
    <h3>📤 Upload ${user.role === 'guest' ? '(PDF Only)' : '(All Files)'}</h3>
    <input type="file" id="f" ${acceptAttr}>
    <div class="bar-wrap"><div id="pb" class="bar"></div></div>
    <div style="display:flex;justify-content:space-between;margin-top:10px">
      <small id="st">Ready</small>
      <button onclick="uploadFile()">Start Upload</button>
    </div>
  </div>`;

  // MODIFICATION: /vault/logout -> /auth/logout
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Vault</title><style>${CSS}</style></head>
  <body>
    <header>
      <div style="display:flex;align-items:center;gap:12px">
        <a href="/" style="text-decoration:none;display:flex;align-items:center;gap:8px;color:var(--txt-main)"><span style="width:30px;height:30px;background:linear-gradient(135deg,#6366f1,#f43f5e);border-radius:8px;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:0.85em;color:#fff;flex-shrink:0">111</span><strong>Vault</strong></a>
        <span class="tag">${user.role}</span>
        <span style="color:var(--txt-muted);font-size:0.8em;padding:4px 10px;background:rgba(255,255,255,0.05);border-radius:20px;border:1px solid var(--border)">${user.username}</span>
      </div>
      <div style="display:flex;gap:8px;align-items:center">
        <a href="/" class="nav-link" style="background:rgba(255,255,255,0.04);border:1px solid var(--border)">🏠 Hub</a>
        <a href="/auth/logout" style="color:var(--err);align-self:center;font-size:0.9em;font-weight:500;padding:8px 12px;border-radius:8px;background:rgba(244,63,94,0.08);border:1px solid rgba(244,63,94,0.15);transition:all 0.2s" onmouseover="this.style.background='rgba(244,63,94,0.15)'" onmouseout="this.style.background='rgba(244,63,94,0.08)'">Sign out</a>
      </div>
    </header>

    ${userPanel}
    ${uploadPanel}

    <div class="card">
      <h3>Files</h3>
      ${fileRows}
    </div>

    <script>
      function uploadFile() {
        const f = document.getElementById('f').files[0];
        if(!f) return alert('Select file');
        
        const xhr = new XMLHttpRequest();
        // MODIFICATION: /vault/api/upload
        xhr.open('POST', '/vault/api/upload', true);
        xhr.setRequestHeader('X-File-Name', f.name);
        
        xhr.upload.onprogress = e => {
          if(e.lengthComputable) {
            const p = (e.loaded / e.total) * 100;
            document.getElementById('pb').style.width = p + '%';
            document.getElementById('st').innerText = Math.round(p) + '%';
          }
        };
        
        xhr.onload = () => {
          if(xhr.status === 200) location.reload();
          else alert('Error: ' + xhr.responseText);
        };
        
        xhr.send(f);
      }

      async function delFile(key) {
        if(!confirm('Delete ' + key + '?')) return;
        // MODIFICATION: /vault/api/delete/
        const res = await fetch('/vault/api/delete/' + encodeURIComponent(key));
        if(res.ok) location.reload(); else alert('Permission Denied: ' + await res.text());
      }

      async function saveUser(form) {
        // MODIFICATION: /vault/api/users
        const res = await fetch('/vault/api/users', {method:'POST', body:new FormData(form)});
        if(res.ok) {
           location.reload();
        } else {
           const txt = await res.text();
           alert('Failed: ' + txt);
        }
      }

      async function deleteUser(name) {
        if(!confirm('Remove user ' + name + '?')) return;
        const fd = new FormData(); fd.append('action','delete'); fd.append('u', name);
        // MODIFICATION: /vault/api/users
        await fetch('/vault/api/users', {method:'POST', body:fd});
        location.reload();
      }
    </script>
  </body></html>`;
}