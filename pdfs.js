/**
 * ULTRA-LIGHTWEIGHT SECURE PDF SYSTEM
 * Features: SQL Auth, RBAC, Upload Progress, R2 Storage
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
      // Fast lookup in D1
      const session = await env.DB.prepare('SELECT * FROM sessions WHERE id = ? AND expires > ?').bind(sessionId, Date.now()).first();
      if (session) user = session;
    }

    // --- 2. PUBLIC ROUTES (Login) ---
    if (url.pathname === '/login' && method === 'POST') {
      const fd = await req.formData();
      const u = fd.get('u'), p = fd.get('p');
      
      // Hash Password (SHA-256)
      const pwHash = await hash(p);
      
      const dbUser = await env.DB.prepare('SELECT * FROM users WHERE username = ? AND password = ?').bind(u, pwHash).first();
      
      if (!dbUser) return new Response('Invalid credentials', { status: 401 });

      // Create Session
      const newSess = crypto.randomUUID();
      await env.DB.prepare('INSERT INTO sessions (id, username, role, expires) VALUES (?, ?, ?, ?)').bind(newSess, dbUser.username, dbUser.role, Date.now() + 86400000).run();

      return new Response('OK', { 
        headers: { 'Set-Cookie': `sess=${newSess}; HttpOnly; Secure; SameSite=Strict; Path=/` } 
      });
    }

    if (url.pathname === '/logout') {
      if (sessionId) await env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(sessionId).run();
      return new Response('Logged out', { 
        status: 302, headers: { 'Location': '/', 'Set-Cookie': 'sess=; Max-Age=0; Path=/' } 
      });
    }

    // --- 3. PROTECTED ROUTES (Redirect to / if not logged in) ---
    if (!user) return new Response(renderLogin(), { headers: { 'Content-Type': 'text/html' } });

    // API: UPLOAD (Streamed + Metadata)
    if (url.pathname === '/api/upload' && method === 'POST') {
      if (user.role === 'guest') return new Response("Guests cannot upload", { status: 403 });

      const filename = req.headers.get('X-File-Name');
      if (!filename) return new Response("Missing name", { status: 400 });

      // Check R2 Limit implicitly (If R2 fails, it throws error)
      try {
        await env.BUCKET.put(filename, req.body, {
          customMetadata: { uploader: user.username, role: user.role }
        });
        return new Response("OK");
      } catch (e) {
        return new Response("Upload Failed: " + e.message, { status: 500 });
      }
    }

    // API: DELETE (Permission Logic)
    if (url.pathname.startsWith('/api/delete/')) {
      const fname = decodeURIComponent(url.pathname.replace('/api/delete/', ''));
      const obj = await env.BUCKET.head(fname);
      
      if (!obj) return new Response("Not found", { status: 404 });

      const fileRole = obj.customMetadata?.role || 'guest';
      const fileOwner = obj.customMetadata?.uploader || '';

      let canDelete = false;
      if (user.role === 'admin') canDelete = true; // Admin deletes everything
      else if (user.role === 'guest+' && fileRole !== 'admin') canDelete = true; // Guest+ deletes non-admin files
      else if (user.role === 'guest+' && fileOwner === user.username) canDelete = true; // Self delete

      if (!canDelete) return new Response("Permission Denied", { status: 403 });

      await env.BUCKET.delete(fname);
      return new Response("Deleted");
    }

    // API: ADMIN USER MANAGEMENT
    if (url.pathname === '/api/users' && method === 'POST') {
      if (user.role !== 'admin') return new Response("Forbidden", { status: 403 });
      const fd = await req.formData();
      const action = fd.get('action');

      if (action === 'create') {
        const hashPw = await hash(fd.get('p'));
        try {
          await env.DB.prepare('INSERT INTO users (username, password, role) VALUES (?, ?, ?)').bind(fd.get('u'), hashPw, fd.get('r')).run();
        } catch(e) { return new Response("User exists", { status: 400 }); }
      }
      if (action === 'delete') {
        await env.DB.prepare('DELETE FROM users WHERE username = ?').bind(fd.get('u')).run();
      }
      return new Response("OK");
    }

    // --- 4. RENDER DASHBOARD ---
    if (url.pathname === '/') {
      // Fetch Files
      const list = await env.BUCKET.list();
      const files = list.objects.map(o => ({
        key: o.key,
        size: o.size,
        uploader: o.customMetadata?.uploader || '?',
        role: o.customMetadata?.role || '?'
      }));

      // Fetch Users (If Admin)
      let userList = [];
      if (user.role === 'admin') {
        const { results } = await env.DB.prepare('SELECT username, role FROM users').all();
        userList = results;
      }

      return new Response(renderDash(user, files, userList), { headers: { 'Content-Type': 'text/html' } });
    }

    // SERVE FILES
    if (url.pathname.startsWith('/file/')) {
       const fname = decodeURIComponent(url.pathname.replace('/file/', ''));
       const obj = await env.BUCKET.get(fname);
       if(!obj) return new Response("404", {status:404});
       const h = new Headers(); obj.writeHttpMetadata(h); h.set('etag', obj.httpEtag);
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

// --- HTML TEMPLATES (Minified-ish) ---
const CSS = `
:root{--bg:#121212;--card:#1e1e1e;--txt:#e0e0e0;--p:#bb86fc;--s:#03dac6;--err:#cf6679}
body{font-family:system-ui;background:var(--bg);color:var(--txt);max-width:800px;margin:0 auto;padding:20px}
input,select,button{background:#333;border:1px solid #444;color:#fff;padding:8px;border-radius:4px;margin:5px 0}
button{cursor:pointer;background:var(--p);color:#000;font-weight:bold;border:none}
button:hover{opacity:0.9}
.card{background:var(--card);padding:20px;border-radius:8px;margin-bottom:20px;box-shadow:0 4px 6px rgba(0,0,0,0.3)}
.row{display:flex;justify-content:space-between;align-items:center;padding:10px 0;border-bottom:1px solid #333}
.tag{font-size:0.7em;padding:2px 6px;border-radius:4px;background:#333;margin-left:5px}
.tag.admin{background:var(--err);color:#000} .tag.guest\\+{background:var(--s);color:#000}
.bar-wrap{height:4px;background:#333;margin-top:5px;border-radius:2px;overflow:hidden}
.bar{height:100%;background:var(--s);width:0%;transition:0.2s}
a{color:var(--s);text-decoration:none}
`;

function renderLogin() {
  return `<!DOCTYPE html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><style>${CSS}</style></head>
  <body style="display:flex;justify-content:center;align-items:center;height:100vh">
    <div class="card" style="width:300px;text-align:center">
      <h2>🔐 Secure Access</h2>
      <form onsubmit="event.preventDefault();l(this)">
        <input type="text" name="u" placeholder="Username" required style="width:90%"><br>
        <input type="password" name="p" placeholder="Password" required style="width:90%"><br>
        <button style="width:100%">LOGIN</button>
      </form>
      <div id="msg" style="margin-top:10px;color:var(--err)"></div>
    </div>
    <script>
      async function l(f){
        const res = await fetch('/login',{method:'POST',body:new FormData(f)});
        if(res.ok) location.reload(); else document.getElementById('msg').innerText="Access Denied";
      }
    </script>
  </body></html>`;
}

function renderDash(user, files, users) {
  const isAdm = user.role === 'admin';
  const canUp = user.role !== 'guest';

  // File List Logic
  const fileRows = files.map(f => {
    // Delete Logic: Admin can delete all. Guest+ can delete non-admin files.
    let canDel = false;
    if (isAdm) canDel = true;
    else if (user.role === 'guest+' && f.role !== 'admin') canDel = true;

    return `
    <div class="row">
      <div>
        <a href="/file/${encodeURIComponent(f.key)}" target="_blank">📄 ${f.key}</a>
        <span class="tag ${f.role === 'admin' ? 'admin' : 'guest+'}">${f.uploader}</span>
        <small style="color:#666">(${(f.size/1024).toFixed(1)} KB)</small>
      </div>
      ${canDel ? `<button onclick="del('${f.key}')" style="background:var(--err);padding:2px 8px;font-size:12px">×</button>` : ''}
    </div>`;
  }).join('') || '<p style="text-align:center;color:#666">No files.</p>';

  // Admin User Panel
  const userPanel = isAdm ? `
  <div class="card">
    <h3>👥 User Management</h3>
    <form onsubmit="event.preventDefault();u(this)">
      <input type="hidden" name="action" value="create">
      <input type="text" name="u" placeholder="New Username" required>
      <input type="password" name="p" placeholder="Password" required>
      <select name="r"><option value="guest">Guest</option><option value="guest+">Guest +</option><option value="admin">Admin</option></select>
      <button>Add User</button>
    </form>
    <hr style="border:0;border-top:1px solid #333;margin:15px 0">
    ${users.map(u => `<div class="row"><small>${u.username} (${u.role})</small> ${u.username!=='admin'?`<button onclick="kill('${u.username}')" style="background:#333;color:#fff;font-size:10px">DEL</button>`:''}</div>`).join('')}
  </div>` : '';

  // Upload Panel
  const uploadPanel = canUp ? `
  <div class="card">
    <h3>📤 Upload PDF</h3>
    <input type="file" id="f" accept=".pdf">
    <div class="bar-wrap"><div id="pb" class="bar"></div></div>
    <div style="display:flex;justify-content:space-between;margin-top:10px">
      <small id="st">Max: 5GB (R2)</small>
      <button onclick="up()">Start Upload</button>
    </div>
  </div>` : '';

  return `<!DOCTYPE html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Vault</title><style>${CSS}</style></head>
  <body>
    <header class="row" style="margin-bottom:20px">
      <div><strong>Vault</strong> <span class="tag">${user.role}</span></div>
      <div style="display:flex;gap:10px;align-items:center">
        <small>👤 ${user.username}</small>
        <a href="/logout" style="background:#333;padding:5px 10px;border-radius:4px;color:#fff;font-size:0.8em">Logout</a>
      </div>
    </header>

    ${uploadPanel}
    ${userPanel}

    <div class="card">
      <h3>Files</h3>
      ${fileRows}
    </div>

    <script>
      // UPLOAD WITH PROGRESS
      function up() {
        const f = document.getElementById('f').files[0];
        if(!f) return alert('Select file');
        
        const xhr = new XMLHttpRequest();
        xhr.open('POST', '/api/upload', true);
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

      async function del(key) {
        if(!confirm('Delete ' + key + '?')) return;
        const res = await fetch('/api/delete/' + encodeURIComponent(key));
        if(res.ok) location.reload(); else alert('Permission Denied');
      }

      async function u(form) {
        const res = await fetch('/api/users', {method:'POST', body:new FormData(form)});
        if(res.ok) location.reload(); else alert('Failed');
      }

      async function kill(name) {
        if(!confirm('Remove user ' + name + '?')) return;
        const fd = new FormData(); fd.append('action','delete'); fd.append('u', name);
        await fetch('/api/users', {method:'POST', body:fd});
        location.reload();
      }
    </script>
  </body></html>`;
}