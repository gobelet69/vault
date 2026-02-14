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
        const session = await env.DB.prepare('SELECT * FROM sessions WHERE id = ? AND expires > ?').bind(sessionId, Date.now()).first();
        if (session) user = session;
      } catch (e) { console.error("Session DB Error:", e); }
    }

    // --- 2. PUBLIC ROUTES (Login & Register) ---
    // Login route
    if (url.pathname === '/vault/login' && method === 'POST') {
      try {
        const fd = await req.formData();
        const u = fd.get('u'), p = fd.get('p');
        const pwHash = await hash(p);

        // Query AUTH_DB for user authentication
        const dbUser = await env.AUTH_DB.prepare('SELECT * FROM users WHERE username = ? AND password = ?').bind(u, pwHash).first();

        if (!dbUser) return new Response('Invalid credentials', { status: 401 });

        // Get user role (default to 'guest' if not set)
        const role = dbUser.role || 'guest';

        const newSess = crypto.randomUUID();
        // Store session in DB (not AUTH_DB)
        await env.DB.prepare('INSERT INTO sessions (id, username, role, expires) VALUES (?, ?, ?, ?)').bind(newSess, dbUser.username, role, Date.now() + 86400000).run();

        return new Response('OK', {
          headers: { 'Set-Cookie': `sess=${newSess}; HttpOnly; Secure; SameSite=Strict; Path=/` }
        });
      } catch (e) { return new Response("Login Error: " + e.message, { status: 500 }); }
    }

    // Register route
    if (url.pathname === '/vault/register' && method === 'POST') {
      try {
        const fd = await req.formData();
        const u = fd.get('u'), p = fd.get('p'), p2 = fd.get('p2');

        // Validate inputs
        if (!u || !p || !p2) return new Response('All fields required', { status: 400 });
        if (p !== p2) return new Response('Passwords do not match', { status: 400 });
        if (u.length < 3) return new Response('Username must be at least 3 characters', { status: 400 });
        if (p.length < 6) return new Response('Password must be at least 6 characters', { status: 400 });

        // Check if user already exists
        const existing = await env.AUTH_DB.prepare('SELECT username FROM users WHERE username = ?').bind(u).first();
        if (existing) return new Response('Username already exists', { status: 409 });

        const pwHash = await hash(p);
        // Insert into AUTH_DB with default role 'guest'
        await env.AUTH_DB.prepare('INSERT INTO users (username, password, role) VALUES (?, ?, ?)').bind(u, pwHash, 'guest').run();

        return new Response('OK');
      } catch (e) { return new Response("Registration Error: " + e.message, { status: 500 }); }
    }

    // Show register page
    if (url.pathname === '/vault/register' && method === 'GET') {
      return new Response(renderRegister(), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }

    // Correction: Check for /vault/logout
    if (url.pathname === '/vault/logout') {
      if (sessionId) await env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(sessionId).run();
      return new Response('Logged out', {
        status: 302, headers: { 'Location': '/', 'Set-Cookie': 'sess=; Max-Age=0; Path=/' }
      });
    }

    // --- 3. PROTECTED ROUTES ---
    if (!user) return new Response(renderLogin(), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });

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
:root{--bg:#121212;--card:#1e1e1e;--txt:#e0e0e0;--p:#bb86fc;--s:#03dac6;--err:#cf6679}
body{font-family:system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--txt);max-width:800px;margin:0 auto;padding:20px}
input,select,button{background:#333;border:1px solid #444;color:#fff;padding:8px;border-radius:4px;margin:5px 0}
button{cursor:pointer;background:var(--p);color:#000;font-weight:bold;border:none}
button:hover{opacity:0.9}
.card{background:var(--card);padding:20px;border-radius:8px;margin-bottom:20px;border:1px solid #333}
.row{display:flex;justify-content:space-between;align-items:center;padding:10px 0;border-bottom:1px solid #333}
.tag{font-size:0.7em;padding:2px 6px;border-radius:4px;background:#333;margin-left:5px;vertical-align:middle}
.tag.admin{background:var(--err);color:#000} .tag.guest\\+{background:var(--s);color:#000}
.bar-wrap{height:4px;background:#333;margin-top:5px;border-radius:2px;overflow:hidden}
.bar{height:100%;background:var(--s);width:0%;transition:0.2s}
a{color:var(--s);text-decoration:none} a:hover{text-decoration:underline}
`;

function renderLogin() {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><style>${CSS}</style></head>
  <body style="display:flex;justify-content:center;align-items:center;height:100vh">
    <div class="card" style="width:320px;text-align:center">
      <h2>🔐 Secure Access</h2>
      <form onsubmit="event.preventDefault();doLogin(this)">
        <input type="text" name="u" id="username" placeholder="Username" autocomplete="username" required style="width:90%"><br>
        <input type="password" name="p" id="password" placeholder="Password" autocomplete="current-password" required style="width:90%"><br>
        <button type="submit" style="width:100%;margin-bottom:10px">LOGIN</button>
      </form>
      <div style="margin-top:15px;padding-top:15px;border-top:1px solid #333">
        <small style="color:#888">Don't have an account?</small><br>
        <a href="/vault/register" style="display:inline-block;margin-top:8px;padding:8px 16px;background:#333;border-radius:4px;text-decoration:none">Create Account</a>
      </div>
      <div id="msg" style="margin-top:10px;color:var(--err)"></div>
    </div>
    <script>
      async function doLogin(f){
        const res = await fetch('/vault/login',{method:'POST',body:new FormData(f)});
        if(res.ok) location.reload(); 
        else document.getElementById('msg').innerText = "Access Denied";
      }
    </script>
  </body></html>`;
}

function renderRegister() {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><style>${CSS}</style></head>
  <body style="display:flex;justify-content:center;align-items:center;height:100vh">
    <div class="card" style="width:320px;text-align:center">
      <h2>📝 Create Account</h2>
      <form onsubmit="event.preventDefault();doRegister(this)">
        <input type="text" name="u" id="username" placeholder="Username" autocomplete="username" required style="width:90%"><br>
        <input type="password" name="p" id="password" placeholder="Password" autocomplete="new-password" required style="width:90%"><br>
        <input type="password" name="p2" id="password2" placeholder="Confirm Password" autocomplete="new-password" required style="width:90%"><br>
        <button type="submit" style="width:100%;margin-bottom:10px">REGISTER</button>
      </form>
      <div style="margin-top:15px;padding-top:15px;border-top:1px solid #333">
        <small style="color:#888">Already have an account?</small><br>
        <a href="/vault" style="display:inline-block;margin-top:8px;padding:8px 16px;background:#333;border-radius:4px;text-decoration:none">Back to Login</a>
      </div>
      <div id="msg" style="margin-top:10px;color:var(--err)"></div>
    </div>
    <script>
      async function doRegister(f){
        const res = await fetch('/vault/register',{method:'POST',body:new FormData(f)});
        if(res.ok) {
          alert('Account created successfully! You can now login.');
          location.href = '/vault';
        } else {
          const txt = await res.text();
          document.getElementById('msg').innerText = txt;
        }
      }
    </script>
  </body></html>`;
}

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

  // MODIFICATION: /vault/logout
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Vault</title><style>${CSS}</style></head>
  <body>
    <header class="row" style="margin-bottom:20px;border-bottom:1px solid #444;padding-bottom:15px">
      <div><strong>Vault</strong> <span class="tag">${user.role}</span></div>
      <div style="display:flex;gap:10px;align-items:center">
        <small>👤 ${user.username}</small>
        <a href="/vault/logout" style="background:#333;padding:5px 10px;border-radius:4px;color:#fff;font-size:0.8em;text-decoration:none">Logout</a>
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