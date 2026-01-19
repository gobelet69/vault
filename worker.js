/**
 * FINAL SECURE VAULT SYSTEM
 * Features: Auto-Renaming (collision handling), Granular Permissions, Role Management
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

    // --- 2. PUBLIC ROUTES (Login) ---
    if (url.pathname === '/login' && method === 'POST') {
      try {
        const fd = await req.formData();
        const u = fd.get('u'), p = fd.get('p');
        const pwHash = await hash(p);
        
        const dbUser = await env.DB.prepare('SELECT * FROM users WHERE username = ? AND password = ?').bind(u, pwHash).first();
        
        if (!dbUser) return new Response('Invalid credentials', { status: 401 });

        const newSess = crypto.randomUUID();
        await env.DB.prepare('INSERT INTO sessions (id, username, role, expires) VALUES (?, ?, ?, ?)').bind(newSess, dbUser.username, dbUser.role, Date.now() + 86400000).run();

        return new Response('OK', { 
          headers: { 'Set-Cookie': `sess=${newSess}; HttpOnly; Secure; SameSite=Strict; Path=/` } 
        });
      } catch (e) { return new Response("Login Error: " + e.message, { status: 500 }); }
    }

    if (url.pathname === '/logout') {
      if (sessionId) await env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(sessionId).run();
      return new Response('Logged out', { 
        status: 302, headers: { 'Location': '/', 'Set-Cookie': 'sess=; Max-Age=0; Path=/' } 
      });
    }

    // --- 3. PROTECTED ROUTES ---
    if (!user) return new Response(renderLogin(), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });

    // API: UPLOAD (Avec Renommage + Vérification Type)
    if (url.pathname === '/api/upload' && method === 'POST') {
      
      const originalName = req.headers.get('X-File-Name');
      if (!originalName) return new Response("Missing name", { status: 400 });

      // 1. Vérification du type de fichier pour 'Guest'
      const isPdf = originalName.toLowerCase().endsWith('.pdf');
      if (user.role === 'guest' && !isPdf) {
        return new Response("Guest users can only upload PDF files.", { status: 403 });
      }

      try {
        // Nettoyage basique du nom
        let safeName = originalName.replace(/[^\x00-\x7F]/g, "").trim(); 
        
        // 2. Logique de Renommage (Collision) : file.txt -> file (1).txt
        let finalName = safeName;
        let counter = 1;

        while (true) {
          const existing = await env.BUCKET.head(finalName);
          if (!existing) break; // Le nom est libre, on sort de la boucle

          // On sépare le nom et l'extension pour insérer le (1)
          const dotIndex = safeName.lastIndexOf('.');
          if (dotIndex !== -1) {
            const namePart = safeName.substring(0, dotIndex);
            const extPart = safeName.substring(dotIndex);
            finalName = `${namePart} (${counter})${extPart}`;
          } else {
            finalName = `${safeName} (${counter})`;
          }
          counter++;
        }

        // 3. Sauvegarde dans R2
        await env.BUCKET.put(finalName, req.body, {
          customMetadata: { uploader: user.username, role: user.role }
        });
        return new Response("OK");

      } catch (e) { return new Response("Upload Failed: " + e.message, { status: 500 }); }
    }

    // API: DELETE (Permissions strictes)
    if (url.pathname.startsWith('/api/delete/')) {
      const fname = decodeURIComponent(url.pathname.replace('/api/delete/', ''));
      const obj = await env.BUCKET.head(fname);
      
      if (!obj) return new Response("Not found", { status: 404 });

      const fileOwner = obj.customMetadata?.uploader || '';

      // Règle : Admin supprime tout, les autres ne suppriment que leurs propres fichiers
      let canDelete = false;
      
      if (user.role === 'admin') {
        canDelete = true;
      } else {
        // Guest et Guest+ : Uniquement si c'est LEUR fichier
        if (fileOwner === user.username) {
          canDelete = true;
        }
      }

      if (!canDelete) return new Response("Permission Denied: You can only delete your own files.", { status: 403 });

      await env.BUCKET.delete(fname);
      return new Response("Deleted");
    }

    // API: USER MANAGEMENT
    if (url.pathname === '/api/users' && method === 'POST') {
      if (user.role !== 'admin') return new Response("Forbidden", { status: 403 });
      
      try {
        const fd = await req.formData();
        const action = fd.get('action');

        if (action === 'create') {
          const hashPw = await hash(fd.get('p'));
          await env.DB.prepare('INSERT OR REPLACE INTO users (username, password, role) VALUES (?, ?, ?)').bind(fd.get('u'), hashPw, fd.get('r')).run();
        }
        if (action === 'delete') {
          await env.DB.prepare('DELETE FROM users WHERE username = ?').bind(fd.get('u')).run();
        }
        return new Response("OK");
      } catch(e) { 
        return new Response("DB Error: " + e.message, { status: 500 }); 
      }
    }

    // --- 4. RENDER DASHBOARD ---
    if (url.pathname === '/') {
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
             const { results } = await env.DB.prepare('SELECT username, role FROM users').all();
             userList = results;
          } catch(e) { console.log("User table error", e); }
        }

        return new Response(renderDash(user, files, userList), { 
          headers: { 'Content-Type': 'text/html; charset=utf-8' }
        });
      } catch (e) { return new Response("Render Error: " + e.message, { status: 500 }); }
    }

    // SERVE FILES
    if (url.pathname.startsWith('/file/')) {
       const fname = decodeURIComponent(url.pathname.replace('/file/', ''));
       const obj = await env.BUCKET.get(fname);
       if(!obj) return new Response("404", {status:404});
       
       const h = new Headers(); 
       obj.writeHttpMetadata(h); 
       h.set('etag', obj.httpEtag);
       
       // Détection basique du Content-Type pour l'affichage navigateur
       let type = 'application/octet-stream';
       if(fname.endsWith('.pdf')) type = 'application/pdf';
       else if(fname.endsWith('.jpg') || fname.endsWith('.png')) type = 'image/' + fname.split('.').pop();
       else if(fname.endsWith('.txt')) type = 'text/plain';
       
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
    <div class="card" style="width:300px;text-align:center">
      <h2>🔐 Secure Access</h2>
      <form onsubmit="event.preventDefault();doLogin(this)">
        <input type="text" name="u" placeholder="Username" required style="width:90%"><br>
        <input type="password" name="p" placeholder="Password" required style="width:90%"><br>
        <button style="width:100%">LOGIN</button>
      </form>
      <div id="msg" style="margin-top:10px;color:var(--err)"></div>
    </div>
    <script>
      async function doLogin(f){
        const res = await fetch('/login',{method:'POST',body:new FormData(f)});
        if(res.ok) location.reload(); 
        else document.getElementById('msg').innerText = "Access Denied";
      }
    </script>
  </body></html>`;
}

function renderDash(user, files, users) {
  const isAdm = user.role === 'admin';
  const isGuestPlus = user.role === 'guest+';
  
  // Règle d'upload : Seul Guest est restreint au PDF
  const acceptAttr = user.role === 'guest' ? 'accept=".pdf"' : ''; 

  const fileRows = files.map(f => {
    // Règle de suppression : Admin OU Propriétaire du fichier
    let canDel = false;
    if (isAdm) canDel = true;
    else if (f.uploader === user.username) canDel = true;

    const tagHtml = f.uploader !== '?' 
      ? `<span class="tag ${f.role === 'admin' ? 'admin' : 'guest+'}">${f.uploader}</span>` 
      : `<span class="tag" style="background:#444;color:#aaa">Legacy</span>`;

    return `
    <div class="row">
      <div style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:80%">
        <a href="/file/${encodeURIComponent(f.key)}" target="_blank">📄 ${f.key}</a>
        ${tagHtml}
      </div>
      <div style="display:flex;align-items:center;gap:10px">
        <small style="color:#666">${(f.size/1024).toFixed(1)} KB</small>
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
        ${u.username!=='admin'?`<button onclick="deleteUser('${u.username}')" style="background:#333;color:#fff;font-size:10px">✕</button>`:''}
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

  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Vault</title><style>${CSS}</style></head>
  <body>
    <header class="row" style="margin-bottom:20px;border-bottom:1px solid #444;padding-bottom:15px">
      <div><strong>Vault</strong> <span class="tag">${user.role}</span></div>
      <div style="display:flex;gap:10px;align-items:center">
        <small>👤 ${user.username}</small>
        <a href="/logout" style="background:#333;padding:5px 10px;border-radius:4px;color:#fff;font-size:0.8em;text-decoration:none">Logout</a>
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

      async function delFile(key) {
        if(!confirm('Delete ' + key + '?')) return;
        const res = await fetch('/api/delete/' + encodeURIComponent(key));
        if(res.ok) location.reload(); else alert('Permission Denied: ' + await res.text());
      }

      async function saveUser(form) {
        const res = await fetch('/api/users', {method:'POST', body:new FormData(form)});
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
        await fetch('/api/users', {method:'POST', body:fd});
        location.reload();
      }
    </script>
  </body></html>`;
}