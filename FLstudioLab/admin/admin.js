// FLstudioLab Admin-Panel Logik
const API = '/api/admin';
let adminSession = localStorage.getItem('admin_session') || null;

function showError(id, msg) {
  const el = document.getElementById(id);
  if (el) { el.innerText = msg; el.style.display = 'block'; }
}
function hideError(id) {
  const el = document.getElementById(id);
  if (el) { el.innerText = ''; el.style.display = 'none'; }
}

// Login
if (document.getElementById('admin-login-btn')) {
  document.getElementById('admin-login-btn').onclick = async function() {
    hideError('admin-login-error');
    const username = document.getElementById('admin-username').value;
    const password = document.getElementById('admin-password').value;
    const form = new FormData();
    form.append('username', username);
    form.append('password', password);
    const res = await fetch(API + '/login', { method: 'POST', body: form });
    const data = await res.json();
    if (data.admin_session) {
      localStorage.setItem('admin_session', data.admin_session);
      adminSession = data.admin_session;
      document.getElementById('admin-login').style.display = 'none';
      document.getElementById('admin-dashboard').style.display = 'block';
      loadAll();
    } else {
      showError('admin-login-error', data.detail || data.msg || 'Login fehlgeschlagen');
    }
  };
}

// Logout
if (document.getElementById('admin-logout-btn')) {
  document.getElementById('admin-logout-btn').onclick = function() {
    localStorage.removeItem('admin_session');
    window.location.reload();
  };
}

// Tab-Switching
const tabs = document.querySelectorAll('.admin-tab');
tabs.forEach(tab => {
  tab.onclick = function() {
    tabs.forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.admin-section').forEach(s => s.classList.remove('active'));
    this.classList.add('active');
    document.getElementById('admin-section-' + this.dataset.tab).classList.add('active');
  };
});

// Daten laden
async function loadAll() {
  await loadUsers();
  await loadSupport();
  await loadLogs();
  await loadPublic();
  await loadStorage();
}

// Nutzerverwaltung
async function loadUsers() {
  const res = await fetch(API + '/users?admin_session=' + adminSession);
  const data = await res.json();
  const sec = document.getElementById('admin-section-users');
  if (!data.users) { sec.innerHTML = 'Fehler beim Laden.'; return; }
  sec.innerHTML = `<table style="width:100%;border-collapse:collapse;">
    <thead><tr><th>Name</th><th>Code</th><th>Status</th><th>Aktion</th></tr></thead>
    <tbody>
      ${data.users.map(u => `
        <tr>
          <td>${u.username}</td>
          <td>${u.user_code||''}</td>
          <td>${u.blocked?'Gesperrt':'Aktiv'}</td>
          <td>
            <button class="btn" onclick="adminBlockUser('${u.username}',${!u.blocked})">${u.blocked?'Freischalten':'Blockieren'}</button>
            <button class="btn btn-danger" onclick="adminDeleteUser('${u.username}')">Löschen</button>
          </td>
        </tr>
      `).join('')}
    </tbody>
  </table>`;
}
window.adminBlockUser = async function(username, unblock) {
  const form = new FormData();
  form.append('admin_session', adminSession);
  form.append('username', username);
  await fetch(API + '/user/' + (unblock?'unblock':'block'), { method: 'POST', body: form });
  loadUsers();
};
window.adminDeleteUser = async function(username) {
  if (!confirm('User wirklich löschen?')) return;
  const form = new FormData();
  form.append('admin_session', adminSession);
  form.append('username', username);
  await fetch(API + '/user/delete', { method: 'POST', body: form });
  loadUsers();
};

// Support
async function loadSupport() {
  const res = await fetch(API + '/support?admin_session=' + adminSession);
  const data = await res.json();
  const sec = document.getElementById('admin-section-support');
  if (!data.support) { sec.innerHTML = 'Fehler beim Laden.'; return; }
  sec.innerHTML = `<div style="max-height:400px;overflow-y:auto;">
    ${data.support.map(s => `
      <div style="border-bottom:1px solid var(--border);padding:8px 0;">
        <b>${s.username||'anonym'}</b> <span style="color:var(--text-muted);font-size:0.95rem;">${new Date(s.timestamp*1000).toLocaleString()}</span><br>
        <span>${s.message}</span>
      </div>
    `).join('')}
  </div>`;
}

// Logs
async function loadLogs() {
  const res = await fetch(API + '/logs?admin_session=' + adminSession);
  const data = await res.json();
  const sec = document.getElementById('admin-section-logs');
  if (!data.logs) { sec.innerHTML = 'Fehler beim Laden.'; return; }
  sec.innerHTML = Object.keys(data.logs).map(log => `
    <h4>${log}</h4>
    <pre style="background:var(--bg);padding:12px;border-radius:var(--radius);max-height:200px;overflow:auto;">${JSON.stringify(data.logs[log],null,2)}</pre>
  `).join('');
}

// Öffentliche Dateien
async function loadPublic() {
  const res = await fetch(API + '/public/list?admin_session=' + adminSession);
  const data = await res.json();
  const sec = document.getElementById('admin-section-public');
  if (!data.files) { sec.innerHTML = 'Fehler beim Laden.'; return; }
  sec.innerHTML = `<form id="admin-public-upload" style="margin-bottom:18px;display:flex;gap:8px;">
    <input type="file" id="admin-public-file" style="flex:1;">
    <button type="submit" class="btn">Hochladen</button>
  </form>
  <table style="width:100%;border-collapse:collapse;">
    <thead><tr><th>Name</th><th>Größe</th><th></th></tr></thead>
    <tbody>
      ${data.files.map(f => `
        <tr>
          <td>${f.name}</td>
          <td>${(f.size/1024/1024).toFixed(2)} MB</td>
          <td><button class="btn btn-danger" onclick="adminDeletePublic('${f.name}')">Löschen</button></td>
        </tr>
      `).join('')}
    </tbody>
  </table>`;
  document.getElementById('admin-public-upload').onsubmit = async function(e) {
    e.preventDefault();
    const fileInput = document.getElementById('admin-public-file');
    if (!fileInput.files.length) return;
    const form = new FormData();
    form.append('admin_session', adminSession);
    form.append('file', fileInput.files[0]);
    await fetch(API + '/public/upload', { method: 'POST', body: form });
    fileInput.value = '';
    loadPublic();
  };
}
window.adminDeletePublic = async function(name) {
  const form = new FormData();
  form.append('admin_session', adminSession);
  form.append('filename', name);
  await fetch(API + '/public/delete', { method: 'POST', body: form });
  loadPublic();
};

// Speicherplatz
async function loadStorage() {
  const res = await fetch(API + '/users?admin_session=' + adminSession);
  const data = await res.json();
  const sec = document.getElementById('admin-section-storage');
  if (!data.users) { sec.innerHTML = 'Fehler beim Laden.'; return; }
  sec.innerHTML = `<table style="width:100%;border-collapse:collapse;">
    <thead><tr><th>Name</th><th>Speicher (MB)</th><th>Aktion</th></tr></thead>
    <tbody>
      ${data.users.map(u => `
        <tr>
          <td>${u.username}</td>
          <td><input type="number" id="storage-${u.username}" value="${(u.storage_used/1024/1024).toFixed(2)}" style="width:80px;"></td>
          <td><button class="btn" onclick="adminSetStorage('${u.username}')">Setzen</button></td>
        </tr>
      `).join('')}
    </tbody>
  </table>`;
}
window.adminSetStorage = async function(username) {
  const val = document.getElementById('storage-' + username).value;
  const form = new FormData();
  form.append('admin_session', adminSession);
  form.append('username', username);
  form.append('storage', Math.round(val*1024*1024));
  await fetch(API + '/user/storage', { method: 'POST', body: form });
  loadStorage();
};

// Nach Login alles laden
if (adminSession && document.getElementById('admin-dashboard')) {
  document.getElementById('admin-login').style.display = 'none';
  document.getElementById('admin-dashboard').style.display = 'block';
  loadAll();
}
