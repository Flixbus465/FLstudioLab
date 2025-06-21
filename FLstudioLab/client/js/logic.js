// FLstudioLab zentrale JS-Logik
// API-URL ggf. anpassen
const API = '/api';
let sessionId = localStorage.getItem('session_id') || null;
let username = null;

// Hilfsfunktionen
function api(path, method = 'GET', data = null, isForm = false) {
  const opts = { method, headers: {} };
  if (data) {
    if (isForm) {
      opts.body = data;
    } else {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(data);
    }
  }
  return fetch(API + path, opts).then(r => r.json());
}

function showError(id, msg) {
  const el = document.getElementById(id);
  if (el) { el.innerText = msg; el.style.display = 'block'; }
}
function hideError(id) {
  const el = document.getElementById(id);
  if (el) { el.innerText = ''; el.style.display = 'none'; }
}

// Login/Registrierung
if (document.getElementById('login-form')) {
  // Login
  document.getElementById('login-form').onsubmit = async function(e) {
    e.preventDefault();
    hideError('login-error');
    const form = new FormData();
    form.append('username', document.getElementById('login-username').value);
    form.append('password', document.getElementById('login-password').value);
    if (document.getElementById('login-2fa').style.display !== 'none') {
      form.append('twofa_code', document.getElementById('login-2fa-code').value);
    }
    if (document.getElementById('login-captcha').style.display !== 'none') {
      form.append('captcha', document.getElementById('login-captcha-input').value);
    }
    const res = await fetch(API + '/login', { method: 'POST', body: form });
    const data = await res.json();
    if (data.session_id) {
      localStorage.setItem('session_id', data.session_id);
      window.location = 'index.html';
    } else if (data.captcha_required) {
      document.getElementById('login-captcha').style.display = 'block';
      showError('login-error', data.msg || 'Captcha erforderlich');
    } else if (data.twofa_required) {
      document.getElementById('login-2fa').style.display = 'block';
      showError('login-error', data.msg || '2FA-Code erforderlich');
    } else {
      showError('login-error', data.detail || data.msg || 'Login fehlgeschlagen');
    }
  };
  // Registrierung
  document.getElementById('register-form').onsubmit = async function(e) {
    e.preventDefault();
    hideError('register-error');
    const username = document.getElementById('register-username').value;
    const password = document.getElementById('register-password').value;
    if (password.length < 32) {
      showError('register-error', 'Passwort zu kurz (min. 32 Zeichen)');
      return;
    }
    const form = new FormData();
    form.append('username', username);
    form.append('password', password);
    const res = await fetch(API + '/register', { method: 'POST', body: form });
    const data = await res.json();
    if (data.msg && data.msg.includes('erfolgreich')) {
      // Optional: 2FA aktivieren
      if (document.getElementById('register-2fa').checked) {
        // Login, dann 2FA aktivieren
        const loginForm = new FormData();
        loginForm.append('username', username);
        loginForm.append('password', password);
        const loginRes = await fetch(API + '/login', { method: 'POST', body: loginForm });
        const loginData = await loginRes.json();
        if (loginData.session_id) {
          localStorage.setItem('session_id', loginData.session_id);
          // 2FA aktivieren
          const twofaForm = new FormData();
          twofaForm.append('session_id', loginData.session_id);
          const twofaRes = await fetch(API + '/2fa/enable', { method: 'POST', body: twofaForm });
          const twofaData = await twofaRes.json();
          if (twofaData.qr_code_url) {
            document.getElementById('register-qr').style.display = 'block';
            document.getElementById('register-qr-img').src = twofaData.qr_code_url;
          }
        }
      } else {
        window.location = 'index.html';
      }
    } else {
      showError('register-error', data.detail || data.msg || 'Registrierung fehlgeschlagen');
    }
  };
}

// Logout
if (document.getElementById('logout-btn')) {
  document.getElementById('logout-btn').onclick = async function() {
    const form = new FormData();
    form.append('session_id', localStorage.getItem('session_id'));
    await fetch(API + '/logout', { method: 'POST', body: form });
    localStorage.removeItem('session_id');
    window.location = 'login.html';
  };
}

// Session prüfen und User-Info laden
async function checkSession() {
  sessionId = localStorage.getItem('session_id');
  if (!sessionId) { window.location = 'login.html'; return; }
  // Dummy-Check: Lade Usernamen aus API (z.B. /files/list)
  const res = await fetch(API + '/files/list?session_id=' + sessionId);
  if (res.status !== 200) { localStorage.removeItem('session_id'); window.location = 'login.html'; return; }
  // Username aus Response extrahieren (optional)
  // username = ...
}
if (document.getElementById('user-info')) checkSession();

// Dynamisches Laden der Modul-Seiten
function loadModule(tab, target) {
  fetch(tab + '.html').then(r => r.text()).then(html => {
    document.getElementById(target).innerHTML = html;
    // Optional: Modul-spezifische Logik initialisieren
  });
}
if (document.getElementById('messenger-view')) loadModule('messenger', 'messenger-view');
if (document.getElementById('files-view')) loadModule('files', 'files-view');
if (document.getElementById('linkshare-view')) loadModule('public_files', 'linkshare-view');
if (document.getElementById('support-view')) loadModule('support', 'support-view');
if (document.getElementById('settings-view')) loadModule('settings', 'settings-view');

// Weitere Modul-Logik (Messenger, Dateien, Support, Settings) kann hier modular ergänzt werden.

// --- Dateien Modul ---
async function initFiles() {
  if (!document.getElementById('files-list')) return;
  const sessionId = localStorage.getItem('session_id');
  // Dateien laden
  async function loadFiles() {
    const res = await fetch(API + '/files/list?session_id=' + sessionId);
    const data = await res.json();
    const tbody = document.getElementById('files-list');
    if (!data.files || !Array.isArray(data.files)) { tbody.innerHTML = '<tr><td colspan="4">Keine Dateien gefunden.</td></tr>'; return; }
    let used = 0;
    tbody.innerHTML = '';
    data.files.forEach(f => {
      used += f.size || 0;
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${f.orig_name || f.name}</td>
        <td>${(f.size/1024/1024).toFixed(2)} MB</td>
        <td>${new Date(f.uploaded*1000).toLocaleString()}</td>
        <td>
          <button class="btn" onclick="downloadFile('${f.name}')">Download</button>
          <button class="btn btn-danger" onclick="deleteFile('${f.name}')">Löschen</button>
        </td>
      `;
      tbody.appendChild(tr);
    });
    document.getElementById('storage-info').innerText = `Speicher: ${(used/1024/1024/1024).toFixed(2)} GB / 4 GB`;
  }
  window.downloadFile = async function(name) {
    window.open(API + '/files/download/' + name + '?session_id=' + sessionId, '_blank');
  };
  window.deleteFile = async function(name) {
    if (!confirm('Datei wirklich löschen?')) return;
    const form = new FormData();
    form.append('session_id', sessionId);
    form.append('filename', name);
    await fetch(API + '/files/delete', { method: 'POST', body: form });
    loadFiles();
  };
  document.getElementById('upload-form').onsubmit = async function(e) {
    e.preventDefault();
    const fileInput = document.getElementById('file-upload');
    if (!fileInput.files.length) return;
    const form = new FormData();
    form.append('session_id', sessionId);
    form.append('file', fileInput.files[0]);
    await fetch(API + '/files/upload', { method: 'POST', body: form });
    fileInput.value = '';
    loadFiles();
  };
  loadFiles();
}
if (document.getElementById('files-view')) setTimeout(initFiles, 300);

// --- Messenger Modul ---
async function initMessenger() {
  if (!document.getElementById('chat-list')) return;
  const sessionId = localStorage.getItem('session_id');
  let currentContact = null;
  let ephemeralMode = false;

  // Kontakte laden
  async function loadContacts() {
    const res = await fetch(API + '/contacts?session_id=' + sessionId);
    const data = await res.json();
    const clist = document.getElementById('chat-list');
    clist.innerHTML = '';
    if (!data.contacts || !data.contacts.length) {
      clist.innerHTML = '<div style="color:var(--text-muted);">Keine Kontakte</div>';
      return;
    }
    data.contacts.forEach(c => {
      const div = document.createElement('div');
      div.className = 'contact';
      div.style = 'padding:8px 0;cursor:pointer;color:var(--text);border-bottom:1px solid var(--border);';
      div.innerText = c;
      div.onclick = () => { openChat(c); };
      clist.appendChild(div);
    });
  }

  // Chat öffnen
  async function openChat(contact) {
    currentContact = contact;
    document.getElementById('chat-header').innerHTML = `<b>Chat mit ${contact}</b>`;
    loadMessages();
  }

  // Nachrichten laden
  async function loadMessages() {
    if (!currentContact) return;
    const ephemeral = document.getElementById('ephemeral-mode').checked;
    const res = await fetch(API + `/messages?session_id=${sessionId}&contact=${encodeURIComponent(currentContact)}&ephemeral=${ephemeral}`);
    const data = await res.json();
    const cmsgs = document.getElementById('chat-messages');
    cmsgs.innerHTML = '';
    if (!data.messages || !data.messages.length) {
      cmsgs.innerHTML = '<div style="color:var(--text-muted);">Keine Nachrichten</div>';
      return;
    }
    data.messages.forEach(m => {
      const div = document.createElement('div');
      div.style = `margin-bottom:10px;${m.from===currentContact?'color:var(--text-muted);':''}`;
      div.innerHTML = `<span style="font-size:0.97rem;"><b>${m.from}</b>: ${m.text}</span> <span style="font-size:0.85rem;color:var(--text-muted);float:right;">${new Date(m.timestamp*1000).toLocaleTimeString()}</span>`;
      cmsgs.appendChild(div);
    });
    cmsgs.scrollTop = cmsgs.scrollHeight;
  }

  // Nachricht senden
  document.getElementById('chat-form').onsubmit = async function(e) {
    e.preventDefault();
    if (!currentContact) return;
    const input = document.getElementById('chat-input');
    const ephemeral = document.getElementById('ephemeral-mode').checked;
    const form = new FormData();
    form.append('session_id', sessionId);
    form.append('contact', currentContact);
    form.append('message', input.value);
    form.append('ephemeral', ephemeral);
    await fetch(API + '/messages/send', { method: 'POST', body: form });
    input.value = '';
    loadMessages();
  };
  document.getElementById('ephemeral-mode').onchange = loadMessages;

  // Auto-Reload alle 5s
  setInterval(() => { if(currentContact) loadMessages(); }, 5000);

  loadContacts();
}
if (document.getElementById('messenger-view')) setTimeout(initMessenger, 400);

// --- Link-Share Modul ---
async function initLinkShare() {
  if (!document.getElementById('share-form')) return;
  const sessionId = localStorage.getItem('session_id');
  document.getElementById('share-form').onsubmit = async function(e) {
    e.preventDefault();
    const fileInput = document.getElementById('share-upload');
    if (!fileInput.files.length) return;
    const form = new FormData();
    form.append('session_id', sessionId);
    form.append('file', fileInput.files[0]);
    const res = await fetch('/api/files/upload', { method: 'POST', body: form });
    const data = await res.json();
    if (data.name) {
      // Jetzt Einmal-Link generieren
      const shareForm = new FormData();
      shareForm.append('session_id', sessionId);
      shareForm.append('filename', data.name);
      const shareRes = await fetch('/api/files/share', { method: 'POST', body: shareForm });
      const shareData = await shareRes.json();
      if (shareData.link) {
        const linkDiv = document.getElementById('share-link');
        linkDiv.style.display = 'block';
        linkDiv.innerHTML = `<b>Dein Einmal-Link:</b> <a href="${shareData.link}" target="_blank">${window.location.origin + shareData.link}</a>`;
      }
    }
    fileInput.value = '';
  };
}
if (document.getElementById('linkshare-view')) setTimeout(initLinkShare, 500);

// --- Support Modul ---
async function initSupport() {
  if (!document.getElementById('support-form')) return;
  const sessionId = localStorage.getItem('session_id');
  const statusDiv = document.getElementById('support-status');
  // Support-Verlauf laden
  async function loadSupport() {
    const res = await fetch('/api/support', { method: 'GET' }); // Optional: Admin-API für Verlauf
    // Für User: nur eigene Nachrichten anzeigen (hier: Dummy)
    // Für Demo: Verlauf ausblenden
    document.getElementById('support-messages').innerHTML = '<div style="color:var(--text-muted);">Support-Verlauf wird nur Admins angezeigt.</div>';
  }
  // Nachricht senden
  document.getElementById('support-form').onsubmit = async function(e) {
    e.preventDefault();
    statusDiv.innerText = '';
    const msg = document.getElementById('support-message').value;
    if (!msg.trim()) return;
    const form = new FormData();
    form.append('session_id', sessionId);
    form.append('message', msg);
    const res = await fetch('/api/support', { method: 'POST', body: form });
    const data = await res.json();
    if (data.msg && data.msg.includes('gesendet')) {
      statusDiv.innerText = 'Nachricht gesendet!';
      document.getElementById('support-message').value = '';
    } else {
      statusDiv.innerText = data.detail || data.msg || 'Fehler beim Senden.';
    }
    setTimeout(() => { statusDiv.innerText = ''; }, 3000);
  };
  loadSupport();
}
if (document.getElementById('support-view')) setTimeout(initSupport, 600);

// --- Settings Modul ---
async function initSettings() {
  if (!document.getElementById('settings-form')) return;
  const sessionId = localStorage.getItem('session_id');
  const statusDiv = document.getElementById('settings-status');
  // 2FA aktivieren
  document.getElementById('settings-2fa').onchange = async function() {
    if (this.checked) {
      const form = new FormData();
      form.append('session_id', sessionId);
      const res = await fetch('/api/2fa/enable', { method: 'POST', body: form });
      const data = await res.json();
      if (data.qr_code_url) {
        document.getElementById('settings-qr').style.display = 'block';
        document.getElementById('settings-qr-img').src = data.qr_code_url;
      }
    } else {
      document.getElementById('settings-qr').style.display = 'none';
      document.getElementById('settings-qr-img').src = '';
      // 2FA deaktivieren (optional)
    }
  };
  // Passwort ändern
  document.getElementById('settings-password-btn').onclick = async function() {
    const pw = document.getElementById('settings-password').value;
    if (pw.length < 32) { statusDiv.innerText = 'Passwort zu kurz (min. 32 Zeichen)'; return; }
    const form = new FormData();
    form.append('session_id', sessionId);
    form.append('new_password', pw);
    const res = await fetch('/api/settings/password', { method: 'POST', body: form });
    const data = await res.json();
    if (data.msg && data.msg.includes('geändert')) {
      statusDiv.innerText = 'Passwort geändert!';
      document.getElementById('settings-password').value = '';
    } else {
      statusDiv.innerText = data.detail || data.msg || 'Fehler beim Ändern.';
    }
    setTimeout(() => { statusDiv.innerText = ''; }, 3000);
  };
  // Emergency-Button
  document.getElementById('emergency-btn').onclick = async function() {
    if (!confirm('Wirklich ALLE Daten und den Account unwiderruflich löschen?')) return;
    const form = new FormData();
    form.append('session_id', sessionId);
    const res = await fetch('/api/emergency', { method: 'POST', body: form });
    const data = await res.json();
    if (data.msg && data.msg.includes('gelöscht')) {
      localStorage.removeItem('session_id');
      window.location = 'login.html';
    } else {
      statusDiv.innerText = data.detail || data.msg || 'Fehler beim Löschen.';
      setTimeout(() => { statusDiv.innerText = ''; }, 3000);
    }
  };
}
if (document.getElementById('settings-view')) setTimeout(initSettings, 700);
