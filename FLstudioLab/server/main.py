from fastapi import FastAPI, HTTPException, Request, Depends, UploadFile, File, Form
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
import bcrypt
import json
import os
import uuid
import time
from typing import Optional, List
import pyotp
import qrcode
from cryptography.fernet import Fernet
import random
import string

app = FastAPI(title="FLstudioLab API")

# CORS für Entwicklung (anpassen für Produktion)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'data')
SECURITY_DIR = os.path.join(os.path.dirname(__file__), '..', 'security')
USERS_FILE = os.path.join(DATA_DIR, 'users.json')
SESSIONS_FILE = os.path.join(DATA_DIR, 'sessions.json')
FILES_DIR = os.path.join(DATA_DIR, 'files')
PUBLIC_DIR = os.path.join(DATA_DIR, 'public')
LOGS_DIR = os.path.join(SECURITY_DIR, 'logs')
LOGIN_ATTEMPTS_FILE = os.path.join(LOGS_DIR, 'login_attempts.json')
MAX_ATTEMPTS = 5
BLOCK_TIME = 3600  # 1 Stunde
QR_CODES_DIR = os.path.join(SECURITY_DIR, 'qr_codes')
MESSAGES_DIR = os.path.join(DATA_DIR, 'messages')
MESSAGE_TTL = 48 * 3600  # 48 Stunden

# Schlüssel für Dateiverschlüsselung (in Produktion pro User generieren!)
FERNET_KEY_FILE = os.path.join(SECURITY_DIR, 'filekey.key')
def get_fernet():
    if not os.path.exists(FERNET_KEY_FILE):
        key = Fernet.generate_key()
        with open(FERNET_KEY_FILE, 'wb') as f:
            f.write(key)
    else:
        with open(FERNET_KEY_FILE, 'rb') as f:
            key = f.read()
    return Fernet(key)

# Hilfsfunktion: Speicherverbrauch berechnen
def get_user_storage(username):
    user_dir = os.path.join(FILES_DIR, username)
    total = 0
    if os.path.exists(user_dir):
        for fname in os.listdir(user_dir):
            fpath = os.path.join(user_dir, fname)
            if os.path.isfile(fpath):
                total += os.path.getsize(fpath)
    return total

MAX_STORAGE = 4 * 1024 * 1024 * 1024  # 4GB

# --- Hilfsfunktionen ---
def load_json(path):
    if not os.path.exists(path):
        return {}
    with open(path, 'r', encoding='utf-8') as f:
        try:
            return json.load(f)
        except Exception:
            return {}

def save_json(path, data):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())

# Hilfsfunktion: IP anonymisieren (Hash)
def anonymize_ip(ip: str) -> str:
    return bcrypt.hashpw(ip.encode(), bcrypt.gensalt()).decode()

def get_client_ip(request: Request) -> str:
    # X-Forwarded-For für Reverse Proxy berücksichtigen
    return request.headers.get('x-forwarded-for', request.client.host)

# Hilfsfunktion: 10-stelliger User-Code
def generate_user_code():
    return ''.join(random.choices(string.digits, k=10))

# --- Models ---
class User(BaseModel):
    username: str
    password: str
    twofa_enabled: bool = False
    twofa_secret: Optional[str] = None
    storage_used: int = 0
    is_admin: bool = False
    blocked: bool = False
    user_code: str
    contacts: List[str]
    files: List[dict]

class Session(BaseModel):
    session_id: str
    username: str
    expires: float
    ip_hash: str

SESSIONS_LOG_FILE = os.path.join(LOGS_DIR, 'sessions.json')

# Session-Log speichern
def log_session_event(event_type, session_id, username, ip_hash):
    log = []
    if os.path.exists(SESSIONS_LOG_FILE):
        try:
            with open(SESSIONS_LOG_FILE, 'r', encoding='utf-8') as f:
                log = json.load(f)
        except Exception:
            log = []
    log.append({
        "timestamp": int(time.time()),
        "event": event_type,
        "session_id": session_id,
        "username": username,
        "ip_hash": ip_hash
    })
    with open(SESSIONS_LOG_FILE, 'w', encoding='utf-8') as f:
        json.dump(log, f, indent=2, ensure_ascii=False)

# Session-Validierung mit Ablauf und IP-Hash

def validate_session(session_id, request: Request):
    sessions = load_json(SESSIONS_FILE)
    session = sessions.get(session_id)
    if not session:
        return None
    # Ablauf prüfen
    if session["expires"] < time.time():
        del sessions[session_id]
        save_json(SESSIONS_FILE, sessions)
        return None
    # IP-Hash prüfen
    client_ip = get_client_ip(request)
    ip_hash = session["ip_hash"]
    if not bcrypt.checkpw(client_ip.encode(), ip_hash.encode()):
        return None
    return session

# --- Auth & Session ---
@app.post("/api/register")
def register(username: str = Form(...), password: str = Form(...)):
    if len(password) < 32:
        raise HTTPException(status_code=400, detail="Passwort zu kurz (min. 32 Zeichen)")
    users = load_json(USERS_FILE)
    if username in users:
        raise HTTPException(status_code=409, detail="Benutzername existiert bereits")
    users[username] = {
        "password": hash_password(password),
        "twofa_enabled": False,
        "storage_used": 0,
        "is_admin": False,
        "blocked": False,
        "user_code": generate_user_code(),
        "contacts": [],
        "files": []
    }
    save_json(USERS_FILE, users)
    return {"msg": "Registrierung erfolgreich"}

@app.post("/api/login")
def login(request: Request, username: str = Form(...), password: str = Form(...), captcha: str = Form(None), twofa_code: str = Form(None)):
    users = load_json(USERS_FILE)
    login_attempts = load_json(LOGIN_ATTEMPTS_FILE)
    client_ip = get_client_ip(request)
    ip_entry = login_attempts.get(client_ip, {"fails": 0, "blocked_until": 0})
    now = time.time()
    # IP-Sperre prüfen
    if ip_entry["blocked_until"] > now:
        raise HTTPException(status_code=429, detail=f"Zu viele Fehlversuche. IP für 1 Stunde gesperrt.")
    # Captcha-Prüfung (Platzhalter)
    if ip_entry["fails"] >= 3 and captcha != "42":
        return JSONResponse(status_code=403, content={"captcha_required": True, "msg": "Captcha erforderlich"})
    user = users.get(username)
    if not user or not verify_password(password, user["password"]):
        ip_entry["fails"] += 1
        if ip_entry["fails"] >= MAX_ATTEMPTS:
            ip_entry["blocked_until"] = now + BLOCK_TIME
        login_attempts[client_ip] = ip_entry
        save_json(LOGIN_ATTEMPTS_FILE, login_attempts)
        raise HTTPException(status_code=401, detail="Login fehlgeschlagen")
    if user.get("blocked"):
        raise HTTPException(status_code=403, detail="Account gesperrt")
    # 2FA aktiviert?
    if user.get("twofa_enabled"):
        secret = user.get("twofa_secret")
        if not twofa_code:
            return JSONResponse(status_code=401, content={"twofa_required": True, "msg": "2FA-Code erforderlich"})
        totp = pyotp.TOTP(secret)
        if not totp.verify(twofa_code):
            ip_entry["fails"] += 1
            if ip_entry["fails"] >= MAX_ATTEMPTS:
                ip_entry["blocked_until"] = now + BLOCK_TIME
            login_attempts[client_ip] = ip_entry
            save_json(LOGIN_ATTEMPTS_FILE, login_attempts)
            raise HTTPException(status_code=401, detail="2FA-Code ungültig")
    # Erfolgreich: Fehlversuche zurücksetzen
    if client_ip in login_attempts:
        del login_attempts[client_ip]
        save_json(LOGIN_ATTEMPTS_FILE, login_attempts)
    session_id = str(uuid.uuid4())
    ip_hash = anonymize_ip(client_ip)
    sessions = load_json(SESSIONS_FILE)
    sessions[session_id] = {
        "username": username,
        "expires": time.time() + 3600,
        "ip_hash": ip_hash
    }
    save_json(SESSIONS_FILE, sessions)
    return {"session_id": session_id, "twofa": user.get("twofa_enabled", False)}

@app.post("/api/logout")
def logout(request: Request, session_id: str = Form(...)):
    sessions = load_json(SESSIONS_FILE)
    session = sessions.get(session_id)
    if session:
        log_session_event("logout", session_id, session["username"], session["ip_hash"])
        del sessions[session_id]
        save_json(SESSIONS_FILE, sessions)
    return {"msg": "Logout erfolgreich"}

# --- 2FA (Platzhalter) ---
@app.post("/api/2fa/enable")
def enable_2fa(session_id: str = Form(...)):
    sessions = load_json(SESSIONS_FILE)
    users = load_json(USERS_FILE)
    session = sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=401, detail="Session ungültig")
    username = session["username"]
    user = users.get(username)
    if not user:
        raise HTTPException(status_code=404, detail="User nicht gefunden")
    # Neues Secret generieren
    secret = pyotp.random_base32()
    user["twofa_enabled"] = True
    user["twofa_secret"] = secret
    users[username] = user
    save_json(USERS_FILE, users)
    # QR-Code generieren
    otp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="FLstudioLab")
    qr_path = os.path.join(QR_CODES_DIR, f"{username}.png")
    img = qrcode.make(otp_uri)
    with open(qr_path, 'wb') as f:
        img.save(f)
    return {"msg": "2FA aktiviert", "qr_code_url": f"/api/2fa/qr/{username}"}

@app.get("/api/2fa/qr/{username}")
def get_2fa_qr(username: str):
    qr_path = os.path.join(QR_CODES_DIR, f"{username}.png")
    if not os.path.exists(qr_path):
        raise HTTPException(status_code=404, detail="QR-Code nicht gefunden")
    return FileResponse(qr_path, media_type="image/png")

@app.post("/api/2fa/verify")
def verify_2fa(session_id: str = Form(...), code: str = Form(...)):
    sessions = load_json(SESSIONS_FILE)
    users = load_json(USERS_FILE)
    session = sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=401, detail="Session ungültig")
    username = session["username"]
    user = users.get(username)
    if not user or not user.get("twofa_enabled"):
        raise HTTPException(status_code=400, detail="2FA nicht aktiviert")
    secret = user.get("twofa_secret")
    totp = pyotp.TOTP(secret)
    if not totp.verify(code):
        raise HTTPException(status_code=401, detail="2FA-Code ungültig")
    return {"msg": "2FA erfolgreich"}

# --- Datei-API ---
@app.post("/api/files/upload")
def upload_file(session_id: str = Form(...), file: UploadFile = File(...)):
    sessions = load_json(SESSIONS_FILE)
    users = load_json(USERS_FILE)
    session = sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=401, detail="Session ungültig")
    username = session["username"]
    user = users.get(username)
    if not user:
        raise HTTPException(status_code=404, detail="User nicht gefunden")

    user_dir = os.path.join(FILES_DIR, username)
    os.makedirs(user_dir, exist_ok=True)
    # Speicher prüfen
    storage_used = get_user_storage(username)
    file_bytes = file.file.read()
    if storage_used + len(file_bytes) > MAX_STORAGE:
        raise HTTPException(status_code=413, detail="Speicherlimit erreicht (4GB)")
    # Verschlüsseln & speichern
    fernet = get_fernet()
    encrypted = fernet.encrypt(file_bytes)
    fname = f"{int(time.time())}_{file.filename}"
    fpath = os.path.join(user_dir, fname)
    with open(fpath, 'wb') as f:
        f.write(encrypted)
    # Metadaten speichern
    user.setdefault("files", []).append({
        "name": fname,
        "orig_name": file.filename,
        "size": len(encrypted),
        "uploaded": int(time.time())
    })
    users[username] = user
    save_json(USERS_FILE, users)
    return {"msg": "Datei hochgeladen", "name": fname}

@app.get("/api/files/list")
def list_files(session_id: str):
    sessions = load_json(SESSIONS_FILE)
    users = load_json(USERS_FILE)
    session = sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=401, detail="Session ungültig")
    username = session["username"]
    user = users.get(username, {})
    return {"files": user.get("files", [])}

@app.post("/api/files/delete")
def delete_file(session_id: str = Form(...), filename: str = Form(...)):
    sessions = load_json(SESSIONS_FILE)
    users = load_json(USERS_FILE)
    session = sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=401, detail="Session ungültig")
    username = session["username"]
    user_dir = os.path.join(FILES_DIR, username)
    fpath = os.path.join(user_dir, filename)
    if os.path.exists(fpath):
        os.remove(fpath)
    # Metadaten aktualisieren
    user = users.get(username, {})
    user["files"] = [f for f in user.get("files", []) if f["name"] != filename]
    users[username] = user
    save_json(USERS_FILE, users)
    return {"msg": "Datei gelöscht"}

@app.get("/api/files/download/{filename}")
def download_file(session_id: str, filename: str):
    sessions = load_json(SESSIONS_FILE)
    users = load_json(USERS_FILE)
    session = sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=401, detail="Session ungültig")
    username = session["username"]
    user_dir = os.path.join(FILES_DIR, username)
    fpath = os.path.join(user_dir, filename)
    if not os.path.exists(fpath):
        raise HTTPException(status_code=404, detail="Datei nicht gefunden")

    # Datei entschlüsseln
    fernet = get_fernet()
    with open(fpath, 'rb') as f:
        encrypted_data = f.read()
    try:
        decrypted_data = fernet.decrypt(encrypted_data)
    except Exception:
        raise HTTPException(status_code=500, detail="Entschlüsselung fehlgeschlagen")

    # Originalname aus Metadaten holen
    user = users.get(username, {})
    orig_name = filename
    for fmeta in user.get("files", []):
        if fmeta["name"] == filename:
            orig_name = fmeta.get("orig_name", filename)
            break

    headers = {'Content-Disposition': f'attachment; filename="{orig_name}"'}
    return Response(content=decrypted_data, media_type='application/octet-stream', headers=headers)

# --- Öffentliche Links ---
PUBLIC_LINKS_FILE = os.path.join(DATA_DIR, 'public_links.json')

@app.post("/api/files/share")
def share_file(session_id: str = Form(...), filename: str = Form(...)):
    sessions = load_json(SESSIONS_FILE)
    users = load_json(USERS_FILE)
    public_links = load_json(PUBLIC_LINKS_FILE)
    session = sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=401, detail="Session ungültig")
    username = session["username"]
    user_dir = os.path.join(FILES_DIR, username)
    fpath = os.path.join(user_dir, filename)
    if not os.path.exists(fpath):
        raise HTTPException(status_code=404, detail="Datei nicht gefunden")
    link_id = str(uuid.uuid4())
    public_links[link_id] = {
        "username": username,
        "filename": filename,
        "created": int(time.time()),
        "expires": int(time.time()) + 24*3600,
        "used": False
    }
    save_json(PUBLIC_LINKS_FILE, public_links)
    return {"link": f"/api/files/public/{link_id}"}

@app.get("/api/files/public/{link_id}")
def public_download(link_id: str):
    public_links = load_json(PUBLIC_LINKS_FILE)
    link = public_links.get(link_id)
    if not link:
        raise HTTPException(status_code=404, detail="Link nicht gefunden")
    if link.get("used") or time.time() > link.get("expires", 0):
        if link_id in public_links:
            del public_links[link_id]
            save_json(PUBLIC_LINKS_FILE, public_links)
        raise HTTPException(status_code=410, detail="Link abgelaufen oder bereits verwendet")

    # Datei bereitstellen
    username = link["username"]
    filename = link["filename"]
    user_dir = os.path.join(FILES_DIR, username)
    fpath = os.path.join(user_dir, filename)
    if not os.path.exists(fpath):
        raise HTTPException(status_code=404, detail="Datei nicht gefunden")

    # Datei entschlüsseln
    fernet = get_fernet()
    with open(fpath, 'rb') as f:
        encrypted_data = f.read()
    try:
        decrypted_data = fernet.decrypt(encrypted_data)
    except Exception:
        # Link trotzdem als verbraucht markieren, um wiederholte Versuche zu verhindern
        link["used"] = True
        save_json(PUBLIC_LINKS_FILE, public_links)
        raise HTTPException(status_code=500, detail="Entschlüsselung fehlgeschlagen")

    # Link als verwendet markieren
    link["used"] = True
    save_json(PUBLIC_LINKS_FILE, public_links)

    # Originalname aus Metadaten
    users = load_json(USERS_FILE)
    user = users.get(username, {})
    orig_name = filename
    for fmeta in user.get("files", []):
        if fmeta["name"] == filename:
            orig_name = fmeta.get("orig_name", filename)
            break
            
    # Datei als Download zurückgeben
    headers = {'Content-Disposition': f'attachment; filename="{orig_name}"'}
    return Response(content=decrypted_data, media_type='application/octet-stream', headers=headers)

# --- Messenger (Platzhalter) ---
def chat_filename(user1, user2):
    # Alphabetisch sortiert für eindeutige Datei
    users = sorted([user1, user2])
    return os.path.join(MESSAGES_DIR, f"{users[0]}_{users[1]}.json")

def load_chat(user1, user2):
    path = chat_filename(user1, user2)
    if not os.path.exists(path):
        return []
    with open(path, 'r', encoding='utf-8') as f:
        try:
            return json.load(f)
        except Exception:
            return []

def save_chat(user1, user2, messages):
    path = chat_filename(user1, user2)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(messages, f, indent=2, ensure_ascii=False)

def cleanup_old_messages(messages):
    now = time.time()
    return [m for m in messages if now - m['timestamp'] <= MESSAGE_TTL]

@app.post("/api/messages/send")
def send_message(session_id: str = Form(...), contact: str = Form(...), message: str = Form(...), ephemeral: bool = Form(False)):
    sessions = load_json(SESSIONS_FILE)
    users = load_json(USERS_FILE)
    session = sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=401, detail="Session ungültig")
    sender = session["username"]
    if contact not in users:
        raise HTTPException(status_code=404, detail="Kontakt nicht gefunden")
    # Nachricht speichern
    messages = load_chat(sender, contact)
    now = time.time()
    msg = {
        "from": sender,
        "to": contact,
        "text": message,
        "timestamp": now,
        "ephemeral": ephemeral
    }
    messages.append(msg)
    messages = cleanup_old_messages(messages)
    save_chat(sender, contact, messages)
    # Kontakte aktualisieren
    for user in [sender, contact]:
        u = users.get(user, {})
        if "contacts" in u and contact not in u["contacts"] and user != contact:
            u["contacts"].append(contact)
            users[user] = u
    save_json(USERS_FILE, users)
    return {"msg": "Nachricht gesendet"}

@app.get("/api/messages")
def get_messages(session_id: str, contact: str, ephemeral: bool = False):
    sessions = load_json(SESSIONS_FILE)
    users = load_json(USERS_FILE)
    session = sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=401, detail="Session ungültig")
    username = session["username"]
    if contact not in users:
        raise HTTPException(status_code=404, detail="Kontakt nicht gefunden")
    messages = load_chat(username, contact)
    messages = cleanup_old_messages(messages)
    # Flüchtiger Modus: Nur nicht-ephemere oder alle, je nach Modus
    if ephemeral:
        ephemeral_msgs = [m for m in messages if m.get('ephemeral')]
        # Nach Abruf löschen
        save_chat(username, contact, [m for m in messages if not m.get('ephemeral')])
        return {"messages": ephemeral_msgs}
    else:
        return {"messages": [m for m in messages if not m.get('ephemeral')]}

@app.get("/api/contacts")
def get_contacts(session_id: str):
    sessions = load_json(SESSIONS_FILE)
    users = load_json(USERS_FILE)
    session = sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=401, detail="Session ungültig")
    username = session["username"]
    user = users.get(username, {})
    return {"contacts": user.get("contacts", [])}

# --- Support ---
SUPPORT_FILE = os.path.join(DATA_DIR, 'support.json')

def load_support():
    if not os.path.exists(SUPPORT_FILE):
        return []
    with open(SUPPORT_FILE, 'r', encoding='utf-8') as f:
        try:
            return json.load(f)
        except Exception:
            return []

def save_support(messages):
    with open(SUPPORT_FILE, 'w', encoding='utf-8') as f:
        json.dump(messages, f, indent=2, ensure_ascii=False)

@app.post("/api/support")
def send_support(request: Request, session_id: str = Form(None), message: str = Form(...)):
    support = load_support()
    users = load_json(USERS_FILE)
    username = None
    if session_id:
        sessions = load_json(SESSIONS_FILE)
        session = sessions.get(session_id)
        if session:
            username = session["username"]
    client_ip = get_client_ip(request)
    entry = {
        "timestamp": int(time.time()),
        "message": message,
        "username": username,
        "ip_hash": anonymize_ip(client_ip)
    }
    support.append(entry)
    save_support(support)
    return {"msg": "Support-Nachricht gesendet"}

@app.get("/api/admin/support")
def admin_get_support(admin_session: str):
    if not validate_admin_session(admin_session):
        raise HTTPException(status_code=401, detail="Admin-Session ungültig")
    support = load_support()
    return {"support": support}

# --- Admin-API ---
ADMIN_SESSION_FILE = os.path.join(DATA_DIR, 'admin_sessions.json')

def create_admin_session():
    admin_sessions = load_json(ADMIN_SESSION_FILE)
    session_id = str(uuid.uuid4())
    admin_sessions[session_id] = {"created": int(time.time())}
    save_json(ADMIN_SESSION_FILE, admin_sessions)
    return session_id

def validate_admin_session(session_id):
    admin_sessions = load_json(ADMIN_SESSION_FILE)
    return session_id in admin_sessions

@app.post("/api/admin/login")
def admin_login(username: str = Form(...), password: str = Form(...)):
    if username == "admin" and password == "adminroot":
        session_id = create_admin_session()
        return {"admin_session": session_id}
    raise HTTPException(status_code=401, detail="Admin-Login fehlgeschlagen")

@app.get("/api/admin/users")
def admin_list_users(admin_session: str):
    if not validate_admin_session(admin_session):
        raise HTTPException(status_code=401, detail="Admin-Session ungültig")
    users = load_json(USERS_FILE)
    return {"users": [{"username": u, **{k: v for k, v in v.items() if k != 'password'}} for u, v in users.items()]}

@app.post("/api/admin/user/block")
def admin_block_user(admin_session: str = Form(...), username: str = Form(...)):
    if not validate_admin_session(admin_session):
        raise HTTPException(status_code=401, detail="Admin-Session ungültig")
    users = load_json(USERS_FILE)
    if username in users:
        users[username]["blocked"] = True
        save_json(USERS_FILE, users)
        return {"msg": f"User {username} geblockt"}
    raise HTTPException(status_code=404, detail="User nicht gefunden")

@app.post("/api/admin/user/unblock")
def admin_unblock_user(admin_session: str = Form(...), username: str = Form(...)):
    if not validate_admin_session(admin_session):
        raise HTTPException(status_code=401, detail="Admin-Session ungültig")
    users = load_json(USERS_FILE)
    if username in users:
        users[username]["blocked"] = False
        save_json(USERS_FILE, users)
        return {"msg": f"User {username} freigeschaltet"}
    raise HTTPException(status_code=404, detail="User nicht gefunden")

@app.post("/api/admin/user/delete")
def admin_delete_user(admin_session: str = Form(...), username: str = Form(...)):
    if not validate_admin_session(admin_session):
        raise HTTPException(status_code=401, detail="Admin-Session ungültig")
    
    users = load_json(USERS_FILE)
    if username not in users:
        raise HTTPException(status_code=404, detail="User nicht gefunden")
        
    _delete_user_data(username)
    
    # Sessions des gelöschten Users beenden
    sessions = load_json(SESSIONS_FILE)
    sessions_to_delete = [sid for sid, s in sessions.items() if s.get("username") == username]
    for sid in sessions_to_delete:
        del sessions[sid]
    save_json(SESSIONS_FILE, sessions)
    
    return {"msg": f"User {username} und alle zugehörigen Daten wurden gelöscht."}

@app.get("/api/admin/logs")
def admin_get_logs(admin_session: str):
    if not validate_admin_session(admin_session):
        raise HTTPException(status_code=401, detail="Admin-Session ungültig")
    logs = {}
    if os.path.exists(LOGS_DIR):
        for fname in os.listdir(LOGS_DIR):
            fpath = os.path.join(LOGS_DIR, fname)
            if os.path.isfile(fpath):
                with open(fpath, 'r', encoding='utf-8') as f:
                    try:
                        logs[fname] = json.load(f)
                    except Exception:
                        logs[fname] = []
    return {"logs": logs}

@app.post("/api/admin/user/storage")
def admin_set_storage(admin_session: str = Form(...), username: str = Form(...), storage: int = Form(...)):
    if not validate_admin_session(admin_session):
        raise HTTPException(status_code=401, detail="Admin-Session ungültig")
    users = load_json(USERS_FILE)
    if username in users:
        users[username]["storage_used"] = storage
        save_json(USERS_FILE, users)
        return {"msg": f"Speicher für {username} gesetzt"}
    raise HTTPException(status_code=404, detail="User nicht gefunden")

# Öffentliche Dateien verwalten (Platzhalter)
@app.post("/api/admin/public/upload")
def admin_upload_public(admin_session: str = Form(...), file: UploadFile = File(...)):
    if not validate_admin_session(admin_session):
        raise HTTPException(status_code=401, detail="Admin-Session ungültig")
    fpath = os.path.join(PUBLIC_DIR, file.filename)
    with open(fpath, 'wb') as f:
        f.write(file.file.read())
    return {"msg": "Datei hochgeladen", "name": file.filename}

@app.get("/api/admin/public/list")
def admin_list_public(admin_session: str):
    if not validate_admin_session(admin_session):
        raise HTTPException(status_code=401, detail="Admin-Session ungültig")
    files = []
    if os.path.exists(PUBLIC_DIR):
        for fname in os.listdir(PUBLIC_DIR):
            fpath = os.path.join(PUBLIC_DIR, fname)
            if os.path.isfile(fpath):
                files.append({"name": fname, "size": os.path.getsize(fpath)})
    return {"files": files}

@app.post("/api/admin/public/delete")
def admin_delete_public(admin_session: str = Form(...), filename: str = Form(...)):
    if not validate_admin_session(admin_session):
        raise HTTPException(status_code=401, detail="Admin-Session ungültig")
    fpath = os.path.join(PUBLIC_DIR, filename)
    if os.path.exists(fpath):
        os.remove(fpath)
        return {"msg": "Datei gelöscht"}
    raise HTTPException(status_code=404, detail="Datei nicht gefunden")

# --- Helper für User-Löschung ---
def _delete_user_data(username: str):
    """Löscht alle Daten, die mit einem Benutzer verbunden sind."""
    users = load_json(USERS_FILE)
    
    # 1. Dateien löschen
    user_dir = os.path.join(FILES_DIR, username)
    if os.path.exists(user_dir):
        for fname in os.listdir(user_dir):
            fpath = os.path.join(user_dir, fname)
            if os.path.isfile(fpath):
                os.remove(fpath)
        # Verzeichnis nur löschen, wenn es leer ist
        if not os.listdir(user_dir):
            os.rmdir(user_dir)
        
    # 2. Nachrichten löschen
    if os.path.exists(MESSAGES_DIR):
        for fname in os.listdir(MESSAGES_DIR):
            if username in fname.split('_'):
                fpath = os.path.join(MESSAGES_DIR, fname)
                os.remove(fpath)
                
    # 3. Öffentliche Links löschen
    public_links = load_json(PUBLIC_LINKS_FILE)
    to_delete = [lid for lid, l in public_links.items() if l.get("username") == username]
    for lid in to_delete:
        del public_links[lid]
    save_json(PUBLIC_LINKS_FILE, public_links)
    
    # 4. Support-Nachrichten anonymisieren
    support = load_support()
    for entry in support:
        if entry.get("username") == username:
            entry["username"] = f"deleted_user_{str(uuid.uuid4())[:8]}"
    save_support(support)
    
    # 5. User aus Kontakten anderer User entfernen
    all_users = load_json(USERS_FILE)
    for u, u_data in all_users.items():
        if "contacts" in u_data and username in u_data["contacts"]:
            u_data["contacts"].remove(username)
    save_json(USERS_FILE, all_users)

    # 6. User löschen
    if username in all_users:
        del all_users[username]
        save_json(USERS_FILE, all_users)

# --- Emergency Button ---
@app.post("/api/emergency")
def emergency_delete(request: Request, session_id: str = Form(...)):
    sessions = load_json(SESSIONS_FILE)
    session = validate_session(session_id, request)
    if not session:
        raise HTTPException(status_code=401, detail="Session ungültig")
    
    username = session["username"]
    _delete_user_data(username)
    
    # Eigene Session löschen
    if session_id in sessions:
        del sessions[session_id]
        save_json(SESSIONS_FILE, sessions)
        
    return {"msg": "Account & alle Daten gelöscht"}

# --- Healthcheck ---
@app.get("/api/ping")
def ping():
    return {"status": "ok"}

@app.post("/api/settings/password")
def change_password(request: Request, session_id: str = Form(...), new_password: str = Form(...)):
    if len(new_password) < 32:
        raise HTTPException(status_code=400, detail="Passwort zu kurz (min. 32 Zeichen)")
    sessions = load_json(SESSIONS_FILE)
    users = load_json(USERS_FILE)
    session = validate_session(session_id, request)
    if not session:
        raise HTTPException(status_code=401, detail="Session ungültig")
    username = session["username"]
    user = users.get(username)
    if not user:
        raise HTTPException(status_code=404, detail="User nicht gefunden")
    user["password"] = hash_password(new_password)
    users[username] = user
    save_json(USERS_FILE, users)
    return {"msg": "Passwort geändert"}
