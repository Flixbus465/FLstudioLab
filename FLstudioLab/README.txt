FLstudioLab – Sichere, modulare Webplattform
============================================

**Features:**
- Login-System mit 2FA, Captcha, IP-Block, Passwort-Hashing (bcrypt)
- Messenger (persistente & flüchtige Chats)
- Dateiverwaltung (verschlüsselt, 4GB/User, Einmal-Link)
- Support-System
- Admin-Konsole (Port 8081)
- Darkmode, modernes UI, modular


Schnellstart
------------
1. **Abhängigkeiten installieren**
   (Python 3.9+, Node nicht nötig)

   ```sh
   pip install -r requirements.txt
   ```

2. **Backend starten**
   ```sh
   python -m uvicorn server.main:app --reload
   ```
   → API läuft auf http://127.0.0.1:8000

3. **Frontend öffnen**
   - Öffne `client/login.html` im Browser (z.B. per Live-Server/VSCode oder lokal)
   - Nach Login: `client/index.html`

4. **Admin-Konsole**
   - Öffne `admin/index.html` im Browser
   - Login: Name: `admin`, Passwort: `adminroot`


Verzeichnisstruktur
-------------------
- `server/` – FastAPI Backend
- `client/` – Frontend (HTML, CSS, JS)
- `admin/` – Admin-Frontend
- `data/` – Userdaten, Sessions, Dateien
- `security/` – Logs, QR-Codes, Schlüssel


Sicherheit & Hinweise
---------------------
- Passwörter: min. 32 Zeichen, bcrypt-Hash
- 2FA optional (QR-Code für Authenticator-App)
- Nach 5 Fehlversuchen: IP-Sperre (1h)
- Captcha nach 3 Fehlversuchen (Dummy)
- Dateien verschlüsselt (Fernet)
- Öffentliche Links: 1x oder 24h gültig
- Emergency-Button: Account & Daten unwiderruflich löschen
- Admin kann Nutzer blockieren/freischalten/löschen


Deployment-Tipps
----------------
- **Produktiv:**
  - Reverse Proxy (z.B. NGINX)
  - TLS/SSL (Let's Encrypt)
  - Fail2Ban für IP-Blockierung
  - Daten-Backups
- **Start:**
  ```sh
  python -m uvicorn server.main:app --host 0.0.0.0 --port 8000
  ```
- **Admin-Frontend:**
  - Kann auf Port 8081 gehostet werden (z.B. mit eigenem Webserver)


Support & Kontakt
-----------------
- Bei Fragen: felixlinster@gmail.com


Viel Erfolg mit FLstudioLab!


