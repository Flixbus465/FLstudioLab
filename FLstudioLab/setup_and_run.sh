#!/bin/bash

# Dieses Skript richtet die Umgebung ein und startet die FastAPI-Anwendung auf einem Debian-basierten System.

# Beenden Sie das Skript, wenn ein Befehl fehlschlägt
set -e

# 1. Systemabhängigkeiten installieren
echo "--> Installiere Systemabhängigkeiten (erfordert sudo-Rechte)..."
sudo apt-get update
sudo apt-get install -y python3-pip python3-venv libjpeg-dev zlib1g-dev build-essential libssl-dev libffi-dev python3-dev

# 2. Virtuelle Umgebung erstellen und aktivieren
VENV_DIR="venv"
if [ ! -d "$VENV_DIR" ]; then
    echo "--> Erstelle virtuelle Python-Umgebung in '$VENV_DIR'..."
    python3 -m venv $VENV_DIR
fi

echo "--> Aktiviere die virtuelle Umgebung..."
source "$VENV_DIR/bin/activate"

# 3. Python-Abhängigkeiten installieren
echo "--> Installiere Python-Abhängigkeiten aus requirements.txt..."
pip install -r requirements.txt

# 4. Server starten
echo "--> Starte den FastAPI-Server auf http://0.0.0.0:8000..."
uvicorn server.main:app --host 0.0.0.0 --port 8000 