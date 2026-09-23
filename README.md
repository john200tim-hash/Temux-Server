# Termux Server 📱⚡

Ein leichtgewichtiger Python-Edge-Security-Gateway & Web-Server, der direkt auf einem Android-Gerät über **Termux** ausgeführt wird, um lokale Webanwendungen bereitzustellen und den Datenverkehr durch WAF-Regeln zu überwachen und zu schützen.

## 🚀 Übersicht
Dieses Projekt demonstriert, wie man ausrangierte mobile Hardware (Tecno Pop 4 Pro mit MediaTek MT6739 und defektem Touchscreen) ressourcenschonend in einen vollwertigen, drahtlosen Linux-Server verwandelt. Es zeigt praxisnahe Problemlösungskompetenz und Ingenieursgeist, wenn physische Labor-Hardware oder teure Cloud-Infrastruktur nicht verfügbar ist.

## 🌟 Hauptfunktionen
- **Edge Security Gateway & WAF:** Deep-Packet Payload-Inspektion zur Erkennung von SQL-Injections, Cross-Site Scripting (XSS), Path-Traversal (`../`) und Command Injection.
- **Token-Bucket Rate Limiter:** Schutz vor DoS-Angriffen mit automatischer `429 Too Many Requests`-Drosselung.
- **Echtzeit-Web-GUI & Dashboard:** Integriertes Admin-Dashboard (`/dashboard`) mit Statistiken, Live-Threat-Logs und Client-Übersicht.
- **Dynamische IP-Filter:** GUI-gestütztes Whitelisting und Blacklisting von Client-IPs mit SQLite-Persistenz.
- **Integrierte Netzwerk- & Router-Tools:** DNS-Lookup, Ping-Latenz-Messung, Port-Scanner und Routing-Tabellen-Inspektion direkt vom Smartphone aus.
- **Zentrale Windows-Verwaltung:** Vollständige Steuerung über ein zentrales Steuerungs-Skript (`server_manager.bat`) inklusive drahtlosem ADB, SSH und Scrcpy-Display-Spiegelung.

## 🛠️ Verwendung & Technische Schritte

1. **Termux-Speicher konfigurieren:**
   ```bash
   termux-setup-storage
   ```

2. **Abhängigkeiten installieren:**
   ```bash
   pip install starlette uvicorn aiosqlite
   ```

3. **Gateway im Hintergrund starten:**
   ```bash
   nohup python -m uvicorn secure_gateway:app --host 0.0.0.0 --port 8000 --workers 1 > ~/gateway.log 2>&1 &
   ```

4. **Web-GUI aufrufen:**
   Im Browser unter: `http://<GERÄTE-IP>:8000/dashboard`

## 📸 Screenshots der Umgebung
Dokumentations-Screenshots der Termux-Konsole und der aktiven Server-Umgebung befinden sich im Ordner `screenshots/`.

## 🔒 Sicherheit & Datenschutz
Dieses Repository enthält strikte `.gitignore`-Regeln, um sicherzustellen, dass niemals sensible Daten, Tokens, Log-Dateien oder lokale SQLite-Datenbanken veröffentlicht werden.
