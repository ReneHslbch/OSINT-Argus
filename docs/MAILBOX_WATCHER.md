# API-2: Mailbox Watcher Setup

## Übersicht

Der `mailbox_watcher.py` ist ein eigenständiger Worker-Prozess, der weitergeleitete Verdachtsmails entgegennimmt, durch die OSINT-Argus-Pipeline analysiert und eine Antwort-Mail mit dem Ergebnis zurücksendet.

## Voraussetzungen

1. **Gmail-Konto** (oder anderes IMAP-fähiges Postfach) für `osintargus@gmail.com`
2. **App-Passwort** für IMAP/SMTP-Zugang (bei Gmail: Google Account → Security → 2-Step Verification → App passwords)
3. **Python 3.10+** mit installierten Dependencies

## Installation

### 1. Dependencies installieren

```bash
pip install -r requirements.txt
```

### 2. `.env` konfigurieren

Folgende Variablen müssen in `.env` gesetzt werden:

```env
# IMAP-Empfang
MONITOR_MAILBOX_IMAP_SERVER=imap.gmail.com
MONITOR_MAILBOX_IMAP_PORT=993
MONITOR_MAILBOX_ADDRESS=osintargus@gmail.com
MONITOR_MAILBOX_PASSWORD=<dein-Gmail-App-Passwort>
MONITOR_MAILBOX_USE_SSL=true
MONITOR_MAILBOX_FOLDER=INBOX

# SMTP-Versand
MONITOR_SMTP_SERVER=smtp.gmail.com
MONITOR_SMTP_PORT=587
MONITOR_SMTP_USE_TLS=true

# Rate-Limiting (Missbrauchsschutz)
RATE_LIMIT_MAX_ANALYSES_PER_SENDER=5
RATE_LIMIT_WINDOW_HOURS=24

# Polling-Intervall
MAILBOX_POLL_INTERVAL_SECONDS=60

# Attachment-Limit (10 MB)
MAX_ATTACHMENT_SIZE_BYTES=10485760
```

### Gmail-spezifische Einrichtung

1. **2-Step Verification** im Google Account aktivieren
2. **App Password** generieren (16-Zeichen-String)
3. App-Passwort in `.env` bei `MONITOR_MAILBOX_PASSWORD` einfügen
4. IMAP in Gmail-Einstellungen aktivieren (Settings → Forwarding and POP/IMAP → Enable IMAP)

## Starten

### Direkt im Terminal

```bash
python -m app.mailbox_watcher
```

### Als Hintergrundprozess (Windows)

```powershell
start powershell -WindowStyle Hidden -Command "cd 'C:\Users\rhaselbach\Documents\uni\OSINT-Argus'; python -m app.mailbox_watcher"
```

### Mit custom Poll-Intervall

```bash
python -m app.mailbox_watcher --interval 30
```

## Funktionsweise

1. **IMAP-Polling**: Alle 60 Sekunden wird der INBOX auf ungelesene Nachrichten geprüft
2. **Inhaltsextraktion**: Plain-Text und HTML werden aus der Email extrahiert, Anhänge temporär gespeichert
3. **Spracherkennung**: Automatische Erkennung von Deutsch/Englisch basierend auf häufigen Wörtern
4. **Pipeline-Analyse**: `build_initial_state()` + `graph.invoke()` aus der bestehenden Pipeline
5. **Report-Generierung**: `OutputAgent` erstellt strukturierten Bericht
6. **SMTP-Antwort**: Text- und HTML-Version werden an den Absender gesendet
7. **Markierung**: Verarbeitete Emails werden als `\Seen` markiert

## Rate-Limiting

- **Standard**: Maximal 5 Analysen pro Absenderadresse pro 24-Stunden-Fenster
- **Schutz**: Verhindert, dass die öffentliche Adresse als kostenpflichtiges Ziel gegen VirusTotal/NVD-Quota missbraucht wird
- **Konfigurierbar**: Über `RATE_LIMIT_MAX_ANALYSES_PER_SENDER` und `RATE_LIMIT_WINDOW_HOURS`

## Sicherheit

- **Anhänge**: Nur bis 10 MB, temporäre Dateien werden nach Verarbeitung gelöscht
- **Kein OAuth**: Reines IMAP/SMTP mit App-Passwort (kein destruktiver Zugriff auf fremde Postfächer)
- **Isoliert**: Eigenständiger Prozess, keine Abhängigkeit von der Streamlit-App
- **Keine Änderungen**: Nur Lesezugriff auf eingehende Mails, keine Änderungen an fremden Postfächern

## Logs

Standard-Output zeigt:
- `[YYYY-MM-DD HH:MM:SS] [INFO/WARN/ERROR] Nachricht`

Beispiel:
```
[2026-07-03 00:23:55] [INFO] OSINT-Argus Mailbox Watcher gestartet
[2026-07-03 00:24:15] [INFO] Neue Emails gefunden: 2
[2026-07-03 00:24:16] [INFO] Verarbeite Email von user@example.com (Subject: Verdächtige Mail)
[2026-07-03 00:24:17] [INFO] Erkannte Sprache: de
[2026-07-03 00:24:45] [INFO] Starte Pipeline-Analyse (lang=de, files=1)
[2026-07-03 00:25:30] [INFO] Antwort-Mail gesendet an user@example.com
[2026-07-03 00:25:30] [INFO] Email 12345 erfolgreich verarbeitet
```

## Akzeptanzkriterien (API-2)

- [x] Eigenständiger Worker-Prozess (`app/mailbox_watcher.py`)
- [x] IMAP-Abfrage mit `imap-tools`
- [x] Zugangsdaten über `.env` (`MONITOR_MAILBOX_*`)
- [x] Body/Anhänge durch bestehende Pipeline (`build_initial_state()` + `graph.invoke()`)
- [x] Antwort an `From`-Header der eingehenden Mail (nicht an weitergeleiteten Inhalt)
- [x] Antwort-Mail per SMTP aus `OutputReport` (Text/HTML-Template)
- [x] Verarbeitete Nachrichten als `\Seen` markiert
- [x] Rate-Limit gegen Missbrauch (5 Analysen/Absender/24h)
- [x] Anhänge nur mit Größenlimit, temporäre Dateien gelöscht

## Nächste Schritte

- [ ] Optional: `processed`-Ordner statt `\Seen`-Flag (bei Bedarf konfigurierbar)
- [ ] Optional: Whitelist/Blacklist für Absenderadressen
- [ ] Optional: Metrik-Export (Prometheus/StatsD) für Monitoring
