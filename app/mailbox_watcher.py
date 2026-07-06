"""
app/mailbox_watcher.py

Fester "Weiterleiten-und-Analysieren"-Postfach-Service.

Eigenständiger, von der Streamlit-App unabhängiger Worker-Prozess, der
über IMAP neue/ungelesene Nachrichten im fest konfigurierten Postfach
abruft, durch die bestehende Pipeline schickt und eine Antwort-Mail
mit dem Ergebnis zurückschickt.

Starten:
    python -m app.mailbox_watcher

Oder als Hintergrundprozess:
    python -m app.mailbox_watcher --interval 60
"""

import os
import sys
import time
import hashlib
import tempfile
import email
from email.header import decode_header
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass, field

import imaplib
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from imap_tools import MailBox, AND

from dotenv import load_dotenv
load_dotenv()

# Import der bestehenden Pipeline-Komponenten
from app.ui.analyse_tab import build_initial_state
from app.graph import graph
from app.agents.output_agent import OutputAgent
from app.models.router import OutputReport
from app.mailbox_auth import (
    process_registration_email,
    get_registration_response,
    get_registration_response_html,
    extract_sender_email,
    decode_mime_header,
    validate_access_key
)
from app.mailbox_store import mailbox_store
from app.models.mailbox_user import MailAnalysis


# ── Konfiguration aus .env ────────────────────────────────────────────────────

MAILBOX_IMAP_SERVER = os.getenv("MONITOR_MAILBOX_IMAP_SERVER", "imap.gmail.com")
MAILBOX_IMAP_PORT = int(os.getenv("MONITOR_MAILBOX_IMAP_PORT", "993"))
MAILBOX_ADDRESS = os.getenv("MONITOR_MAILBOX_ADDRESS", "")
MAILBOX_PASSWORD = os.getenv("MONITOR_MAILBOX_PASSWORD", "")

MAILBOX_USE_SSL = os.getenv("MONITOR_MAILBOX_USE_SSL", "true").lower() == "true"
MAILBOX_FOLDER = os.getenv("MONITOR_MAILBOX_FOLDER", "INBOX")

SMTP_SERVER = os.getenv("MONITOR_SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("MONITOR_SMTP_PORT", "587"))
SMTP_USE_TLS = os.getenv("MONITOR_SMTP_USE_TLS", "true").lower() == "true"

RATE_LIMIT_MAX_ANALYSES_PER_SENDER = int(os.getenv("RATE_LIMIT_MAX_ANALYSES_PER_SENDER", "5"))
RATE_LIMIT_WINDOW_HOURS = int(os.getenv("RATE_LIMIT_WINDOW_HOURS", "24"))

POLL_INTERVAL_SECONDS = int(os.getenv("MAILBOX_POLL_INTERVAL_SECONDS", "60"))
MAX_ATTACHMENT_SIZE_BYTES = int(os.getenv("MAX_ATTACHMENT_SIZE_BYTES", str(10 * 1024 * 1024)))  # 10 MB

TEMP_DIR = Path(os.getenv("MAILBOX_TEMP_DIR", tempfile.gettempdir())) / "osint_argus_mailbox"
TEMP_DIR.mkdir(parents=True, exist_ok=True)


# ── Logging ───────────────────────────────────────────────────────────────────

def log(msg: str, level: str = "INFO"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [{level}] {msg}")


# ── Rate-Limiting ─────────────────────────────────────────────────────────────

@dataclass
class RateLimitTracker:
    """Verfolgt die Anzahl der Analysen pro Absenderadresse."""
    sender_counts: Dict[str, List[datetime]] = field(default_factory=dict)

    def is_allowed(self, sender: str) -> bool:
        now = datetime.now()
        window_start = now - timedelta(hours=RATE_LIMIT_WINDOW_HOURS)
        
        if sender not in self.sender_counts:
            self.sender_counts[sender] = []
        
        self.sender_counts[sender] = [
            ts for ts in self.sender_counts[sender] if ts > window_start
        ]
        
        if len(self.sender_counts[sender]) >= RATE_LIMIT_MAX_ANALYSES_PER_SENDER:
            log(f"Rate-Limit überschritten für {sender} ({len(self.sender_counts[sender])} Analysen im letzten {RATE_LIMIT_WINDOW_HOURS}h)", "WARN")
            return False
        
        self.sender_counts[sender].append(now)
        return True


# ── Email-Extrahierung ────────────────────────────────────────────────────────

def decode_mime_header(value: str) -> str:
    """Decodiert MIME-kodierte Email-Header (z.B. =?UTF-8?B?...?=)."""
    if not value:
        return ""
    decoded_parts = []
    for text, encoding in decode_header(value):
        if isinstance(text, bytes):
            try:
                decoded_parts.append(text.decode(encoding or "utf-8", errors="replace"))
            except Exception:
                decoded_parts.append(text.decode("utf-8", errors="replace"))
        else:
            decoded_parts.append(text)
    return "".join(decoded_parts)


def extract_email_content(msg: email.message.Message) -> Tuple[str, str, List[Dict]]:
    """
    Extrahiert Text-Inhalt (Plain-Text oder HTML) und Anhänge aus einer Email.
    
    Returns:
        (plain_text, html_content, attachments)
        attachments: List of dicts with keys: filename, content_type, data (bytes)
    """
    plain_text = ""
    html_content = ""
    attachments = []

    def walk_payload(part):
        nonlocal plain_text, html_content

        if part.get_content_maintype() == "multipart":
            for child in part.walk():
                walk_payload(child)
            return

        content_type = part.get_content_type()
        disposition = str(part.get("Content-Disposition", ""))

        if "attachment" in disposition:
            filename = part.get_filename()
            if filename:
                filename = decode_mime_header(filename)
            payload = part.get_payload(decode=True)
            if payload:
                attachments.append({
                    "filename": filename or "unnamed",
                    "content_type": content_type,
                    "data": payload
                })
            return

        if content_type == "text/plain" and not plain_text:
            payload = part.get_payload(decode=True)
            if payload:
                charset = part.get_content_charset() or "utf-8"
                try:
                    plain_text = payload.decode(charset, errors="replace")
                except Exception:
                    plain_text = payload.decode("utf-8", errors="replace")

        elif content_type == "text/html" and not html_content:
            payload = part.get_payload(decode=True)
            if payload:
                charset = part.get_content_charset() or "utf-8"
                try:
                    html_content = payload.decode(charset, errors="replace")
                except Exception:
                    html_content = payload.decode("utf-8", errors="replace")

    walk_payload(msg)

    if not plain_text and html_content:
        plain_text = html_content.replace("<br>", "\n").replace("</p>", "\n\n").replace("<p>", "")

    return plain_text.strip(), html_content.strip(), attachments


def detect_language_from_email(content: str) -> str:
    """
    Einfache Spracheerkennung basierend auf häufigen Wörtern.
    Fallback auf 'en'.
    """
    if not content:
        return "en"
    
    content_lower = content.lower()[:2000]
    
    de_indicators = ["der", "die", "das", "und", "ist", "nicht", "haben", "mit", "sich", "des", "sind", "waren"]
    en_indicators = ["the", "and", "is", "in", "to", "of", "a", "for", "on", "with", "as", "was"]
    
    de_count = sum(1 for word in de_indicators if f" {word} " in f" {content_lower} ")
    en_count = sum(1 for word in en_indicators if f" {word} " in f" {content_lower} ")
    
    return "de" if de_count > en_count else "en"


# ── Analyse-Pipeline ──────────────────────────────────────────────────────────

def analyze_email_content(plain_text: str, html_content: str, attachments: List[Dict], lang: str) -> Dict[str, Any]:
    """
    Führt die bestehende Analyse-Pipeline auf Email-Inhalt aus.
    
    Anhänge werden temporär gespeichert, gescannt und wieder gelöscht.
    """
    temp_files = []
    
    try:
        input_text = plain_text[:10000] if plain_text else ""
        if html_content:
            input_text += "\n\n" + html_content[:10000]
        
        if attachments:
            input_text += "\n\n[Anhänge verfügbar]"
        
        state = build_initial_state(input_text.strip(), lang)
        
        for attachment in attachments:
            if attachment["data"]:
                temp_path = TEMP_DIR / f"{hashlib.sha256(attachment['data'][:1024]).hexdigest()[:16]}_{attachment['filename']}"
                try:
                    temp_path.write_bytes(attachment["data"])
                    temp_files.append(temp_path)
                    state["file_paths"].append(str(temp_path))
                    state["to_scan"].append(str(temp_path))
                except Exception as e:
                    log(f"Fehler beim Speichern temporärer Datei {attachment['filename']}: {e}", "ERROR")
        
        log(f"Starte Pipeline-Analyse (lang={lang}, files={len(state['file_paths'])})")
        result = graph.invoke(state)
        
        return result
        
    finally:
        for temp_file in temp_files:
            try:
                if temp_file.exists():
                    temp_file.unlink()
            except Exception as e:
                log(f"Fehler beim Löschen temporärer Datei {temp_file}: {e}", "WARN")


def format_report_email(report: OutputReport, lang: str, original_sender: str) -> Tuple[str, str]:
    """
    Erstellt Text- und HTML-Version der Antwort-Mail basierend auf OutputReport.
    
    Returns:
        (text_body, html_body)
    """
    if lang == "de":
        subject = f"[OSINT-Argus] Analyse-Ergebnis - Risiko: {report.risk_level}"
        
        text_body = f"""
OSINT-Argus Analyse-Bericht
{'=' * 60}

RISIKOSTUFUNG: {report.risk_level}
Bedrohungs-Score: {report.threat_score}/100
Schwachstellen-Score: {report.vulnerability_score}/100

ZUSAMMENFASSUNG:
{report.summary}

TECHNISCHE ERKLÄRUNG:
{report.explanation}

PRÄVENTION:
{report.action_prevent}

FALLS BEREITS GEKLICKT/INTERAGIERT:
{chr(10).join(f'{i}. {step}' for i, step in enumerate(report.action_incident_response, 1))}

RISIKOINDIKATOREN:
{chr(10).join(f'  • {ind}' for ind in report.indicators)}

{'=' * 60}
Dies ist eine automatisierte Antwort von OSINT-Argus.
"""

        html_body = f"""
<html>
<head>
<style>
body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 20px auto; }}
.header {{ background: #1a1a2e; color: #fff; padding: 20px; border-radius: 8px 8px 0 0; }}
.risk-badge {{ display: inline-block; padding: 5px 15px; border-radius: 4px; font-weight: bold; }}
.risk-LOW {{ background: #22c55e; }}
.risk-MEDIUM {{ background: #eab308; }}
.risk-HIGH {{ background: #f97316; }}
.risk-CRITICAL {{ background: #ef4444; }}
.section {{ background: #f8fafc; padding: 15px; margin: 15px 0; border-left: 4px solid #3b82f6; }}
.score {{ display: inline-block; margin-right: 20px; }}
.indicators {{ list-style: none; padding: 0; }}
.indicators li {{ padding: 5px 0; border-bottom: 1px solid #e2e8f0; }}
.footer {{ font-size: 12px; color: #64748b; text-align: center; margin-top: 30px; }}
</style>
</head>
<body>
<div class="header">
<h1>👁️ OSINT-Argus Analyse-Bericht</h1>
</div>

<div class="section">
<h2>Risikostufung</h2>
<span class="risk-badge risk-{report.risk_level}">{report.risk_level}</span>
<p class="score"><strong>Bedrohungs-Score:</strong> {report.threat_score}/100</p>
<p class="score"><strong>Schwachstellen-Score:</strong> {report.vulnerability_score}/100</p>
</div>

<div class="section">
<h2>Zusammenfassung</h2>
<p>{report.summary}</p>
</div>

<div class="section">
<h2>Technische Erklärung</h2>
<p>{report.explanation}</p>
</div>

<div class="section" style="border-left-color: #ef4444;">
<h2>⚠️ Prävention</h2>
<p>{report.action_prevent}</p>
</div>

<div class="section" style="border-left-color: #f97316;">
<h2>🚨 Falls bereits interagierte</h2>
<ol>
{''.join(f"<li>{step}</li>" for step in report.action_incident_response)}
</ol>
</div>

<div class="section">
<h2>Risikoindikatoren</h2>
<ul class="indicators">
{''.join(f"<li>{ind}</li>" for ind in report.indicators)}
</ul>
</div>

<div class="footer">
<p>Dies ist eine automatisierte Antwort von OSINT-Argus.</p>
</div>
</body>
</html>
"""
    else:
        subject = f"[OSINT-Argus] Analysis Result - Risk: {report.risk_level}"
        
        text_body = f"""
OSINT-Argus Analysis Report
{'=' * 60}

RISK LEVEL: {report.risk_level}
Threat Score: {report.threat_score}/100
Vulnerability Score: {report.vulnerability_score}/100

SUMMARY:
{report.summary}

TECHNICAL EXPLANATION:
{report.explanation}

PREVENTION:
{report.action_prevent}

IF ALREADY CLICKED/INTERACTED:
{chr(10).join(f'{i}. {step}' for i, step in enumerate(report.action_incident_response, 1))}

RISK INDICATORS:
{chr(10).join(f'  • {ind}' for ind in report.indicators)}

{'=' * 60}
This is an automated response from OSINT-Argus.
"""

        html_body = f"""
<html>
<head>
<style>
body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 20px auto; }}
.header {{ background: #1a1a2e; color: #fff; padding: 20px; border-radius: 8px 8px 0 0; }}
.risk-badge {{ display: inline-block; padding: 5px 15px; border-radius: 4px; font-weight: bold; }}
.risk-LOW {{ background: #22c55e; }}
.risk-MEDIUM {{ background: #eab308; }}
.risk-HIGH {{ background: #f97316; }}
.risk-CRITICAL {{ background: #ef4444; }}
.section {{ background: #f8fafc; padding: 15px; margin: 15px 0; border-left: 4px solid #3b82f6; }}
.score {{ display: inline-block; margin-right: 20px; }}
.indicators {{ list-style: none; padding: 0; }}
.indicators li {{ padding: 5px 0; border-bottom: 1px solid #e2e8f0; }}
.footer {{ font-size: 12px; color: #64748b; text-align: center; margin-top: 30px; }}
</style>
</head>
<body>
<div class="header">
<h1>👁️ OSINT-Argus Analysis Report</h1>
</div>

<div class="section">
<h2>Risk Level</h2>
<span class="risk-badge risk-{report.risk_level}">{report.risk_level}</span>
<p class="score"><strong>Threat Score:</strong> {report.threat_score}/100</p>
<p class="score"><strong>Vulnerability Score:</strong> {report.vulnerability_score}/100</p>
</div>

<div class="section">
<h2>Summary</h2>
<p>{report.summary}</p>
</div>

<div class="section">
<h2>Technical Explanation</h2>
<p>{report.explanation}</p>
</div>

<div class="section" style="border-left-color: #ef4444;">
<h2>⚠️ Prevention</h2>
<p>{report.action_prevent}</p>
</div>

<div class="section" style="border-left-color: #f97316;">
<h2>🚨 If Already Interacted</h2>
<ol>
{''.join(f"<li>{step}</li>" for step in report.action_incident_response)}
</ol>
</div>

<div class="section">
<h2>Risk Indicators</h2>
<ul class="indicators">
{''.join(f"<li>{ind}</li>" for ind in report.indicators)}
</ul>
</div>

<div class="footer">
<p>This is an automated response from OSINT-Argus.</p>
</div>
</body>
</html>
"""

    return subject, text_body, html_body


# ── SMTP-Versand (lokal für nicht-Auth-Mails) ─────────────────────────────────────

def send_response_email_local(to_address: str, subject: str, text_body: str, html_body: str) -> bool:
    """Sendet die Antwort per SMTP (lokale Version für Analyse-Mails)."""
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = MAILBOX_ADDRESS
        msg["To"] = to_address
        
        part_text = MIMEText(text_body, "plain", "utf-8")
        part_html = MIMEText(html_body, "html", "utf-8")
        msg.attach(part_text)
        msg.attach(part_html)
        
        if SMTP_USE_TLS:
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=30) as server:
                server.starttls()
                server.login(MAILBOX_ADDRESS, MAILBOX_PASSWORD)
                server.sendmail(MAILBOX_ADDRESS, [to_address], msg.as_string())
        else:
            with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, timeout=30) as server:
                server.login(MAILBOX_ADDRESS, MAILBOX_PASSWORD)
                server.sendmail(MAILBOX_ADDRESS, [to_address], msg.as_string())
        
        log(f"Antwort-Mail gesendet an {to_address}")
        return True
        
    except Exception as e:
        log(f"Fehler beim Senden der Antwort-Mail: {e}", "ERROR")
        return False


# ── IMAP-Verarbeitung ─────────────────────────────────────────────────────────

def process_mailbox(rate_limiter: RateLimitTracker) -> int:
    """
    Ruft neue/ungelesene Emails ab, verarbeitet sie und markiert als gelesen.
    
    Returns:
        Anzahl der verarbeiteten Emails
    """
    processed_count = 0
    
    if not MAILBOX_ADDRESS or not MAILBOX_PASSWORD:
        log("Mailbox-Konfiguration unvollständig (MONITOR_MAILBOX_ADDRESS/PASSWORD nicht gesetzt)", "ERROR")
        return 0
    
    try:
        with MailBox(MAILBOX_IMAP_SERVER, port=MAILBOX_IMAP_PORT) as mailbox:
            mailbox.login(MAILBOX_ADDRESS, MAILBOX_PASSWORD)
            mailbox.folder.set(MAILBOX_FOLDER)
            
            messages = list(mailbox.fetch(AND(seen=False, deleted=False)))
            
            if not messages:
                return 0
            
            log(f"Neue Emails gefunden: {len(messages)}")
            
            for msg in messages:
                try:
                    log(f"Verarbeite Email von {msg.from_} (Subject: {msg.subject[:50] if msg.subject else 'N/A'})")
                    
                    if not rate_limiter.is_allowed(msg.from_):
                        log(f"Überspringe Email von {msg.from_} (Rate-Limit)", "WARN")
                        try:
                            mailbox.uid('STORE', msg.uid, '+FLAGS', r'(\Seen)')
                        except Exception as e:
                            log(f"Fehler beim Markieren als gelesen: {e}", "WARN")
                        processed_count += 1
                        continue
                    
                    # ZUERST: Prüfen ob es eine Registrierungs-Mail ist (immer aktiv)
                    subject = decode_mime_header(msg.subject or "")
                    from_email = msg.from_
                    
                    log(f"Subject: '{subject}', From: '{from_email}'")
                    
                    if "REGISTER" in subject.upper() or "REGISTRATION" in subject.upper():
                        log(f"Erkannte Registrierungs-Mail von {from_email}", "INFO")
                        success, message, user = process_registration_email(msg, msg.uid)
                        
                        if success and user:
                            response_text = get_registration_response(user)
                            response_html = get_registration_response_html(user)   # NEU
                            send_response_email_local(from_email, "OSINT-Argus Registrierung bestätigt", response_text, response_html)
                        else:
                            log(f"Registrierung fehlgeschlagen für {from_email}: {message}", "WARN")
                        
                        try:
                            mailbox.uid('STORE', msg.uid, '+FLAGS', r'(\Seen)')
                        except Exception as e:
                            log(f"Fehler beim Markieren als gelesen: {e}", "WARN")
                        processed_count += 1
                        continue
                    
                    # Prüfen ob Auto-Analyze aktiviert ist (über .env)
                    # Wenn OFF: Mail überspringen, bleibt im Postfach für manuelle Analyse in UI
                    auto_analyze_enabled = os.getenv("MAILBOX_AUTO_ANALYZE", "true").lower() == "true"
                    
                    if not auto_analyze_enabled:
                        log(f"Auto-Analyze OFF - Mail {msg.uid} im Postfach belassen", "INFO")
                        processed_count += 1
                        continue
                    
                    # Auto-Analyze ON: Mail analysieren
                    log(f"Analysiere Mail von {from_email} (Subject: {msg.subject[:50]})")
                    lang = detect_language_from_email(plain_text or html_content)
                    log(f"Erkannte Sprache: {lang}")
                    
                    analysis_result = analyze_email_content(plain_text, html_content, attachments, lang)
                    
                    # OutputAgent aufrufen für strukturierten Report
                    output_agent = OutputAgent()
                    final_state = output_agent.run(analysis_result)
                    
                    # Report extrahieren
                    report_obj = None
                    if "action_advice" in final_state:
                        # Versuche aus findings den Report zu rekonstruieren
                        findings = final_state.get("findings", [])
                        for f in findings:
                            if hasattr(f, 'threat_sum') and len(f.threat_sum) > 0:
                                # Reconstruiere OutputReport aus findings
                                threat_score = 50
                                risk_level = "MEDIUM"
                                for item in f.threat_sum:
                                    if "Threat Score:" in item:
                                        try:
                                            threat_score = int(item.split(":")[1].strip())
                                        except:
                                            pass
                                    if "Level:" in item:
                                        risk_level = item.split(":")[1].strip()
                                
                                report_obj = OutputReport(
                                    threat_score=threat_score,
                                    vulnerability_score=50,
                                    risk_level=risk_level,
                                    explanation=final_state.get("summary", "Analyse durchgeführt."),
                                    summary=final_state.get("summary", "Automatische Analyse abgeschlossen."),
                                    action_prevent=final_state.get("action_advice", "Interagiere nicht mit den Objekten."),
                                    action_incident_response=["1. System isolieren", "2. Weitere Schritte prüfen"],
                                    indicators=f.indicators if hasattr(f, 'indicators') else []
                                )
                                break
                    
                    if not report_obj:
                        report_obj = OutputReport(
                            threat_score=50,
                            vulnerability_score=50,
                            risk_level="MEDIUM",
                            explanation="Report-Erstellung nicht möglich.",
                            summary="Automatische Analyse durchgeführt.",
                            action_prevent="Interagiere nicht mit den analysierten Objekten.",
                            action_incident_response=["1. System isolieren", "2. IT-Sicherheit kontaktieren"],
                            indicators=["Automatische Analyse"]
                        )
                    
                    # Analyse speichern für UI-Access
                    analysis = MailAnalysis(
                        user_id="anonymous",  # Wird später bei User-Linking aktualisiert
                        mail_uid=msg.uid,
                        subject=msg.subject,
                        from_address=from_email,
                        risk_level=report_obj.risk_level,
                        risk_score=max(report_obj.threat_score, report_obj.vulnerability_score),
                        summary=report_obj.summary,
                        full_report={
                            "threat_score": report_obj.threat_score,
                            "vulnerability_score": report_obj.vulnerability_score,
                            "risk_level": report_obj.risk_level,
                            "explanation": report_obj.explanation,
                            "summary": report_obj.summary,
                            "action_prevent": report_obj.action_prevent,
                            "action_incident_response": report_obj.action_incident_response,
                            "indicators": report_obj.indicators
                        }
                    )
                    mailbox_store.save_analysis(analysis)
                    
                    # Antwort-Mail senden
                    subject, text_body, html_body = format_report_email(
                        report_obj, lang, from_email
                    )
                    
                    if send_response_email_local(from_email, subject, text_body, html_body):
                        mailbox.uid('STORE', msg.uid, '+FLAGS', r'(\Seen)')
                        processed_count += 1
                        log(f"Email {msg.uid} erfolgreich verarbeitet")
                    else:
                        log(f"Fehler beim Senden der Antwort für Email {msg.uid}", "ERROR")
                        
                except Exception as e:
                    log(f"Fehler bei der Verarbeitung von Email {msg.uid}: {e}", "ERROR")
                    continue
                    
    except Exception as e:
        log(f"IMAP-Verbindungsfehler: {e}", "ERROR")
    
    return processed_count


# ── Hauptloop ─────────────────────────────────────────────────────────────────

def main():
    log("=" * 60)
    log("OSINT-Argus Mailbox Watcher gestartet")
    log(f"Mailbox: {MAILBOX_ADDRESS}")
    log(f"IMAP: {MAILBOX_IMAP_SERVER}:{MAILBOX_IMAP_PORT}")
    log(f"SMTP: {SMTP_SERVER}:{SMTP_PORT}")
    log(f"Rate-Limit: {RATE_LIMIT_MAX_ANALYSES_PER_SENDER} Analysen/{RATE_LIMIT_WINDOW_HOURS}h pro Absender")
    log(f"Poll-Interval: {POLL_INTERVAL_SECONDS}s")
    log("=" * 60)
    
    rate_limiter = RateLimitTracker()
    
    while True:
        try:
            log(f"[Poll] Prüfe Mailbox...")
            processed = process_mailbox(rate_limiter)
            if processed > 0:
                log(f"[Poll] Verarbeitet {processed} Email(s)")
            else:
                log(f"[Poll] Keine neuen Mails gefunden")
        except KeyboardInterrupt:
            log("Stopp per Tastatur-Interrupt")
            break
        except Exception as e:
            log(f"Unerwarteter Fehler in der Hauptschleife: {e}", "ERROR")
        
        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
