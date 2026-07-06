"""
app/ui/mail_access.py

Mail-Access Tab: Login via Access-Key, Mails anzeigen, Analyse starten.
- Auto-Analyze ON: Zeigt analysierte Mails mit Ergebnis
- Auto-Analyze OFF: Zeigt ungelesene Mails, Klick startet manuelle Analyse
"""

import streamlit as st
from datetime import datetime
from typing import Optional, List, Dict
import tempfile
from pathlib import Path
import email as email_module
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from imap_tools import MailBox, AND
from dotenv import load_dotenv
import os
import re

from app.mailbox_auth import validate_access_key, decode_mime_header
from app.mailbox_store import mailbox_store
from app.models.mailbox_user import MailboxUser, MailAnalysis
from app.config_manager import get_auto_analyze, set_auto_analyze
from app.ui.analyse_tab import run_with_live_log
from app.utils.prompt_cleaner import clean_llm_output
from app.ui.results import map_result_to_mail
from app.agents.output_agent import OutputAgent
from app.graph import graph, graph_async
from app.state import ArgusState

# Konfiguration
MAILBOX_ADDRESS = "osintargus@gmail.com"
MAILBOX_PASSWORD = ""  # Wird aus .env geladen
MAILBOX_IMAP_SERVER = "imap.gmail.com"
MAILBOX_IMAP_PORT = 993
TEMP_DIR = Path(tempfile.gettempdir()) / "osint_argus_attachments"
TEMP_DIR.mkdir(parents=True, exist_ok=True)


def run_analysis_pipeline(user_input: str, lang: str = "en") -> dict:
    """Führt die komplette Analyse-Pipeline aus und gibt den finalen State zurück."""
    from app.ui.analyse_tab import build_initial_state
    
    state = build_initial_state(user_input.strip(), lang)
    
    final_state = graph.invoke(state)
    
    return final_state


def load_env():
    """Lädt Umgebungsvariablen."""
    load_dotenv()
    global MAILBOX_ADDRESS, MAILBOX_PASSWORD
    MAILBOX_ADDRESS = os.getenv("MONITOR_MAILBOX_ADDRESS", MAILBOX_ADDRESS)
    MAILBOX_PASSWORD = os.getenv("MONITOR_MAILBOX_PASSWORD", "")


def extract_email_content_from_string(raw_text: str) -> tuple:
    """Extrahiert Inhalt aus rohem Email-String."""
    # Versuche UTF-8-Mojibake zu reparieren
    try:
        raw_text = raw_text.encode('latin-1').decode('utf-8', errors='ignore')
    except (UnicodeEncodeError, UnicodeDecodeError):
        pass
    
    msg = email_module.message_from_string(raw_text or "")
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
                charset = part.get_content_charset()
                if charset:
                    try:
                        plain_text = payload.decode(charset, errors="ignore")
                    except (UnicodeDecodeError, LookupError):
                        plain_text = payload.decode("utf-8", errors="ignore")
                else:
                    try:
                        plain_text = payload.decode("utf-8", errors="ignore")
                    except UnicodeDecodeError:
                        plain_text = payload.decode("latin-1", errors="ignore")
        
        elif content_type == "text/html" and not html_content:
            payload = part.get_payload(decode=True)
            if payload:
                charset = part.get_content_charset()
                if charset:
                    try:
                        html_content = payload.decode(charset, errors="ignore")
                    except (UnicodeDecodeError, LookupError):
                        html_content = payload.decode("utf-8", errors="ignore")
                else:
                    try:
                        html_content = payload.decode("utf-8", errors="ignore")
                    except UnicodeDecodeError:
                        html_content = payload.decode("latin-1", errors="ignore")
    
    walk_payload(msg)
    
    if not plain_text and html_content:
        text_from_html = html_content
        text_from_html = re.sub(r'<[^>]+>', ' ', text_from_html)
        text_from_html = text_from_html.replace('&nbsp;', ' ').replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>')
        text_from_html = re.sub(r'\s+', ' ', text_from_html)
        plain_text = text_from_html.strip()
    
    return plain_text.strip(), html_content, attachments


def fetch_user_mails(user: MailboxUser) -> List[Dict]:
    """Holt Mails aus dem Postfach für den User."""
    load_env()
    mails = []
    
    try:
        with MailBox(MAILBOX_IMAP_SERVER, port=MAILBOX_IMAP_PORT) as mailbox:
            mailbox.login(MAILBOX_ADDRESS, MAILBOX_PASSWORD)
            messages = list(mailbox.fetch(AND(deleted=False)))
            
            for msg in messages:
                subject = msg.subject or ""
                if "REGISTER" in subject.upper() or "REGISTRATION" in subject.upper():
                    continue
                
                mails.append({
                    "uid": msg.uid,
                    "subject": subject,
                    "from": msg.from_ or "Unknown",
                    "date": msg.date,
                    "text": msg.text or "",
                    "html": msg.html or "",
                    "seen": msg.flags and "\\Seen" in msg.flags
                })
    except Exception as e:
        st.error(f"Fehler beim Abrufen der Mails: {e}")
    
    return mails


def save_attachments(attachments: List[Dict]) -> List[str]:
    """Speichert Anhänge temporär und gibt Pfade zurück."""
    paths = []
    for att in attachments:
        if att.get("data"):
            safe_filename = "".join(c for c in att["filename"] if c.isalnum() or c in ('.', '-', '_'))[:50]
            temp_path = TEMP_DIR / f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{safe_filename}"
            try:
                temp_path.write_bytes(att["data"])
                paths.append(str(temp_path))
            except Exception as e:
                st.warning(f"Konnte Anhang {att['filename']} nicht speichern: {e}")
    return paths





def render_login_view():
    """Rendert den Login-Bereich."""
    st.markdown("### 🔐 Mail-Access Login")
    st.markdown("Gib deinen Access-Key ein, um deine Mails einzusehen.")
    
    with st.form("login_form"):
        access_key = st.text_input("Access-Key", placeholder="12-Zeichen-Key", max_chars=12, key="login_access_key")
        submit_btn = st.form_submit_button("Anmelden", use_container_width=True)
    
    if submit_btn:
        if not access_key or len(access_key) != 12:
            st.error("Access-Key muss genau 12 Zeichen lang sein.")
        else:
            success, message, user = validate_access_key(access_key)
            if success:
                st.session_state["mailbox_user"] = user
                st.session_state["mailbox_logged_in"] = True
                st.success(message)
                st.rerun()
            else:
                st.error(message)
    
    with st.expander("❓ Noch keinen Access-Key?"):
        st.markdown("""
        **So erhältst du einen Access-Key:**
        1. Sende eine E-Mail mit dem Betreff `REGISTER` an: **osintargus@gmail.com**
        2. Du erhältst eine Antwort-Mail mit deinem persönlichen Access-Key
        """)


def render_waiting_view():
    """Rendert die Warteanzeige während der Analyse."""
    st.markdown("### ⏳ Analyse läuft...")
    st.info("Deine Mail wird analysiert. Die Antwort erhältst du per E-Mail.")
    
    with st.spinner("🔄 Verarbeite Mail..."):
        st.markdown("")
    
    if st.button("❌ Abbrechen", use_container_width=True):
        st.session_state.pop("analyzing_mail_uid", None)
        st.session_state.pop("user_input", None)
        st.session_state.pop("mail_from", None)
        st.session_state.pop("mail_subject", None)
        st.rerun()


def render_mail_list(user: MailboxUser):
    """Rendert die Mail-Liste mit Analyse-Start."""
    auto_analyze = get_auto_analyze()
    
    col1, col2 = st.columns([3, 1])
    with col1:
        st.markdown(f"### 👤 {user.email_address}")
    with col2:
        if st.button("Abmelden", use_container_width=True):
            st.session_state.pop("mailbox_user", None)
            st.session_state.pop("mailbox_logged_in", None)
            st.rerun()
    
    st.markdown("---")
    
    if st.button("🔄 Mails aktualisieren"):
        st.session_state.pop("cached_mails", None)
        st.rerun()
    
    if "cached_mails" not in st.session_state:
        st.session_state.cached_mails = fetch_user_mails(user)
    
    mails = st.session_state.cached_mails
    
    if not mails:
        st.info("Keine Mails im Postfach.")
        return
    
    mails_sorted = sorted(mails, key=lambda m: (m.get("seen", False), m['date']), reverse=True)
    
    st.markdown(f"**{len(mails_sorted)} Mail(s)**")
    
    for mail in mails_sorted:
        is_seen = mail.get("seen", False)
        status_icon = "📖" if is_seen else "📬"
        header_text = f"{status_icon} {mail['subject'][:30]}{'...' if len(mail['subject']) > 30 else ''} | {mail['from'][:20]} | {mail['date'].strftime('%d.%m %H:%M')}"
        
        with st.expander(header_text, expanded=False):
            st.markdown(f"**Von:** {mail['from']}")
            st.markdown(f"**Empfangen:** {mail['date'].strftime('%d.%m.%Y %H:%M')}")
            st.divider()
            
            preview = (mail['text'] or mail['html'] or "")[:200]
            st.text_area("Preview", preview, height=80, disabled=True, label_visibility="collapsed", key=f"preview_{mail['uid']}")
            
            _, _, attachments = extract_email_content_from_string(mail['text'])
            if attachments:
                st.caption(f"📎 {len(attachments)} Anhang/en")
            
            if auto_analyze:
                st.info("Auto-Analyze aktiv - Mail wurde bereits analysiert.")
            else:
                if st.button("🔍 Zur Analyse", key=f"analyze_{mail['uid']}", use_container_width=True):
                    plain_text, html, atts = extract_email_content_from_string(mail['text'])
                    att_paths = save_attachments(atts)
                    
                    input_text = (plain_text or html).rstrip()
                    
                    # Zentrale Bereinigung von Editor-Markierungen
                    input_text = clean_llm_output(input_text)
                    
                    if att_paths:
                        input_text += "\n\n[Anhänge: " + ", ".join(att_paths) + "]"
                    
                    print(f"[DEBUG] Mail-Input: {len(input_text)} Zeichen")
                    print(f"[DEBUG] Mail-Input Preview: {input_text[:500]!r}")
                    
                    if not input_text.strip():
                        st.error("Konnte keinen Textinhalt aus der Mail extrahieren.")
                        st.stop()
                    
                    st.session_state["user_input"] = input_text
                    st.session_state["mail_uid"] = mail['uid']
                    st.session_state["mail_from"] = mail['from']
                    st.session_state["mail_subject"] = mail['subject']
                    st.session_state["analyzing_mail_uid"] = mail['uid']
                    st.rerun()


def render_analysis_execution():
    """Führt die Analyse aus und sendet Ergebnis per E-Mail."""

    load_env()
    
    input_text = st.session_state.get("user_input", "")
    from_address = st.session_state.get("mail_from", "")
    subject = st.session_state.get("mail_subject", "")
    mail_uid = st.session_state.get("mail_uid", "")
    
    print(f"[DEBUG] render_analysis_execution: input_text length = {len(input_text)}")
    print(f"[DEBUG] render_analysis_execution: input_text preview = {input_text[:500]!r}")
    
    if not input_text.strip():
        st.error("Kein valideter Input für die Analyse vorhanden.")
        st.session_state.pop("analyzing_mail_uid", None)
        st.rerun()
        return
    
    try:
        lang = st.session_state.get("language", "en")
        
        # Vollständige Pipeline ausfuhren (ohne Live-Log)
        result = run_analysis_pipeline(input_text.strip(), lang=lang)
        
        if not result:
            raise Exception("Analyse lieferte kein Ergebnis")
        
        print(f"[DEBUG] render_analysis_execution: risk_score = {result.get('risk_score')}, risk_level = {result.get('risk_level')}")
        print(f"[DEBUG] render_analysis_execution: findings count = {len(result.get('findings', []))}")
        
        # Ergebnis per Mail senden
        SMTP_SERVER = os.getenv("MONITOR_SMTP_SERVER", "smtp.gmail.com")
        SMTP_PORT = int(os.getenv("MONITOR_SMTP_PORT", "587"))
        SMTP_USE_TLS = os.getenv("MONITOR_SMTP_USE_TLS", "true").lower() == "true"
        
        if from_address:
            print(f"[DEBUG] map_result_to_mail input: result keys = {result.keys()}")
            subject_email, text_body, html_body = map_result_to_mail(result, lang)
            print(f"[DEBUG] map_result_to_mail output: subject = {subject_email}")
            print(f"[DEBUG] map_result_to_mail output: text_body preview = {text_body[:200]!r}")
            
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject_email
            msg["From"] = MAILBOX_ADDRESS
            msg["To"] = from_address
            msg.attach(MIMEText(text_body, "plain", "utf-8"))
            msg.attach(MIMEText(html_body, "html", "utf-8"))
            
            try:
                if SMTP_USE_TLS:
                    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=30) as server:
                        server.starttls()
                        server.login(MAILBOX_ADDRESS, MAILBOX_PASSWORD)
                        server.sendmail(MAILBOX_ADDRESS, [from_address], msg.as_string())
                else:
                    with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, timeout=30) as server:
                        server.login(MAILBOX_ADDRESS, MAILBOX_PASSWORD)
                        server.sendmail(MAILBOX_ADDRESS, [from_address], msg.as_string())
                st.success("✅ Analyse abgeschlossen! Antwort-Mail gesendet.")
            except Exception as e:
                st.warning(f"✅ Analyse abgeschlossen, aber Mail-Versand fehlgeschlagen: {e}")
        
        # Reset
        st.session_state.pop("analyzing_mail_uid", None)
        st.session_state.pop("user_input", None)
        st.session_state.pop("mail_uid", None)
        st.session_state.pop("mail_from", None)
        st.session_state.pop("mail_subject", None)
        st.rerun()
        
    except Exception as e:
        st.error(f"❌ Analyse-Fehler: {str(e)}")
        st.session_state.pop("analyzing_mail_uid", None)
        st.session_state.pop("user_input", None)


def render_mail_access_tab():
    """Haupt-Render-Funktion."""
    user: Optional[MailboxUser] = st.session_state.get("mailbox_user")
    
    auto_analyze = get_auto_analyze()
    
    col1, col2 = st.columns([4, 1])
    with col1:
        st.markdown("**⚙️ Auto-Analyze**")
        st.caption("Neue Mails automatisch verarbeiten")
    with col2:
        if st.toggle("Auto-Analyze", value=auto_analyze, label_visibility="collapsed"):
            if not auto_analyze:
                set_auto_analyze(True)
                st.rerun()
        else:
            if auto_analyze:
                set_auto_analyze(False)
                st.rerun()
    
    st.markdown("---")
    
    # Prüfen ob Analyse läuft (Warteanzeige)
    if st.session_state.get("analyzing_mail_uid"):
        render_waiting_view()
        # Analyse nach Rerun ausführen
        render_analysis_execution()
        return
    
    if not user:
        render_login_view()
        return
    
    render_mail_list(user)
