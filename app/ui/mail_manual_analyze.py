"""
app/ui/mail_manual_analyze.py

Manuelle Mail-Analyse: User wählt Mails aus dem Postfach zur Analyse.
Nur aktiv wenn MAILBOX_AUTO_ANALYZE=false.
"""

import streamlit as st
from datetime import datetime
from typing import List, Optional
import email
from imap_tools import MailBox, AND

from app.mailbox_auth import validate_access_key, decode_mime_header
from app.mailbox_store import mailbox_store
from app.models.mailbox_user import MailboxUser, MailAnalysis
from app.ui.analyse_tab import build_initial_state
from app.graph import graph
from app.agents.output_agent import OutputAgent
from app.models.router import OutputReport


# Gmail-Konfiguration (aus .env)
from dotenv import load_dotenv
load_dotenv()
import os

MAILBOX_ADDRESS = os.getenv("MONITOR_MAILBOX_ADDRESS", "")
MAILBOX_PASSWORD = os.getenv("MONITOR_MAILBOX_PASSWORD", "")
MAILBOX_IMAP_SERVER = os.getenv("MONITOR_MAILBOX_IMAP_SERVER", "imap.gmail.com")
MAILBOX_IMAP_PORT = int(os.getenv("MONITOR_MAILBOX_IMAP_PORT", "993"))


def fetch_unread_mails() -> List[dict]:
    """Holt alle ungelesenen Mails aus dem Postfach."""
    if not MAILBOX_ADDRESS or not MAILBOX_PASSWORD:
        return []
    
    mails = []
    try:
        with MailBox(MAILBOX_IMAP_SERVER, port=MAILBOX_IMAP_PORT) as mailbox:
            mailbox.login(MAILBOX_ADDRESS, MAILBOX_PASSWORD)
            messages = list(mailbox.fetch(AND(seen=False, deleted=False)))
            
            for msg in messages:
                mails.append({
                    "uid": msg.uid,
                    "subject": msg.subject or "N/A",
                    "from": msg.from_ or "Unknown",
                    "date": msg.date,
                    "text": msg.text or "",
                    "html": msg.html or ""
                })
    except Exception as e:
        st.error(f"Fehler beim Abrufen der Mails: {e}")
    
    return mails


def analyze_mail_from_uid(mail_data: dict, user: MailboxUser) -> Optional[MailAnalysis]:
    """Führt Analyse auf einer Mail aus und speichert das Ergebnis."""
    try:
        # Inhalt extrahieren
        plain_text = mail_data["text"][:10000]
        html_content = mail_data["html"][:10000] if mail_data["html"] else ""
        
        input_text = plain_text
        if html_content and not plain_text:
            input_text = html_content
        
        # Pipeline starten
        state = build_initial_state(input_text.strip(), "de")
        final_state = graph.invoke(state)
        
        # OutputAgent aufrufen
        output_agent = OutputAgent()
        final_state = output_agent.run(final_state)
        
        # Report extrahieren
        report_obj = None
        findings = final_state.get("findings", [])
        for f in findings:
            if hasattr(f, 'threat_sum') and len(f.threat_sum) > 0:
                threat_score = 50
                risk_level = "MEDIUM"
                indicators = []
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
                    indicators=indicators
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
        
        # Analyse speichern
        analysis = MailAnalysis(
            user_id=user.user_id,
            mail_uid=str(mail_data["uid"]),
            subject=mail_data["subject"],
            from_address=mail_data["from"],
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
        
        # Mail als gelesen markieren
        try:
            with MailBox(MAILBOX_IMAP_SERVER, port=MAILBOX_IMAP_PORT) as mailbox:
                mailbox.login(MAILBOX_ADDRESS, MAILBOX_PASSWORD)
                mailbox.uid('STORE', mail_data["uid"], '+FLAGS', r'(\Seen)')
        except Exception as e:
            st.warning(f"Konnte Mail nicht als gelesen markieren: {e}")
        
        return analysis
        
    except Exception as e:
        st.error(f"Analyse-Fehler: {e}")
        return None


def render_manual_analyze_view(user: MailboxUser):
    """Rendert die manuelle Analyse-Ansicht."""
    st.markdown("### 📥 Mails zur manuellen Analyse auswählen")
    st.markdown("Wähle eine Mail aus dem Postfach, um sie zu analysieren.")
    
    # Button zum Aktualisieren
    col1, col2 = st.columns([3, 1])
    with col2:
        if st.button("🔄 Mails aktualisieren", use_container_width=True):
            st.session_state.pop("cached_mails", None)
            st.rerun()
    
    # Mails abrufen (cachen für diese Session)
    if "cached_mails" not in st.session_state:
        st.session_state.cached_mails = fetch_unread_mails()
    
    mails = st.session_state.cached_mails
    
    if not mails:
        st.info("Keine neuen Mails im Postfach.")
        return
    
    st.markdown(f"**{len(mails)} neue Mail(s) verfügbar**")
    
    # Liste der Mails anzeigen
    for i, mail in enumerate(mails):
        with st.expander(f"{mail['subject'][:50]}{'...' if len(mail['subject']) > 50 else ''} - {mail['from']}"):
            # Metadaten
            col1, col2 = st.columns(2)
            with col1:
                st.caption(f"Von: {mail['from']}")
            with col2:
                st.caption(f"Empfangen: {mail['date'].strftime('%d.%m.%Y %H:%M')}")
            
            # Preview
            preview = (mail['text'] or mail['html'] or "")[:300]
            st.text_area("Vorschau", preview, height=100, disabled=True)
            
            # Analyse-Button
            if st.button("🔍 Analysieren", key=f"analyze_{mail['uid']}", use_container_width=True):
                with st.spinner("Analysiere Mail..."):
                    analysis = analyze_mail_from_uid(mail, user)
                    if analysis:
                        st.success("Analyse abgeschlossen!")
                        st.session_state.pop("cached_mails", None)
                        st.session_state.selected_analysis = analysis
                        st.rerun()


def render_mail_manual_analyze_tab():
    """Haupt-Render-Funktion für den manuellen Analyse-Tab."""
    user: Optional[MailboxUser] = st.session_state.get("mailbox_user")
    
    if not user:
        st.info("Bitte zuerst in der 'Mail Analyse' mit Access-Key anmelden.")
        return
    
    # Prüfen ob Report angezeigt werden soll
    selected: Optional[MailAnalysis] = st.session_state.get("selected_analysis")
    if selected:
        st.markdown("### 📊 Analyse-Ergebnis")
        
        if selected.risk_level:
            badges = {
                "LOW": ("🟢 LOW", "background: #22c55e;"),
                "MEDIUM": ("🟡 MEDIUM", "background: #eab308;"),
                "HIGH": ("🟠 HIGH", "background: #f97316;"),
                "CRITICAL": ("🔴 CRITICAL", "background: #ef4444;"),
            }
            label, style = badges.get(selected.risk_level, ("⚪ UNKNOWN", "background: #94a3b8;"))
            st.markdown(f'<span style="{style} padding: 4px 12px; border-radius: 4px; font-weight: bold;">{label}</span>', unsafe_allow_html=True)
        
        if selected.summary:
            st.markdown(f"**Zusammenfassung:** {selected.summary}")
        
        if selected.full_report:
            report = selected.full_report
            col1, col2 = st.columns(2)
            with col1:
                st.metric("Threat Score", f"{report.get('threat_score', 0)}/100")
            with col2:
                st.metric("Vulnerability Score", f"{report.get('vulnerability_score', 0)}/100")
            
            if report.get("action_prevent"):
                st.markdown("### 🛡️ Prävention")
                st.markdown(report["action_prevent"])
            
            if report.get("action_incident_response"):
                st.markdown("### 🚨 Incident Response")
                for i, step in enumerate(report["action_incident_response"], 1):
                    st.markdown(f"{i}. {step}")
        
        if st.button("⬅️ Zurück"):
            st.session_state.pop("selected_analysis", None)
            st.rerun()
        return
    
    render_manual_analyze_view(user)
