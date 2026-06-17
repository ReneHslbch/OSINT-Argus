import json

import streamlit as st
import time
from app.agents.identity_agent import IdentityAgent
from app.graph import graph
from app.memory.chroma_memory import get_last_analyses, get_user_profile, save_user_profile
from app.agents.leak_agent import LeakAgent
from app.models.router import ExecutiveSummary

st.set_page_config(
    page_title="OSINT-Argus",
    page_icon="👁️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
.argus-header {
    display: flex; align-items: center; gap: 12px;
    padding: 0.5rem 0 1.5rem 0;
    border-bottom: 1px solid rgba(128,128,128,0.2);
    margin-bottom: 1.5rem;
}
.argus-title { font-size: 1.6rem; font-weight: 700; letter-spacing: -0.02em; margin: 0; }
.argus-sub   { font-size: 0.75rem; opacity: 0.45; margin: 0; letter-spacing: 0.05em; text-transform: uppercase; }

.risk-badge { display: inline-block; padding: 5px 16px; border-radius: 999px; font-weight: 700; font-size: 0.9rem; letter-spacing: 0.05em; }
.risk-LOW      { background: #d1fae5; color: #065f46; }
.risk-MEDIUM   { background: #fef3c7; color: #92400e; }
.risk-HIGH     { background: #fee2e2; color: #991b1b; }
.risk-CRITICAL { background: #991b1b; color: #fff; animation: pulse 1.4s infinite; }
.risk-UNKNOWN  { background: #e5e7eb; color: #374151; }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.65} }

.action-box { border-radius: 8px; padding: 1rem 1.2rem; font-size: 0.88rem; line-height: 1.75; }
.action-prevent  { background: #fffbeb; border-left: 4px solid #f59e0b; color: #78350f; }
.action-incident { background: #fff1f2; border-left: 4px solid #ef4444; color: #7f1d1d; }

.live-row {
    display: flex; align-items: center; gap: 10px;
    padding: 5px 0; font-size: 0.83rem;
    border-bottom: 1px solid rgba(128,128,128,0.1);
}
.live-agent  { font-weight: 600; min-width: 110px; }
.live-target { font-family: monospace; opacity: 0.7; font-size: 0.78rem; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.live-status { margin-left: auto; font-size: 0.85rem; }

.memory-card {
    background: rgba(128,128,128,0.06); border: 1px solid rgba(128,128,128,0.12);
    border-radius: 8px; padding: 0.55rem 0.85rem; margin-bottom: 0.45rem; font-size: 0.8rem;
}
.memory-q   { font-weight: 600; margin-bottom: 2px; }
.memory-lvl { font-size: 0.7rem; opacity: 0.45; }

.score-bar-wrap { height: 8px; border-radius: 4px; background: rgba(128,128,128,0.15); margin-top: 6px; }
.score-bar-fill { height: 8px; border-radius: 4px; }

.indicator-pill {
    background: rgba(239,68,68,0.07); border: 1px solid rgba(239,68,68,0.2);
    border-radius: 6px; padding: 6px 10px; font-size: 0.8rem; margin-bottom: 6px;
}
</style>
""", unsafe_allow_html=True)

LEVEL_ICON  = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🔴", "CRITICAL": "🚨", "UNKNOWN": "⚪"}
LEVEL_COLOR = {"LOW": "#10b981", "MEDIUM": "#f59e0b", "HIGH": "#ef4444", "CRITICAL": "#dc2626", "UNKNOWN": "#9ca3af"}
AGENT_ICON  = {
    "input": "📥", "orchestrator": "🧠", "domain": "🌐",
    "email": "📧", "cve": "🛡️", "phone": "📞",
    "file": "📄", "identity": "👤", "output": "📊",
}

def level_badge(level: str) -> str:
    return f'<span class="risk-badge risk-{level}">{LEVEL_ICON.get(level,"⚪")} {level}</span>'

def score_bar(score: int, color: str) -> str:
    pct = max(4, min(100, int(score)))
    return (
        f'<div class="score-bar-wrap">'
        f'<div class="score-bar-fill" style="width:{pct}%;background:{color}"></div>'
        f'</div>'
    )


# ── Sidebar ───────────────────────────────────────────────────────────────────
def render_sidebar():
    with st.sidebar:
        st.markdown("## 👁️ OSINT-Argus")
        st.caption("Multi-Agent Cybersecurity Analyzer")
        st.divider()
        
        st.markdown("**Letzte Analysen (ChromaDB)**")
        
        # 1. Daten live aus der ChromaDB abfragen (die letzten 8 Analysen)
        try:
            db_entries = get_last_analyses(limit=8)
        except Exception as e:
            st.error("Fehler beim Laden der Historie")
            db_entries = []
            
        if db_entries:
            # Neueste Analysen ganz oben anzeigen
            for entry in reversed(db_entries):
                # ChromaDB speichert Dokumente als Strings. Wenn du dort JSON ablegst, extrahieren wir es:
                try:
                    # Versuche, den gespeicherten Inhalt als JSON zu parsen (falls strukturiert abgelegt)
                    content_data = json.loads(entry["content"])
                    lvl = content_data.get("risk_level", "UNKNOWN")
                    score = content_data.get("score", "?")
                except Exception:
                    # Fallback, falls du flachen Text/Report in die DB schreibst
                    lvl = "?"
                    score = "?"
                
                # Icons und Query vorbereiten
                icon = LEVEL_ICON.get(lvl, "⚪") if 'LEVEL_ICON' in globals() else "⚪"
                query_text = entry["query"][:35]
                timestamp = entry.get("timestamp", "").split(" ")[1] if " " in entry.get("timestamp", "") else ""
                
                # Beschriftung für den Button bauen (Zweizeilig durch Zeilenumbruch)
                button_label = f"{icon} {query_text}\n{lvl} · Score {score}/100 · {timestamp}"
                
                # Einzigartiger Key für Streamlit, basierend auf der Chroma-ID
                if st.button(button_label, key=f"hist_{entry['id']}", use_container_width=True):
                    # Wenn der User klickt, laden wir die Daten in den Session-State
                    st.session_state["active_report_query"] = entry["query"]
                    st.session_state["active_report_content"] = entry["content"]
                    st.rerun() # UI neu laden, um den alten Report im Hauptfenster zu rendern
                    
        else:
            st.caption("Noch keine Analysen in der Datenbank vorhanden.")
            
        st.divider()
        st.caption("Agents: Input · Orchestrator · Domain · Email · CVE · Phone · File · Identity · Output")

# ── NEU: WEICHE FÜR GELADENEN ARCHIV-REPORT ──────────────────────────────
def check_archiv():
    if "active_report_content" in st.session_state:
        st.markdown(
            '<div class="argus-header">'
            '<span style="font-size:2.2rem">📜</span>'
            '<div><p class="argus-title">Archivierter Befund</p>'
            f'<p class="argus-sub">Eingabe: {st.session_state["active_report_query"][:80]}...</p></div>'
            '</div>', unsafe_allow_html=True,
        )
        st.info("ℹ️ Sie betrachten eine historische Analyse aus der ChromaDB-Vektordatenbank.")
        
        try:
            # Dekodiere den JSON-String aus ChromaDB
            data = json.loads(st.session_state["active_report_content"])
            
            lvl = data.get("risk_level", "UNKNOWN")
            score = data.get("score", 0)
            summary = data.get("summary", "")
            indicators = data.get("indicators", [])
            prevent_text = data.get("action_prevent", "")
            incident_steps = data.get("action_incident_response", [])

            # 1. Scores & Badge anzeigen
            col_ts, col_vs, col_lvl = st.columns([1, 1, 1])
            with col_ts:
                st.markdown("**Risiko-Score**")
                color_t = LEVEL_COLOR.get(lvl, "#9ca3af")
                st.markdown(
                    f'<span style="font-size:2.2rem;font-weight:700">{score}</span>'
                    f'<span style="opacity:.4;font-size:1rem"> / 100</span>'
                    f'{score_bar(score, color_t)}',
                    unsafe_allow_html=True,
                )
            with col_vs:
                st.markdown("**Datenquelle**")
                st.markdown('<span style="font-size:1.5rem;font-weight:600;display:block;margin-top:8px;">ChromaDB Persistent</span>', unsafe_allow_html=True)
            with col_lvl:
                st.markdown("**Gesamteinstufung**")
                st.markdown(level_badge(lvl), unsafe_allow_html=True)

            # 2. Zusammenfassung
            if summary:
                st.markdown("---")
                st.markdown("#### Zusammenfassung")
                st.info(summary)

            # 3. Indikatoren
            if indicators:
                st.markdown("#### 💡 Haupt-Risikoindikatoren")
                cols = st.columns(3)
                for i, ind in enumerate(indicators[:9]):
                    clean = ind.replace("**", "").replace("`", "").strip("- ").strip()
                    if not clean:
                        continue
                    with cols[i % 3]:
                        st.markdown(f'<div class="indicator-pill">⚠️ {clean}</div>', unsafe_allow_html=True)

            # 4. Handlungsempfehlungen
            st.markdown("---")
            st.markdown("#### Handlungsempfehlungen")
            col_p, col_i = st.columns(2)
            with col_p:
                st.markdown("🚫 **Unbedingt vermeiden**")
                st.markdown(
                    f'<div class="action-box action-prevent">{prevent_text}</div>',
                    unsafe_allow_html=True,
                )
            with col_i:
                st.markdown("🔥 **Falls bereits geklickt**")
                if incident_steps:
                    incident_text = "<br>".join([f"{step}" if step.startswith(('1.', '2.', '3.', '4.')) else f"{idx+1}. {step}" for idx, step in enumerate(incident_steps)])
                else:
                    incident_text = "Keine spezifischen Incident-Response-Schritte hinterlegt."
                st.markdown(
                    f'<div class="action-box action-incident">{incident_text}</div>',
                    unsafe_allow_html=True,
                )

        except Exception as e:
            # Fallback, falls noch unstrukturierte Altdaten in ChromaDB liegen
            st.warning("Das Format dieser alten Analyse ist unstrukturiert. Zeige Rohdaten an:")
            st.text_area("Report Rohdaten", st.session_state["active_report_content"], height=350)

        st.markdown("---")
        if st.button("🔄 Neue Analyse starten", type="primary"):
            del st.session_state["active_report_content"]
            del st.session_state["active_report_query"]
            st.rerun()
            
        return True # Beendet die Anzeige des Archivs erfolgreich

    return False # Signalisiert main(), dass kein Archiv-Eintrag geladen ist

# ── Leak & Identity Check (Optimiert für sauberes Parsing) ─────────────────
def render_user_profile_section():
    st.header("👤 Digitale Identitäts-Akte (Lernendes Profil)")
    st.write(
        "Dieses Profil schärft sich automatisch aus deinen eingegebenen Texten (Schritt 2). "
        "Du kannst die Daten hier jederzeit korrigieren oder ergänzen."
    )

    # 1. Aktuelles Profil aus ChromaDB laden
    current_profile = get_user_profile()

    # 2. Formular-Felder für den User (Editable)
    with st.form("profile_form"):
        col1, col2 = st.columns(2)
        with col1:
            vorname = st.text_input("Vorname", value=current_profile.get("vorname", "Unbekannt"))
            email = st.text_input("E-Mail-Adresse (für Leak-Checks)", value=current_profile.get("email", "Unbekannt"))
        with col2:
            nachname = st.text_input("Nachname", value=current_profile.get("nachname", "Unbekannt"))
            telefon = st.text_input("Telefonnummer", value=current_profile.get("telefon", "Unbekannt"))

        # Kompetenz und Begriffe (Anzeige)
        st.markdown(f"**Erkanntes IT-Kompetenzlevel:** `{current_profile.get('kompetenz_level', 'UNBEKANNT')}`")
        st.markdown(f"**Gefundene Fachbegriffe:** {', '.join(current_profile.get('fachbegriffe', [])) or 'Keine'}")
        st.caption(f"*Profiler-Charakteristik:* {current_profile.get('charakteristik', '')}")

        save_changes = st.form_submit_button("Profil-Änderungen speichern")
        if save_changes:
            updated_data = {
                "vorname": vorname,
                "nachname": nachname,
                "email": email,
                "telefon": telefon,
                "kompetenz_level": current_profile.get("kompetenz_level", "UNBEKANNT"),
                "fachbegriffe": current_profile.get("fachbegriffe", []),
                "charakteristik": "Manuell vom Nutzer angepasst."
            }
            save_user_profile(updated_data)
            st.success("Profil erfolgreich in ChromaDB aktualisiert!")
            st.rerun()

    # ==============================================================================
    # SCHRITT 3: DER DIRECT CALL BUTTON FÜR BEIDE AGENTEN
    # ==============================================================================
    st.subheader("🛡️ On-Demand OSINT Target-Scanning")
    st.write("Triggere den `LeakAgent` (E-Mail) und den `IdentityAgent` (Klarname) parallel, um Exposures und Profile aufzudecken.")

    if st.button("🔥 Person im Internet aufspüren & prüfen", type="primary"):
        has_valid_email = email and email != "Unbekannt" and "@" in email
        fullname_target = f"{vorname.strip()} {nachname.strip()}".replace("Unbekannt", "").strip()
        
        if not has_valid_email and not fullname_target:
            st.error("❌ Bitte trage zuerst einen Namen oder eine E-Mail-Adresse im Profil ein.")
            return

        st.session_state["osint_scan_results"] = {}

        if has_valid_email:
            with st.spinner(f"🕵️ LeakAgent sucht nach Datenlecks für '{email}'..."):
                try:
                    mock_state_leak = {"current_check": email, "findings": []}
                    leak_agent = LeakAgent()
                    res_leak = leak_agent.run(mock_state_leak)
                    if res_leak.get("findings"):
                        st.session_state["osint_scan_results"]["leak"] = res_leak["findings"][-1]
                except Exception as e:
                    st.error(f"Fehler im LeakAgent: {e}")

        if fullname_target:
            with st.spinner(f"🔎 IdentityAgent scannt soziale Profile für '{fullname_target}'..."):
                try:
                    mock_state_ident = {"current_check": fullname_target, "findings": []}
                    identity_agent = IdentityAgent()
                    res_ident = identity_agent.run(mock_state_ident)
                    if res_ident.get("findings"):
                        st.session_state["osint_scan_results"]["identity"] = res_ident["findings"][-1]
                except Exception as e:
                    st.error(f"Fehler im IdentityAgent: {e}")

    # ==============================================================================
    # OPTIMIERTES ERGEBNIS-RENDERING MIT AUTOMATISCHER LLM-ZUSAMMENFASSUNG
    # ==============================================================================
    if "osint_scan_results" in st.session_state and st.session_state["osint_scan_results"]:
        st.markdown("---")
        st.markdown("## 📊 Kombinierte OSINT-Ermittlungsakte")
        
        scan_data = st.session_state["osint_scan_results"]
        
        # ── HIER TRIGGERN WIR DEN OUTPUT AGENT / DIE ZUSAMMENFASSUNG ──
        if "summary" not in st.session_state["osint_scan_results"]:
            with st.spinner("🧠 OutputAgent generiert die Gesamtlage und Handlungsempfehlungen..."):
                try:
                    from app.models.llm import get_llm
                    # Wir holen das LLM und zwingen es in das strukturierte Summary-Schema
                    summary_llm = get_llm().with_structured_output(ExecutiveSummary)
                    
                    # Rohdaten für das LLM vorbereiten
                    ident_raw = scan_data.get("identity").vulnerability_sum if "identity" in scan_data else []
                    threat_raw = scan_data.get("identity").threat_sum if "identity" in scan_data else []
                    leak_raw = scan_data.get("leak").vulnerability_sum if "leak" in scan_data else []
                    
                    prompt = f"""
                        Du bist ein empathischer, aber glasklarer Cybersecurity-Berater. Analysiere die folgenden OSINT-Ergebnisse und erstelle eine prägnante Lagebeurteilung DIREKT an den Nutzer gerichtet. 

                        Nutze konsequent die Du-Form ("Du", "Dein Profile", "Deine Daten"). Vermeide es, in der dritten Person ("René Haselbach", "das Target") zu sprechen.

                        Gefundene Profile/Datenkonstrukte: {ident_raw}
                        Erkannte Bedrohungen der Identität: {threat_raw}
                        Gefundene Datenlecks (Breaches): {leak_raw}
                        IT-Kompetenzlevel des Nutzers: {current_profile.get('kompetenz_level', 'FORTGESCHRITTEN')}

                        Generiere die Antwort strikt für das Pydantic-Modell 'ExecutiveSummary':
                        1. headline: Eine direkte, wachrüttelnde Punchline (z.B. "Deine Kombination aus Tech-Stack auf GitHub und dem alten Zynga-Leak macht dich zum perfekten Ziel für Spear-Phishing.")
                        2. digital_footprint_summary: Eine kurze Zusammenfassung, was man über DICH im Netz herausfinden kann und wie Angreifer dein Profil (Tech auf GitHub, Privates auf Instagram) verknüpfen.
                        3. primary_threat_vector: Welcher konkrete Angriffs-Szenario droht DIR aktuell am meisten (z.B. Credential Stuffing wegen Zynga oder personalisierte Phishing-Mails)?
                        4. action_items: Eine Liste von exakt 3 konkreten, sofort umsetzbaren To-Dos für den Nutzer (z.B. "Passwort bei Zynga-Identischen Accounts ändern", "2FA auf GitHub aktivieren"). Keine Beschreibungen von Fehlern, sondern klare Handlungsaufforderungen!
                        """
                    
                    summary_res = summary_llm.invoke(prompt)
                    st.session_state["osint_scan_results"]["summary"] = summary_res
                except Exception as e:
                    st.caption(f"Gesamtzusammenfassung temporär nicht verfügbar: {e}")

        # ── EXECUTIVE SUMMARY ANZEIGEN (Falls erfolgreich generiert) ──
        if "summary" in scan_data:
            summary = scan_data["summary"]
            
            # Schicke, auffällige Box für die Punchline
            st.markdown(
                f"""
                <div style="background-color: #f4f6f9; border-left: 5px solid #1f77b4; padding: 15px; border-radius: 6px; margin-bottom: 20px;">
                    <h4 style="margin: 0 0 5px 0; color: #1f77b4;">🔮 OutputAgent: Lagebeurteilung</h4>
                    <p style="font-size: 1.1rem; font-weight: bold; margin: 0;">"{summary.headline}"</p>
                </div>
                """,
                unsafe_allow_html=True
            )
            
            # Key Insights in zwei kleinen Informationsblöcken nebeneinander
            sum_col1, sum_col2 = st.columns(2)
            with sum_col1:
                st.markdown("**🌐 Digitale Präsenz:**")
                st.write(summary.digital_footprint_summary)
            with sum_col2:
                st.markdown("**🎯 Primärer Angriffsvektor:**")
                st.write(summary.primary_threat_vector)
                
            # Die konkrete To-Do-Liste für René
            st.markdown("##### 🛠️ Sofortige Abwehrmaßnahmen (Action Items):")
            for item in summary.action_items:
                st.markdown(f"- [ ] {item}")
            st.markdown("---")

        # ── DARUNTER FOLGEN DIE BEIDEN DETAIL-SPALTEN ──
        col_left, col_right = st.columns([1, 1])

        # ── LINKE SPALTE: IDENTITY AGENT RECHERCHE ──
        with col_left:
            st.markdown("### 👤 IdentityAgent Profil-Funde")
            if "identity" in scan_data:
                ident_finding = scan_data["identity"]
                
                # Risiko-Metrik schön visualisieren
                vector_text = "".join(ident_finding.threat_sum).lower()
                risk_color = "red" if "high" in vector_text or "critical" in vector_text else "orange"
                st.markdown(f"**Spear-Phishing Vektor-Risiko:** <span style='color:{risk_color}; font-weight:bold; font-size:1.1rem;'>⚠️ HIGH</span>", unsafe_allow_html=True)
                
                st.markdown("#### 🌐 Verifizierte Profile & Vektoren")
                
                raw_entries = ident_finding.vulnerability_sum
                current_platform = None
                platform_data = {}

                # Intelligenter Parser
                for entry in raw_entries:
                    entry_str = str(entry).strip()
                    
                    if ("github" in entry_str.lower() or "reddit" in entry_str.lower() or "instagram" in entry_str.lower()) and "https://" in entry_str.lower():
                        current_platform = "GitHub" if "github" in entry_str.lower() else ("Reddit" if "reddit" in entry_str.lower() else "Instagram")
                        url = entry_str.split('(')[1].split(')')[0] if '(' in entry_str else entry_str
                        platform_data[current_platform] = {"url": url, "angriffsvektor": "", "pretexts": []}
                    
                    elif current_platform and "angriffsvektor:" in entry_str.lower():
                        platform_data[current_platform]["angriffsvektor"] = entry_str.split("Angriffsvektor:")[1].strip()
                    
                    elif current_platform and (entry_str.startswith("•") or entry_str.startswith("- •")):
                        clean_pretext = entry_str.replace("•", "").replace('"', '').strip()
                        platform_data[current_platform]["pretexts"].append(clean_pretext)

                if platform_data:
                    for plat_name, data in platform_data.items():
                        st.markdown(f"**🔗 Plattform:** [{plat_name}]({data['url']})")
                        if data["angriffsvektor"]:
                            st.caption(f"**Gefahrenanalyse:** {data['angriffsvektor']}")
                        if data["pretexts"]:
                            with st.expander(f"🎯 Mögliche Phishing-Betreffzeilen ({plat_name})"):
                                for pt in data["pretexts"]:
                                    st.code(pt, language="text")
                        st.markdown("<div style='margin-bottom:15px;'></div>", unsafe_allow_html=True)
                else:
                    st.info("Profile gefunden. Details im Expander:")
                    with st.expander("Rohdaten anzeigen"):
                        st.write(raw_entries)
            else:
                st.caption("Keine Identitätsdaten geladen.")

        # ── RECHTE SPALTE: LEAK AGENT RECHERCHE ──
        with col_right:
            st.markdown("### 🛡️ LeakAgent Exposure-Funde")
            if "leak" in scan_data:
                leak_finding = scan_data["leak"]
                breaches = leak_finding.vulnerability_sum
                
                if not breaches:
                    st.success(f"🎉 **Entwarnung:** Keine bekannten Datenlecks für diese E-Mail registriert.")
                else:
                    st.error(f"🚨 **Gefahr:** Diese Identität ist in **{len(breaches)} Datenlecks** vertreten!")
                    
                    for vuln in breaches:
                        display_name = str(vuln).replace("Breach: ", "")
                        st.markdown(
                            f"""
                            <div style="background-color: #ffeded; border-left: 5px solid #ff4b4b; padding: 10px; border-radius: 4px; margin-bottom: 8px;">
                                <strong style="color: #ff4b4b;">🔥 {display_name}</strong><br/>
                                <small style="color: #555;">Kategorie: Credential Leak Exposure</small>
                            </div>
                            """, 
                            unsafe_allow_html=True
                        )
                        
                        if "zynga" in display_name.lower():
                            with st.expander("ℹ️ Details zu Zynga"):
                                st.write("**Geleakt:** Passwörter (SHA-1), E-Mails, Usernames.")
                                st.write("**Risiko:** Angreifer testen diese Kombinationen automatisiert bei anderen Portalen.")
            else:
                st.caption("Keine Leak-Daten geladen.")
# ── State builder ─────────────────────────────────────────────────────────────
def build_initial_state(user_input: str) -> dict:
    return {
        "user_input": user_input, "input_type": "unknown",
        "current_agent": "input", "next_agent": "",
        "findings": [], "risk_score": None, "summary": None,
        "memory_context": None, "to_scan": [], "scanned": [],
        "current_check": None, "file_paths": [], "file_hashes": [],
    }


# ── Live pipeline runner ──────────────────────────────────────────────────────
def run_with_live_log(user_input: str):
    state    = build_initial_state(user_input)
    log_slot = st.empty()
    log_rows = []   # (agent, target, done)
    t0       = time.time()

    def render_log():
        rows_html = ""
        for agent, target, done in log_rows[-14:]:
            icon   = AGENT_ICON.get(agent, "⚙️")
            status = "✅" if done else "⏳"
            tgt    = target[:60] if target else ""
            rows_html += (
                f'<div class="live-row">'
                f'<span style="font-size:1rem">{icon}</span>'
                f'<span class="live-agent">{agent.upper()}</span>'
                f'<span class="live-target">{tgt}</span>'
                f'<span class="live-status">{status}</span>'
                f'</div>'
            )
        elapsed = round(time.time() - t0, 1)
        log_slot.markdown(
            f'<div style="border:1px solid rgba(128,128,128,0.15);border-radius:10px;padding:1rem 1.2rem;margin:0.5rem 0">'
            f'<div style="font-size:0.7rem;opacity:0.4;margin-bottom:0.6rem;letter-spacing:0.08em">AGENT PIPELINE · {elapsed}s</div>'
            f'{rows_html}'
            f'</div>', unsafe_allow_html=True,
        )

    # We accumulate ALL findings across stream chunks into one list
    all_findings = []
    final_state  = state.copy()

    for chunk in graph.stream(state, stream_mode="updates"):
        for node_name, node_state in chunk.items():
            # Mark previous step done
            if log_rows:
                prev = log_rows[-1]
                log_rows[-1] = (prev[0], prev[1], True)

            target = node_state.get("current_check") or ""
            log_rows.append((node_name, target, False))
            render_log()

            # Merge scalars
            for key in ("risk_score", "risk_level", "summary", "action_advice",
                        "input_type", "memory_context", "next_agent", "current_check"):
                if node_state.get(key) is not None:
                    final_state[key] = node_state[key]

            # Accumulate findings (never overwrite, only extend)
            if node_state.get("findings"):
                all_findings.extend(node_state["findings"])

            # Keep latest queue state
            for key in ("to_scan", "scanned"):
                if key in node_state:
                    final_state[key] = node_state[key]

    # Mark last step done
    if log_rows:
        prev = log_rows[-1]
        log_rows[-1] = (prev[0], prev[1], True)
    render_log()

    final_state["findings"] = all_findings
    return final_state


# ── Helpers for extracting OutputAgent report from findings ───────────────────
def extract_output_report(findings: list) -> dict:
    """
    OutputAgent appends a Findings object with:
      threat_sum = ["Threat Score: 95", "Level: CRITICAL"]
      vulnerability_sum = ["Vulnerability Score: 85", "indicator1", ...]
    We parse those — because stream_mode="updates" only returns keys in
    ArgusState TypedDict, and risk_level/risk_score are missing from it.
    """
    threat_score = vuln_score = None
    risk_level   = None
    indicators   = []

    for f in findings:
        agent_val  = str(getattr(getattr(f, "agent", ""), "value", ""))
        threat_sum = getattr(f, "threat_sum", [])
        vuln_sum   = getattr(f, "vulnerability_sum", [])

        if agent_val != "orchestrator":
            continue
        if not any("Threat Score" in str(t) for t in threat_sum):
            continue

        for t in threat_sum:
            s = str(t)
            if "Threat Score" in s:
                try: threat_score = int(s.split(":")[-1].strip())
                except: pass
            if "Level" in s:
                try: risk_level = s.split(":")[-1].strip()
                except: pass

        for v in vuln_sum:
            s = str(v)
            if "Vulnerability Score" in s:
                try: vuln_score = int(s.split(":")[-1].strip())
                except: pass
            else:
                indicators.append(s)

    return {
        "threat_score": threat_score,
        "vuln_score":   vuln_score,
        "risk_level":   risk_level,
        "indicators":   indicators,
    }


# ── Render results ────────────────────────────────────────────────────────────
def render_results(result: dict):
    findings   = result.get("findings") or []

    # Extract everything from the OutputAgent findings object —
    # stream_mode="updates" does NOT return risk_level/risk_score/summary/action_advice
    # because they are missing from ArgusState TypedDict.
    report = extract_output_report(findings)

    threat_score = report["threat_score"] or 0
    vuln_score   = report["vuln_score"]   or 0
    risk_level   = report["risk_level"]   or result.get("risk_level") or "UNKNOWN"
    risk_score   = max(threat_score, vuln_score)
    indicators   = report["indicators"]

    # summary and action_advice: try state first, then fall back to findings text
    summary    = result.get("summary") or ""
    action_adv = result.get("action_advice") or ""

    st.markdown("---")

    # ── Score row — use the REAL scores from OutputAgent ─────────────────────
    col_ts, col_vs, col_lvl = st.columns([1, 1, 1])

    with col_ts:
        st.markdown("**Bedrohungs-Score**")
        color_t = LEVEL_COLOR.get(risk_level, "#9ca3af")
        st.markdown(
            f'<span style="font-size:2.2rem;font-weight:700">{threat_score}</span>'
            f'<span style="opacity:.4;font-size:1rem"> / 100</span>'
            f'{score_bar(threat_score, color_t)}',
            unsafe_allow_html=True,
        )
    with col_vs:
        st.markdown("**Schwachstellen-Score**")
        st.markdown(
            f'<span style="font-size:2.2rem;font-weight:700">{vuln_score}</span>'
            f'<span style="opacity:.4;font-size:1rem"> / 100</span>'
            f'{score_bar(vuln_score, "#f59e0b")}',
            unsafe_allow_html=True,
        )
    with col_lvl:
        st.markdown("**Gesamteinstufung**")
        st.markdown(level_badge(risk_level), unsafe_allow_html=True)
        if risk_level == "CRITICAL":
            st.error("Sofortiger Handlungsbedarf!")
        elif risk_level == "HIGH":
            st.warning("Erhöhtes Risiko — Vorsicht geboten.")
        elif risk_level == "MEDIUM":
            st.info("Moderates Risiko — aufmerksam bleiben.")
        else:
            st.success("Kein akutes Risiko erkannt.")

    # ── Summary ───────────────────────────────────────────────────────────────
    if summary:
        st.markdown("---")
        st.markdown("#### Zusammenfassung")
        st.info(summary)

    # ── Indicators ────────────────────────────────────────────────────────────
    if indicators:
        st.markdown("#### 💡 Haupt-Risikoindikatoren")
        cols = st.columns(3)
        for i, ind in enumerate(indicators[:9]):
            clean = ind.replace("**", "").replace("`", "").strip("- ").strip()
            if not clean:
                continue
            with cols[i % 3]:
                st.markdown(f'<div class="indicator-pill">⚠️ {clean}</div>', unsafe_allow_html=True)

    # ── Action advice ─────────────────────────────────────────────────────────
    if action_adv:
        st.markdown("---")
        st.markdown("#### Handlungsempfehlungen")

        # Split on the marker the OutputAgent uses
        split_marker = "FALLS BEREITS GEKLICKT:"
        if split_marker in action_adv:
            parts = action_adv.split(split_marker, 1)
            prevent_text  = parts[0].replace("PRÄVENTION:", "").strip()
            incident_text = parts[1].strip()
        else:
            # OutputAgent sometimes uses newline-separated numbered lists without the marker
            prevent_text  = action_adv.strip()
            incident_text = ""

        col_p, col_i = st.columns(2)
        with col_p:
            st.markdown("🚫 **Unbedingt vermeiden**")
            # Render as markdown so bold/lists work
            st.markdown(
                f'<div class="action-box action-prevent">{prevent_text}</div>',
                unsafe_allow_html=True,
            )
        with col_i:
            if incident_text:
                st.markdown("🔥 **Falls bereits geklickt**")
                st.markdown(
                    f'<div class="action-box action-incident">{incident_text}</div>',
                    unsafe_allow_html=True,
                )
            else:
                st.markdown("🔥 **Falls bereits geklickt**")
                st.markdown(
                    '<div class="action-box action-incident">'
                    '1. Gerät sofort vom Netzwerk trennen.<br>'
                    '2. Passwörter von einem sicheren Gerät ändern.<br>'
                    '3. Bank / IT-Sicherheit kontaktieren.<br>'
                    '4. Gerät auf Malware scannen.'
                    '</div>',
                    unsafe_allow_html=True,
                )

    # ── Agent findings detail ─────────────────────────────────────────────────
    st.markdown("---")
    st.markdown("#### Agent-Findings (Detail)")

    # Show only real agent findings — skip orchestrator routing logs and the output summary
    display_findings = []
    seen = set()
    for f in findings:
        agent_val = str(getattr(getattr(f, "agent", ""), "value", ""))
        inp       = getattr(f, "input", "")
        key       = (agent_val, inp)
        if agent_val == "orchestrator":
            continue
        if key in seen:
            continue
        seen.add(key)
        display_findings.append(f)

    if not display_findings:
        st.caption("Keine Detail-Findings vorhanden.")
    else:
        for f in display_findings:
            agent_val  = str(getattr(getattr(f, "agent", ""), "value", "?"))
            inp        = getattr(f, "input", "")
            threats    = getattr(f, "threat_sum", [])
            vulns      = getattr(f, "vulnerability_sum", [])
            icon       = AGENT_ICON.get(agent_val, "⚙️")

            with st.expander(f"{icon} {agent_val.upper()} — {inp[:60]}", expanded=False):
                if threats:
                    st.markdown("**🎯 Bedrohungen**")
                    for t in threats:
                        if str(t).strip():
                            st.markdown(f"- {t}")
                if vulns:
                    st.markdown("**🔍 Schwachstellen / Befunde**")
                    for v in vulns:
                        if str(v).strip():
                            st.markdown(f"- {v}")
                if not threats and not vulns:
                    st.caption("Keine Befunde.")


# ── Main ──────────────────────────────────────────────────────────────────────
# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    render_sidebar()

    if check_archiv(): return

    st.markdown(
        '<div class="argus-header">'
        '<span style="font-size:2.2rem">👁️</span>'
        '<div><p class="argus-title">OSINT-Argus</p>'
        '<p class="argus-sub">Multi-Agent Cybersecurity Analyzer</p></div>'
        '</div>', unsafe_allow_html=True,
    )

    # ==============================================================================
    # SCHRITT 3: TABS FÜR DIE SEKTIONEN (Standardmäßig ist Tab 1 aktiv)
    # ==============================================================================
    tab1, tab2 = st.tabs(["🔍 Analyse-Pipeline", "👤 Profil & Leak-Check"])

    # --- TAB 1: ANALYSE-PIPELINE (STANDARD) ---
    with tab1:
        col_input, col_help = st.columns([3, 1])
        with col_input:
            user_input = st.text_area(
                "Input",
                placeholder=(
                    "Domain          →  example.com\n"
                    "E-Mail-Adresse  →  user@domain.com\n"
                    "E-Mail-Inhalt   →  komplette Mail hier reinkopieren\n"
                    "Telefonnummer   →  +49 151 12345678\n"
                    "Dateipfad/Hash  →  /pfad/zur/datei.pdf"
                ),
                height=190,
                label_visibility="collapsed",
            )
        with col_help:
            st.markdown("**Unterstützte Inputs**")
            for line in ["🌐 Domain / URL", "📧 E-Mail-Adresse", "📨 E-Mail-Inhalt",
                         "📞 Telefonnummer", "📄 Datei / Hash", "🔎 Software + Version"]:
                st.caption(line)

        run_col, clear_col, _ = st.columns([1, 1, 4])
        with run_col:
            run_btn = st.button("🔍 Analysieren", type="primary", use_container_width=True)
        with clear_col:
            if st.button("✕ Leeren", use_container_width=True):
                st.session_state.pop("last_result", None)
                st.rerun()

        if run_btn:
            if not user_input or not user_input.strip():
                st.warning("Bitte einen Input eingeben.")
            else:
                t0 = time.time()
                try:
                    result  = run_with_live_log(user_input.strip())
                    elapsed = round(time.time() - t0, 1)
                    st.success(f"✅ Analyse abgeschlossen in {elapsed}s")
                except Exception as e:
                    st.error(f"❌ Pipeline-Fehler: {type(e).__name__}: {e}")
                    st.stop()

                if "history" not in st.session_state:
                    st.session_state["history"] = []
                st.session_state["history"].append({
                    "query":      user_input.strip()[:60],
                    "risk_level": result.get("risk_level", "UNKNOWN"),
                    "score":      result.get("risk_score", 0),
                })
                st.session_state["last_result"] = result

        if "last_result" in st.session_state:
            render_results(st.session_state["last_result"])

    # --- TAB 2: PROFIL & LEAK SCAN ---
    with tab2:
        render_user_profile_section()


if __name__ == "__main__":
    main()