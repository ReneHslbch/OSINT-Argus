"""
app/ui/leak_tab.py
Tab 2: Digitale Identitäts-Akte — Profil-Verwaltung, OSINT-Scan
und kombinierte Ergebnisdarstellung.
"""

import streamlit as st

from app.memory.chroma_memory import get_user_profile, save_user_profile
from app.agents.leak_agent import LeakAgent
from app.agents.identity_agent import IdentityAgent
from app.models.router import ExecutiveSummary


def render_leak_tab() -> None:
    """Rendert den kompletten Profil- & Leak-Check Tab."""
    st.header("👤 Digitale Identitäts-Akte (Lernendes Profil)")
    st.write(
        "Dieses Profil schärft sich automatisch aus deinen eingegebenen Texten (Schritt 2). "
        "Du kannst die Daten hier jederzeit korrigieren oder ergänzen."
    )

    current_profile = get_user_profile()
    vorname, nachname, email, telefon = _render_profile_form(current_profile)
    _render_osint_scan_button(vorname, nachname, email, current_profile)
    _render_scan_results(current_profile)


# ── Profil-Formular ───────────────────────────────────────────────────────────

def _render_profile_form(current_profile: dict) -> tuple[str, str, str, str]:
    """Zeigt das editierbare Profil-Formular und gibt die aktuellen Feldwerte zurück."""
    with st.form("profile_form"):
        col1, col2 = st.columns(2)
        with col1:
            vorname = st.text_input("Vorname",                          value=current_profile.get("vorname",   "Unbekannt"))
            email   = st.text_input("E-Mail-Adresse (für Leak-Checks)", value=current_profile.get("email",    "Unbekannt"))
        with col2:
            nachname = st.text_input("Nachname",       value=current_profile.get("nachname", "Unbekannt"))
            telefon  = st.text_input("Telefonnummer",  value=current_profile.get("telefon",  "Unbekannt"))

        st.markdown(f"**Erkanntes IT-Kompetenzlevel:** `{current_profile.get('kompetenz_level', 'UNBEKANNT')}`")
        st.markdown(f"**Gefundene Fachbegriffe:** {', '.join(current_profile.get('fachbegriffe', [])) or 'Keine'}")
        st.caption(f"*Profiler-Charakteristik:* {current_profile.get('charakteristik', '')}")

        if st.form_submit_button("Profil-Änderungen speichern"):
            updated = {
                "vorname":          vorname,
                "nachname":         nachname,
                "email":            email,
                "telefon":          telefon,
                "kompetenz_level":  current_profile.get("kompetenz_level", "UNBEKANNT"),
                "fachbegriffe":     current_profile.get("fachbegriffe", []),
                "charakteristik":   "Manuell vom Nutzer angepasst.",
            }
            save_user_profile(updated)
            st.success("Profil erfolgreich in ChromaDB aktualisiert!")
            st.rerun()

    return vorname, nachname, email, telefon


# ── OSINT-Scan-Button ─────────────────────────────────────────────────────────

def _render_osint_scan_button(
    vorname: str, nachname: str, email: str, current_profile: dict
) -> None:
    st.subheader("🛡️ On-Demand OSINT Target-Scanning")
    st.write(
        "Triggere den `LeakAgent` (E-Mail) und den `IdentityAgent` (Klarname) parallel, "
        "um Exposures und Profile aufzudecken."
    )

    if not st.button("🔥 Person im Internet aufspüren & prüfen", type="primary"):
        return

    has_valid_email = bool(email and email != "Unbekannt" and "@" in email)
    fullname_target = f"{vorname.strip()} {nachname.strip()}".replace("Unbekannt", "").strip()

    if not has_valid_email and not fullname_target:
        st.error("❌ Bitte trage zuerst einen Namen oder eine E-Mail-Adresse im Profil ein.")
        return

    st.session_state["osint_scan_results"] = {}

    if has_valid_email:
        with st.spinner(f"🕵️ LeakAgent sucht nach Datenlecks für '{email}'..."):
            try:
                res = LeakAgent().run({"current_check": email, "findings": []})
                if res.get("findings"):
                    st.session_state["osint_scan_results"]["leak"] = res["findings"][-1]
            except Exception as e:
                st.error(f"Fehler im LeakAgent: {e}")

    if fullname_target:
        with st.spinner(f"🔎 IdentityAgent scannt soziale Profile für '{fullname_target}'..."):
            try:
                res = IdentityAgent().run({"current_check": fullname_target, "findings": []})
                if res.get("findings"):
                    st.session_state["osint_scan_results"]["identity"] = res["findings"][-1]
            except Exception as e:
                st.error(f"Fehler im IdentityAgent: {e}")


# ── Ergebnis-Rendering ────────────────────────────────────────────────────────

def _render_scan_results(current_profile: dict) -> None:
    scan_data = st.session_state.get("osint_scan_results")
    if not scan_data:
        return

    st.markdown("---")
    st.markdown("## 📊 Kombinierte OSINT-Ermittlungsakte")

    _maybe_generate_summary(scan_data, current_profile)
    _render_executive_summary(scan_data)

    col_left, col_right = st.columns([1, 1])
    with col_left:
        _render_identity_column(scan_data)
    with col_right:
        _render_leak_column(scan_data)


def _maybe_generate_summary(scan_data: dict, current_profile: dict) -> None:
    """Generiert die Executive-Summary via LLM, sofern noch nicht vorhanden."""
    if "summary" in scan_data:
        return

    with st.spinner("🧠 OutputAgent generiert die Gesamtlage und Handlungsempfehlungen..."):
        try:
            from app.models.llm import get_llm

            summary_llm = get_llm().with_structured_output(ExecutiveSummary)

            ident_raw  = scan_data["identity"].vulnerability_sum if "identity" in scan_data else []
            threat_raw = scan_data["identity"].threat_sum        if "identity" in scan_data else []
            leak_raw   = scan_data["leak"].vulnerability_sum     if "leak"     in scan_data else []

            prompt = f"""
Du bist ein empathischer, aber glasklarer Cybersecurity-Berater. Analysiere die folgenden
OSINT-Ergebnisse und erstelle eine prägnante Lagebeurteilung DIREKT an den Nutzer gerichtet.

Nutze konsequent die Du-Form ("Du", "Dein Profile", "Deine Daten"). Vermeide es, in der
dritten Person zu sprechen.

Gefundene Profile/Datenkonstrukte: {ident_raw}
Erkannte Bedrohungen der Identität: {threat_raw}
Gefundene Datenlecks (Breaches): {leak_raw}
IT-Kompetenzlevel des Nutzers: {current_profile.get('kompetenz_level', 'FORTGESCHRITTEN')}

Generiere die Antwort strikt für das Pydantic-Modell 'ExecutiveSummary':
1. headline: Eine direkte, wachrüttelnde Punchline.
2. digital_footprint_summary: Kurze Zusammenfassung, was man über DICH im Netz herausfinden kann.
3. primary_threat_vector: Welcher konkrete Angriffs-Szenario droht DIR aktuell am meisten?
4. action_items: Eine Liste von exakt 3 konkreten, sofort umsetzbaren To-Dos.
"""
            st.session_state["osint_scan_results"]["summary"] = summary_llm.invoke(prompt)
        except Exception as e:
            st.caption(f"Gesamtzusammenfassung temporär nicht verfügbar: {e}")


def _render_executive_summary(scan_data: dict) -> None:
    summary = scan_data.get("summary")
    if not summary:
        return

    st.markdown(
        f"""
        <div style="background-color:#f4f6f9;border-left:5px solid #1f77b4;
                    padding:15px;border-radius:6px;margin-bottom:20px;">
            <h4 style="margin:0 0 5px 0;color:#1f77b4;">🔮 OutputAgent: Lagebeurteilung</h4>
            <p style="font-size:1.1rem;font-weight:bold;margin:0;">"{summary.headline}"</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    c1, c2 = st.columns(2)
    with c1:
        st.markdown("**🌐 Digitale Präsenz:**")
        st.write(summary.digital_footprint_summary)
    with c2:
        st.markdown("**🎯 Primärer Angriffsvektor:**")
        st.write(summary.primary_threat_vector)

    st.markdown("##### 🛠️ Sofortige Abwehrmaßnahmen (Action Items):")
    for item in summary.action_items:
        st.markdown(f"- [ ] {item}")
    st.markdown("---")


def _render_identity_column(scan_data: dict) -> None:
    st.markdown("### 👤 IdentityAgent Profil-Funde")

    if "identity" not in scan_data:
        st.caption("Keine Identitätsdaten geladen.")
        return

    ident_finding = scan_data["identity"]
    vector_text   = "".join(ident_finding.threat_sum).lower()
    risk_color    = "red" if ("high" in vector_text or "critical" in vector_text) else "orange"

    st.markdown(
        f"**Spear-Phishing Vektor-Risiko:** "
        f"<span style='color:{risk_color};font-weight:bold;font-size:1.1rem;'>⚠️ HIGH</span>",
        unsafe_allow_html=True,
    )
    st.markdown("#### 🌐 Verifizierte Profile & Vektoren")

    raw_entries     = ident_finding.vulnerability_sum
    current_platform = None
    platform_data: dict[str, dict] = {}

    for entry in raw_entries:
        entry_str = str(entry).strip()

        if (
            ("github" in entry_str.lower() or "reddit" in entry_str.lower() or "instagram" in entry_str.lower())
            and "https://" in entry_str.lower()
        ):
            current_platform = (
                "GitHub"    if "github"    in entry_str.lower() else
                "Reddit"    if "reddit"    in entry_str.lower() else
                "Instagram"
            )
            url = entry_str.split("(")[1].split(")")[0] if "(" in entry_str else entry_str
            platform_data[current_platform] = {"url": url, "angriffsvektor": "", "pretexts": []}

        elif current_platform and "angriffsvektor:" in entry_str.lower():
            platform_data[current_platform]["angriffsvektor"] = (
                entry_str.split("Angriffsvektor:")[1].strip()
            )

        elif current_platform and (entry_str.startswith("•") or entry_str.startswith("- •")):
            clean_pretext = entry_str.replace("•", "").replace('"', "").strip()
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


def _render_leak_column(scan_data: dict) -> None:
    st.markdown("### 🛡️ LeakAgent Exposure-Funde")

    if "leak" not in scan_data:
        st.caption("Keine Leak-Daten geladen.")
        return

    leak_finding = scan_data["leak"]
    breaches     = leak_finding.vulnerability_sum

    if not breaches:
        st.success("🎉 **Entwarnung:** Keine bekannten Datenlecks für diese E-Mail registriert.")
        return

    st.error(f"🚨 **Gefahr:** Diese Identität ist in **{len(breaches)} Datenlecks** vertreten!")

    for vuln in breaches:
        display_name = str(vuln).replace("Breach: ", "")
        st.markdown(
            f"""
            <div style="background-color:#ffeded;border-left:5px solid #ff4b4b;
                        padding:10px;border-radius:4px;margin-bottom:8px;">
                <strong style="color:#ff4b4b;">🔥 {display_name}</strong><br/>
                <small style="color:#555;">Kategorie: Credential Leak Exposure</small>
            </div>
            """,
            unsafe_allow_html=True,
        )

        if "zynga" in display_name.lower():
            with st.expander("ℹ️ Details zu Zynga"):
                st.write("**Geleakt:** Passwörter (SHA-1), E-Mails, Usernames.")
                st.write(
                    "**Risiko:** Angreifer testen diese Kombinationen automatisiert "
                    "bei anderen Portalen."
                )