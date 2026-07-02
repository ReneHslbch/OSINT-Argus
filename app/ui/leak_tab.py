"""
app/ui/leak_tab.py
Tab 2: Digitale Identitäts-Akte — Profil-Verwaltung, OSINT-Scan
und kombinierte Ergebnisdarstellung.
"""

import time
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
    vorname, nachname, email, telefon, nicks, gamer_tag = _render_profile_form(current_profile)
    _render_osint_scan_button(vorname, nachname, email, nicks, gamer_tag, current_profile)
    _render_scan_results(current_profile)


# ── Profil-Formular ───────────────────────────────────────────────────────────

def _render_profile_form(current_profile: dict) -> tuple[str, str, str, str, list, str]:
    """Zeigt das editierbare Profil-Formular und gibt die aktuellen Feldwerte zurück."""
    with st.form("profile_form"):
        col1, col2 = st.columns(2)
        with col1:
            vorname = st.text_input("Vorname",                          value=current_profile.get("vorname",   "Unbekannt"))
            email   = st.text_input("E-Mail-Adresse (für Leak-Checks)", value=current_profile.get("email",    "Unbekannt"))
            nicks   = st.text_area("Nicks / Spitznamen (durch Komma getrennt)", 
                                   value=", ".join(current_profile.get("nicks", [])), 
                                   placeholder="z.B. Max, Momo, Gamer123")
        with col2:
            nachname = st.text_input("Nachname",       value=current_profile.get("nachname", "Unbekannt"))
            telefon  = st.text_input("Telefonnummer",  value=current_profile.get("telefon",  "Unbekannt"))
            gamer_tag = st.text_input("Gamer Tag / Handle", 
                                      value=current_profile.get("gamer_tag", "Unbekannt"))

        st.markdown(f"**Erkanntes IT-Kompetenzlevel:** `{current_profile.get('kompetenz_level', 'UNBEKANNT')}`")
        st.markdown(f"**Gefundene Fachbegriffe:** {', '.join(current_profile.get('fachbegriffe', [])) or 'Keine'}")
        st.caption(f"*Profiler-Charakteristik:* {current_profile.get('charakteristik', '')}")

        nick_list = []
        if st.form_submit_button("Profil-Änderungen speichern"):
            nick_list = [n.strip() for n in nicks.split(",") if n.strip()]
            updated = {
                "vorname":          vorname,
                "nachname":         nachname,
                "email":            email,
                "telefon":          telefon,
                "nicks":            nick_list,
                "gamer_tag":        gamer_tag,
                "kompetenz_level":  current_profile.get("kompetenz_level", "UNBEKANNT"),
                "fachbegriffe":     current_profile.get("fachbegriffe", []),
                "charakteristik":   "Manuell vom Nutzer angepasst.",
            }
            save_user_profile(updated)
            st.success("Profil erfolgreich in ChromaDB aktualisiert!")
            st.rerun()

    return vorname, nachname, email, telefon, nick_list, gamer_tag


# ── OSINT-Scan-Button ─────────────────────────────────────────────────────────

def _render_osint_scan_button(
    vorname: str, nachname: str, email: str, nicks: list, gamer_tag: str, current_profile: dict
) -> None:
    st.subheader("🛡️ On-Demand OSINT Target-Scanning")
    st.write(
        "Triggere den `LeakAgent` (E-Mail) und den `IdentityAgent` (Klarname, Nicks, Gamer-Tags) parallel, "
        "um Exposures und Profile aufzudecken."
    )

    if not st.button("🔥 Person im Internet aufspüren & prüfen", type="primary"):
        return

    has_valid_email = bool(email and email != "Unbekannt" and "@" in email)
    fullname_target = f"{vorname.strip()} {nachname.strip()}".replace("Unbekannt", "").strip()
    has_nicks = bool(nicks or gamer_tag and gamer_tag != "Unbekannt")

    if not has_valid_email and not fullname_target and not has_nicks:
        st.error("❌ Bitte trage zuerst einen Namen, eine E-Mail-Adresse oder einen Nick/Gamer-Tag im Profil ein.")
        return

    st.session_state["osint_scan_results"] = {}
    skip_targets = st.session_state.get("skip_osint_targets", set())

    if has_valid_email and email not in skip_targets:
        with st.spinner(f"🕵️ LeakAgent sucht nach Datenlecks für '{email}'..."):
            try:
                res = LeakAgent().run({"current_check": email, "findings": []})
                if res.get("findings"):
                    st.session_state["osint_scan_results"]["leak"] = res["findings"][-1]
            except Exception as e:
                st.error(f"Fehler im LeakAgent: {e}")

    search_targets = []
    if fullname_target:
        search_targets.append(("Name", fullname_target))
    for nick in nicks:
        if nick.strip():
            search_targets.append(("Nick", nick.strip()))
    if gamer_tag and gamer_tag != "Unbekannt":
        search_targets.append(("Gamer-Tag", gamer_tag))

    if search_targets:
        st.markdown("### 🔎 OSINT-Scan Ergebnisse")
        
        all_findings = []
        for idx, (label, target) in enumerate(search_targets):
            if target in skip_targets:
                st.caption(f"⏭️ Übersprungen: {label} '{target}'")
                continue
            
            start_time = time.time()
            with st.spinner(f"🔍 Scan {idx+1}/{len(search_targets)}: {label} '{target}'..."):
                try:
                    res = IdentityAgent().run({"current_check": target, "findings": []})
                    elapsed = round(time.time() - start_time, 1)
                    
                    if res.get("findings"):
                        all_findings.extend(res["findings"])
                        st.success(f"✅ {label} ({elapsed}s)")
                    else:
                        st.warning(f"⚠️ Keine Ergebnisse für {label} ({elapsed}s)")
                except Exception as e:
                    st.error(f"❌ Fehler bei {label}: {e}")
        
        if all_findings:
            st.session_state["osint_scan_results"]["identity"] = all_findings[-1]


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
                    padding:12px;border-radius:6px;margin-bottom:15px;">
            <p style="font-size:1.05rem;font-weight:bold;margin:0;">"{summary.headline}"</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _render_identity_column(scan_data: dict) -> None:
    st.markdown("### 👤 Profil-Funde")

    if "identity" not in scan_data:
        st.caption("Keine Identitätsdaten geladen.")
        return

    ident_finding = scan_data["identity"]
    vector_text   = "".join(ident_finding.threat_sum).lower()
    risk_color    = "#dc2626" if ("high" in vector_text or "critical" in vector_text) else "#ea580c"

    risk_label = "⚠️ HIGH" if ("high" in vector_text or "critical" in vector_text) else "⚠️ MEDIUM"
    st.markdown(
        f"**Spear-Phishing-Risiko:** <span style='color:{risk_color};font-weight:bold;font-size:1.1rem;'>{risk_label}</span>",
        unsafe_allow_html=True,
    )

    raw_entries = ident_finding.vulnerability_sum

    platform_data: dict[str, dict] = {}
    current_platform = None

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

        elif current_platform and "angriffsvektor" in entry_str.lower():
            parts = entry_str.split(":", 1)
            if len(parts) > 1:
                platform_data[current_platform]["angriffsvektor"] = parts[1].strip()

        elif current_platform and (entry_str.startswith("•") or entry_str.startswith("- •")):
            clean_pretext = entry_str.replace("•", "").replace('"', "").strip()
            platform_data[current_platform]["pretexts"].append(clean_pretext)

    if platform_data:
        for plat_name, data in platform_data.items():
            st.markdown(f"🔗 **{plat_name}:** [{data['url']}]({data['url']})")
            if data["angriffsvektor"]:
                st.caption(f"⚡ {data['angriffsvektor']}")
            else:
                st.caption("⚡ Keine spezifischen Angriffsvektoren gefunden.")
    else:
        st.info("Keine Profile gefunden.")
        with st.expander("Rohdaten anzeigen"):
            st.write(raw_entries)


def _render_leak_column(scan_data: dict) -> None:
    st.markdown("### 🛡️ Leak-Funde")

    if "leak" not in scan_data:
        st.caption("Keine Leak-Daten geladen.")
        return

    leak_finding = scan_data["leak"]
    breaches     = leak_finding.vulnerability_sum

    if not breaches:
        st.success("✅ Keine bekannten Datenlecks.")
        return

    st.error(f"🚨 **{len(breaches)} Datenleck(s)** gefunden!")

    leak_details = {
        "canva": {
            "geleakt": "E-Mail, Name, Passwort, Mitgliedschaften in Design-Gruppen",
            "risiko": "Passwort-Wiederverwendung testen, Interessen (Design) sichtbar für gezielte Angriffe"
        },
        "zynga": {
            "geleakt": "E-Mail, Passwort, Benutzername (Gaming-Dienste)",
            "risiko": "Passwort könnte bei anderen Diensten funktionieren"
        },
        "adobe": {
            "geleakt": "E-Mail, Passwort, Kreditkarten-Endung (Creative Cloud)",
            "risiko": "Zugang zu Adobe-Diensten bei Passwort-Wiederverwendung"
        },
        "linkedin": {
            "geleakt": "E-Mail, Passwort, Profil-Daten (Beruf, Unternehmen)",
            "risiko": "Business Email Compromise (BEC), gezielte Angriffe über Berufsnetzwerk"
        },
        "dropbox": {
            "geleakt": "E-Mail, Passwort (Cloud-Speicher)",
            "risiko": "Zugriff auf private Dateien bei Passwort-Wiederverwendung"
        }
    }

    for vuln in breaches:
        display_name = str(vuln).replace("Breach: ", "")
        display_lower = display_name.lower()

        detail = None
        for key, info in leak_details.items():
            if key in display_lower:
                detail = info
                break

        st.markdown(
            f"""
            <div style="background-color:#ffeded;border-left:4px solid #ff4b4b;
                        padding:10px;border-radius:4px;margin-bottom:8px;">
                <strong style="color:#ff4b4b;">🔥 {display_name}</strong><br/>
                <small style="color:#666;margin-top:4px;display:block;">
                {detail['geleakt'] if detail else 'Daten bekannt aus Breach-Datenbank'}
                </small>
            </div>
            """,
            unsafe_allow_html=True,
        )