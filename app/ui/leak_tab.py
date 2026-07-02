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
from app.ui.strings import t


def render_leak_tab() -> None:
    """Rendert den kompletten Profil- & Leak-Check Tab."""
    lang = st.session_state.get("ui_language", "en")
    st.header(t("profile_header", lang))
    st.write(t("profile_description", lang))

    current_profile = get_user_profile()
    vorname, nachname, email, telefon, nicks, gamer_tag = _render_profile_form(current_profile, lang)
    _render_osint_scan_button(vorname, nachname, email, nicks, gamer_tag, current_profile, lang)
    _render_scan_results(current_profile, lang)


# ── Profil-Formular ───────────────────────────────────────────────────────────

def _render_profile_form(current_profile: dict, lang: str) -> tuple[str, str, str, str, list, str]:
    """Zeigt das editierbare Profil-Formular und gibt die aktuellen Feldwerte zurück."""
    with st.form("profile_form"):
        col1, col2 = st.columns(2)
        with col1:
            vorname = st.text_input(t("field_firstname", lang), value=current_profile.get("vorname", "Unbekannt"))
            email   = st.text_input(t("field_email", lang), value=current_profile.get("email", "Unbekannt"))
            nicks   = st.text_area(t("field_nicks", lang), 
                                   value=", ".join(current_profile.get("nicks", [])), 
                                   placeholder=t("placeholder_nicks", lang))
        with col2:
            nachname = st.text_input(t("field_lastname", lang), value=current_profile.get("nachname", "Unbekannt"))
            telefon  = st.text_input(t("field_phone", lang), value=current_profile.get("telefon", "Unbekannt"))
            gamer_tag = st.text_input(t("field_gamer_tag", lang), value=current_profile.get("gamer_tag", "Unbekannt"))

        st.markdown(f"{t('label_it_competency', lang)} `{current_profile.get('kompetenz_level', 'UNBEKANNT')}`")
        st.markdown(f"{t('label_expert_terms', lang)} {', '.join(current_profile.get('fachbegriffe', [])) or 'Keine'}")
        st.caption(f"{t('caption_profile_char', lang)} {current_profile.get('charakteristik', '')}")

        nick_list = []
        if st.form_submit_button(t("btn_save_profile", lang)):
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
            st.success(t("msg_profile_saved", lang))
            st.rerun()

    return vorname, nachname, email, telefon, nick_list, gamer_tag


# ── OSINT-Scan-Button ─────────────────────────────────────────────────────────

def _render_osint_scan_button(
    vorname: str, nachname: str, email: str, nicks: list, gamer_tag: str, current_profile: dict, lang: str
) -> None:
    st.subheader(t("subheader_osint_scan", lang))
    st.write(t("osint_scan_description", lang))

    if not st.button(t("btn_scan_person", lang), type="primary"):
        return

    has_valid_email = bool(email and email != "Unbekannt" and "@" in email)
    fullname_target = f"{vorname.strip()} {nachname.strip()}".replace("Unbekannt", "").strip()
    has_nicks = bool(nicks or gamer_tag and gamer_tag != "Unbekannt")

    if not has_valid_email and not fullname_target and not has_nicks:
        st.error(t("msg_profile_empty", lang))
        return

    st.session_state["osint_scan_results"] = {}
    skip_targets = st.session_state.get("skip_osint_targets", set())

    if has_valid_email and email not in skip_targets:
        with st.spinner(t("spinner_leak_agent", lang, email=email)):
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
        st.markdown(t("section_osint_results", lang))
        
        all_findings = []
        for idx, (label, target) in enumerate(search_targets):
            if target in skip_targets:
                st.caption(t("msg_skipped", lang, label=label, target=target))
                continue
            
            start_time = time.time()
            with st.spinner(t("spinner_identity_scan", lang, idx=idx+1, total=len(search_targets), label=label, target=target)):
                try:
                    res = IdentityAgent().run({"current_check": target, "findings": []})
                    elapsed = round(time.time() - start_time, 1)
                    
                    if res.get("findings"):
                        all_findings.extend(res["findings"])
                        st.success(t("msg_scan_complete", lang, label=label, elapsed=elapsed))
                    else:
                        st.warning(t("msg_no_results", lang, label=label, elapsed=elapsed))
                except Exception as e:
                    st.error(t("msg_scan_error", lang, label=label, error=e))
        
        if all_findings:
            st.session_state["osint_scan_results"]["identity"] = all_findings[-1]


# ── Ergebnis-Rendering ────────────────────────────────────────────────────────

def _render_scan_results(current_profile: dict, lang: str) -> None:
    scan_data = st.session_state.get("osint_scan_results")
    if not scan_data:
        return

    st.markdown("---")
    st.markdown(t("section_combined_report", lang))

    _maybe_generate_summary(scan_data, current_profile, lang)
    _render_executive_summary(scan_data)

    col_left, col_right = st.columns([1, 1])
    with col_left:
        _render_identity_column(scan_data, lang)
    with col_right:
        _render_leak_column(scan_data, lang)


def _maybe_generate_summary(scan_data: dict, current_profile: dict, lang: str) -> None:
    """Generiert die Executive-Summary via LLM, sofern noch nicht vorhanden."""
    if "summary" in scan_data:
        return

    with st.spinner(t("spinner_summary", lang)):
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
            st.caption(t("caption_summary_unavailable", lang, error=e))


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


def _render_identity_column(scan_data: dict, lang: str) -> None:
    st.markdown(t("col_identity_finds", lang))

    if "identity" not in scan_data:
        st.caption(t("msg_no_identity_data", lang))
        return

    ident_finding = scan_data["identity"]
    vector_text   = "".join(ident_finding.threat_sum).lower()
    risk_color    = "#dc2626" if ("high" in vector_text or "critical" in vector_text) else "#ea580c"

    risk_label = "⚠️ HIGH" if ("high" in vector_text or "critical" in vector_text) else "⚠️ MEDIUM"
    st.markdown(
        f"{t('label_spear_phishing_risk', lang)} <span style='color:{risk_color};font-weight:bold;font-size:1.1rem;'>{risk_label}</span>",
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
                st.caption(t("caption_attack_vector", lang, vector=data['angriffsvektor']))
            else:
                st.caption(t("caption_no_attack_vector", lang))
    else:
        st.info(t("msg_no_profiles_found", lang))
        with st.expander(t("expander_raw_data", lang)):
            st.write(raw_entries)


def _render_leak_column(scan_data: dict, lang: str) -> None:
    st.markdown(t("col_leak_finds", lang))

    if "leak" not in scan_data:
        st.caption(t("msg_no_leak_data", lang))
        return

    leak_finding = scan_data["leak"]
    breaches     = leak_finding.vulnerability_sum

    if not breaches:
        st.success(t("msg_no_leaks_found", lang))
        return

    st.error(t("msg_breaches_found", lang, count=len(breaches)))

    leak_details_en = {
        "canva": {
            "leaked": "Email, Name, Password, Memberships in Design groups",
            "risk": "Password reuse testing, interests (Design) visible for targeted attacks"
        },
        "zynga": {
            "leaked": "Email, Password, Username (Gaming services)",
            "risk": "Password may work on other services"
        },
        "adobe": {
            "leaked": "Email, Password, Credit card ending (Creative Cloud)",
            "risk": "Access to Adobe services if password reused"
        },
        "linkedin": {
            "leaked": "Email, Password, Profile data (Profession, Company)",
            "risk": "Business Email Compromise (BEC), targeted attacks via professional network"
        },
        "dropbox": {
            "leaked": "Email, Password (Cloud storage)",
            "risk": "Access to private files if password reused"
        }
    }
    
    leak_details_de = {
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

    leak_details = leak_details_de if lang == "de" else leak_details_en

    for vuln in breaches:
        display_name = str(vuln).replace("Breach: ", "")
        display_lower = display_name.lower()

        detail = None
        for key, info in leak_details.items():
            if key in display_lower:
                detail = info
                break

        leaked_text = detail.get("leaked" if lang == "en" else "geleakt") if detail else "Daten bekannt aus Breach-Datenbank"
        
        st.markdown(
            f"""
            <div style="background-color:#ffeded;border-left:4px solid #ff4b4b;
                        padding:10px;border-radius:4px;margin-bottom:8px;">
                <strong style="color:#ff4b4b;">🔥 {display_name}</strong><br/>
                <small style="color:#666;margin-top:4px;display:block;">
                {leaked_text}
                </small>
            </div>
            """,
            unsafe_allow_html=True,
        )