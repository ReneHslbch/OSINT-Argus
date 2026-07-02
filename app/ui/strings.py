"""
app/ui/strings.py
I18N translation layer for static UI strings.

Default language: English ("en")
UI language is independent from analysis language - manually switchable via sidebar.
"""

from typing import Dict, Literal

Language = Literal["en", "de"]

STRINGS: Dict[Language, Dict[str, str]] = {
    "en": {
        # ── Page & Header ──────────────────────────────────────────────────────
        "page_title": "OSINT-Argus",
        "header_subtitle": "Multi-Agent Cybersecurity Analyzer",
        
        # ── Tabs ───────────────────────────────────────────────────────────────
        "tab_analyze": "🔍 Analysis Pipeline",
        "tab_profile": "👤 Profile & Leak-Check",
        
        # ── Input Section ──────────────────────────────────────────────────────
        "input_label": "Input",
        "input_placeholder": (
            "Domain          →  example.com\n"
            "Email Address   →  user@example.com\n"
            "Email Content   →  paste complete email here\n"
            "Phone Number    →  +49 151 12345678\n"
            "File Path/Hash  →  /path/to/file.pdf"
        ),
        "supported_inputs_title": "**Supported Inputs**",
        "supported_inputs": [
            "🌐 Domain / URL",
            "📧 Email Address",
            "📨 Email Content",
            "📞 Phone Number",
            "📄 File / Hash",
            "🔎 Software + Version",
        ],
        
        # ── Buttons ────────────────────────────────────────────────────────────
        "btn_analyze": "🔍 Analyze",
        "btn_clear": "✕ Clear",
        "btn_save_profile": "Save Profile Changes",
        "btn_scan_person": "🔍 Search & Verify Person Online",
        "btn_new_analysis": "🔄 Start New Analysis",
        
        # ── Messages ───────────────────────────────────────────────────────────
        "msg_input_required": "Please enter an input.",
        "msg_analysis_complete": "✅ Analysis completed in {elapsed}s",
        "msg_pipeline_error": "❌ Pipeline error: {type}: {error}",
        "msg_profile_saved": "Profile successfully updated in ChromaDB!",
        "msg_profile_empty": "❌ Please enter a name, email address, or nick/Gamer-Tag in the profile first.",
        
        # ── Leak Tab / Profile ─────────────────────────────────────────────────
        "profile_header": "👤 Digital Identity Archive (Learning Profile)",
        "profile_description": (
            "This profile automatically sharpens from your entered texts (Step 2). "
            "You can correct or supplement the data here at any time."
        ),
        "field_firstname": "First Name",
        "field_lastname": "Last Name",
        "field_email": "Email Address (for Leak-Checks)",
        "field_phone": "Phone Number",
        "field_nicks": "Nicks / Nicknames (comma-separated)",
        "field_gamer_tag": "Gamer Tag / Handle",
        "placeholder_nicks": "e.g. Max, Momo, Gamer123",
        "label_it_competency": "**Detected IT Competency Level:**",
        "label_expert_terms": "**Found Expert Terms:**",
        "caption_profile_char": "*Profiler Characteristic:*",
        
        # ── Leak Tab / OSINT Scan ──────────────────────────────────────────────
        "subheader_osint_scan": "🛡️ On-Demand OSINT Target-Scanning",
        "osint_scan_description": (
            "Trigger the `LeakAgent` (email) and `IdentityAgent` (name, nicks, Gamer-Tags) in parallel "
            "to uncover exposures and profiles."
        ),
        "spinner_leak_agent": "🕵️ LeakAgent searching for data leaks for '{email}'...",
        "section_osint_results": "### 🔎 OSINT-Scan Results",
        "msg_skipped": "⏭️ Skipped: {label} '{target}'",
        "spinner_identity_scan": "🔍 Scan {idx}/{total}: {label} '{target}'...",
        "msg_scan_complete": "✅ {label} ({elapsed}s)",
        "msg_no_results": "⚠️ No results for {label} ({elapsed}s)",
        "msg_scan_error": "❌ Error in {label}: {error}",
        "section_combined_report": "## 📊 Combined OSINT Investigation File",
        "spinner_summary": "🧠 OutputAgent generating overall situation and recommendations...",
        "caption_summary_unavailable": "Overall summary temporarily unavailable: {error}",
        
        # ── Results Column Headers ─────────────────────────────────────────────
        "col_identity_finds": "### 👤 Identity Findings",
        "col_leak_finds": "### 🛡️ Leak Findings",
        "msg_no_identity_data": "No identity data loaded.",
        "msg_no_leak_data": "No leak data loaded.",
        "label_spear_phishing_risk": "**Spear-Phishing Risk:**",
        "msg_no_profiles_found": "No profiles found.",
        "msg_no_leaks_found": "✅ No known data breaches.",
        "msg_breaches_found": "🚨 **{count} data breach(s)** found!",
        "caption_attack_vector": "⚡ {vector}",
        "caption_no_attack_vector": "⚡ No specific attack vectors found.",
        "expander_raw_data": "Show Raw Data",
        
        # ── Results / Scores ───────────────────────────────────────────────────
        "label_threat_score": "**Threat Score**",
        "label_vulnerability_score": "**Vulnerability Score**",
        "label_risk_level": "**Overall Assessment**",
        "risk_critical": "Immediate action required!",
        "risk_high": "Elevated risk — caution advised.",
        "risk_medium": "Moderate risk — stay alert.",
        "risk_low": "No acute risk detected.",
        
        # ── Results / Expander Labels ──────────────────────────────────────────
        "expander_summary": "📄 Summary",
        "expander_recommendations": "🛡️ Recommendations",
        "expander_indicators": "💡 Main Risk Indicators",
        "header_indicators": "#### 💡 Main Risk Indicators",
        "header_prevention": "🚫 **Must Avoid**",
        "header_incident": "🔥 **If Already Clicked**",
        "expander_agent_findings": "#### Agent Findings (Detail)",
        "msg_no_findings": "No detailed findings available.",
        "header_threats": "**🎯 Threats**",
        "header_vulnerabilities": "**🔍 Vulnerabilities / Findings**",
        "msg_no_vulns": "No findings.",
        
        # ── Archive ────────────────────────────────────────────────────────────
        "archive_header": "Archived Finding",
        "archive_info": "ℹ️ You are viewing a historical analysis from the ChromaDB vector database.",
        "archive_unstructured": "The format of this old analysis is unstructured. Showing raw data:",
        "label_raw_data": "Report Raw Data",
        "label_risk_score": "**Risk Score**",
        "label_data_source": "**Data Source**",
        "msg_no_incident_steps": "No specific incident response steps stored.",
        
        # ── Sidebar ────────────────────────────────────────────────────────────
        "sidebar_title": "## 👁️ OSINT-Argus",
        "sidebar_history": "**Recent Analyses (ChromaDB)**",
        "msg_history_error": "Error loading history",
        "msg_no_history": "No analyses in database yet.",
        "caption_agents": "Agents: Input · Orchestrator · Domain · Email · CVE · Phone · File · Identity · Output",
        
        # ── Language Selector ──────────────────────────────────────────────────
        "label_language": "UI Language",
        "lang_english": "English",
        "lang_german": "Deutsch",
        
        # ── Performance ────────────────────────────────────────────────────────
        "caption_performance": "**Performance Metrics per Node:**",
        "caption_pipeline": "AGENT PIPELINE · {elapsed}s",
    },
    
    "de": {
        # ── Page & Header ──────────────────────────────────────────────────────
        "page_title": "OSINT-Argus",
        "header_subtitle": "Multi-Agent Cybersecurity Analyzer",
        
        # ── Tabs ───────────────────────────────────────────────────────────────
        "tab_analyze": "🔍 Analyse-Pipeline",
        "tab_profile": "👤 Profil & Leak-Check",
        
        # ── Input Section ──────────────────────────────────────────────────────
        "input_label": "Input",
        "input_placeholder": (
            "Domain          →  example.com\n"
            "E-Mail-Adresse  →  user@domain.com\n"
            "E-Mail-Inhalt   →  komplette Mail hier reinkopieren\n"
            "Telefonnummer   →  +49 151 12345678\n"
            "Dateipfad/Hash  →  /pfad/zur/datei.pdf"
        ),
        "supported_inputs_title": "**Unterstützte Inputs**",
        "supported_inputs": [
            "🌐 Domain / URL",
            "📧 E-Mail-Adresse",
            "📨 E-Mail-Inhalt",
            "📞 Telefonnummer",
            "📄 Datei / Hash",
            "🔎 Software + Version",
        ],
        
        # ── Buttons ────────────────────────────────────────────────────────────
        "btn_analyze": "🔍 Analysieren",
        "btn_clear": "✕ Leeren",
        "btn_save_profile": "Profil-Änderungen speichern",
        "btn_scan_person": "🔥 Person im Internet aufspüren & prüfen",
        "btn_new_analysis": "🔄 Neue Analyse starten",
        
        # ── Messages ───────────────────────────────────────────────────────────
        "msg_input_required": "Bitte einen Input eingeben.",
        "msg_analysis_complete": "✅ Analyse abgeschlossen in {elapsed}s",
        "msg_pipeline_error": "❌ Pipeline-Fehler: {type}: {error}",
        "msg_profile_saved": "Profil erfolgreich in ChromaDB aktualisiert!",
        "msg_profile_empty": "❌ Bitte trage zuerst einen Namen, eine E-Mail-Adresse oder einen Nick/Gamer-Tag im Profil ein.",
        
        # ── Leak Tab / Profile ─────────────────────────────────────────────────
        "profile_header": "👤 Digitale Identitäts-Akte (Lernendes Profil)",
        "profile_description": (
            "Dieses Profil schärft sich automatisch aus deinen eingegebenen Texten (Schritt 2). "
            "Du kannst die Daten hier jederzeit korrigieren oder ergänzen."
        ),
        "field_firstname": "Vorname",
        "field_lastname": "Nachname",
        "field_email": "E-Mail-Adresse (für Leak-Checks)",
        "field_phone": "Telefonnummer",
        "field_nicks": "Nicks / Spitznamen (durch Komma getrennt)",
        "field_gamer_tag": "Gamer Tag / Handle",
        "placeholder_nicks": "z.B. Max, Momo, Gamer123",
        "label_it_competency": "**Erkanntes IT-Kompetenzlevel:**",
        "label_expert_terms": "**Gefundene Fachbegriffe:**",
        "caption_profile_char": "*Profiler-Charakteristik:*",
        
        # ── Leak Tab / OSINT Scan ──────────────────────────────────────────────
        "subheader_osint_scan": "🛡️ On-Demand OSINT Target-Scanning",
        "osint_scan_description": (
            "Triggere den `LeakAgent` (E-Mail) und den `IdentityAgent` (Klarname, Nicks, Gamer-Tags) parallel, "
            "um Exposures und Profile aufzudecken."
        ),
        "spinner_leak_agent": "🕵️ LeakAgent sucht nach Datenlecks für '{email}'...",
        "section_osint_results": "### 🔎 OSINT-Scan Ergebnisse",
        "msg_skipped": "⏭️ Übersprungen: {label} '{target}'",
        "spinner_identity_scan": "🔍 Scan {idx}/{total}: {label} '{target}'...",
        "msg_scan_complete": "✅ {label} ({elapsed}s)",
        "msg_no_results": "⚠️ Keine Ergebnisse für {label} ({elapsed}s)",
        "msg_scan_error": "❌ Fehler bei {label}: {error}",
        "section_combined_report": "## 📊 Kombinierte OSINT-Ermittlungsakte",
        "spinner_summary": "🧠 OutputAgent generiert die Gesamtlage und Handlungsempfehlungen...",
        "caption_summary_unavailable": "Gesamtzusammenfassung temporär nicht verfügbar: {error}",
        
        # ── Results Column Headers ─────────────────────────────────────────────
        "col_identity_finds": "### 👤 Profil-Funde",
        "col_leak_finds": "### 🛡️ Leak-Funde",
        "msg_no_identity_data": "Keine Identitätsdaten geladen.",
        "msg_no_leak_data": "Keine Leak-Daten geladen.",
        "label_spear_phishing_risk": "**Spear-Phishing-Risiko:**",
        "msg_no_profiles_found": "Keine Profile gefunden.",
        "msg_no_leaks_found": "✅ Keine bekannten Datenlecks.",
        "msg_breaches_found": "🚨 **{count} Datenleck(s)** gefunden!",
        "caption_attack_vector": "⚡ {vector}",
        "caption_no_attack_vector": "⚡ Keine spezifischen Angriffsvektoren gefunden.",
        "expander_raw_data": "Rohdaten anzeigen",
        
        # ── Results / Scores ───────────────────────────────────────────────────
        "label_threat_score": "**Bedrohungs-Score**",
        "label_vulnerability_score": "**Schwachstellen-Score**",
        "label_risk_level": "**Gesamteinstufung**",
        "risk_critical": "Sofortiger Handlungsbedarf!",
        "risk_high": "Erhöhtes Risiko — Vorsicht geboten.",
        "risk_medium": "Moderates Risiko — aufmerksam bleiben.",
        "risk_low": "Kein akutes Risiko erkannt.",
        
        # ── Results / Expander Labels ──────────────────────────────────────────
        "expander_summary": "📄 Zusammenfassung",
        "expander_recommendations": "🛡️ Handlungsempfehlungen",
        "expander_indicators": "💡 Haupt-Risikoindikatoren",
        "header_indicators": "#### 💡 Haupt-Risikoindikatoren",
        "header_prevention": "🚫 **Unbedingt vermeiden**",
        "header_incident": "🔥 **Falls bereits geklickt**",
        "expander_agent_findings": "#### Agent-Findings (Detail)",
        "msg_no_findings": "Keine Detail-Findings vorhanden.",
        "header_threats": "**🎯 Bedrohungen**",
        "header_vulnerabilities": "**🔍 Schwachstellen / Befunde**",
        "msg_no_vulns": "Keine Befunde.",
        
        # ── Archive ────────────────────────────────────────────────────────────
        "archive_header": "Archivierter Befund",
        "archive_info": "ℹ️ Sie betrachten eine historische Analyse aus der ChromaDB-Vektordatenbank.",
        "archive_unstructured": "Das Format dieser alten Analyse ist unstrukturiert. Zeige Rohdaten an:",
        "label_raw_data": "Report Rohdaten",
        "label_risk_score": "**Risiko-Score**",
        "label_data_source": "**Datenquelle**",
        "msg_no_incident_steps": "Keine spezifischen Incident-Response-Schritte hinterlegt.",
        
        # ── Sidebar ────────────────────────────────────────────────────────────
        "sidebar_title": "## 👁️ OSINT-Argus",
        "sidebar_history": "**Letzte Analysen (ChromaDB)**",
        "msg_history_error": "Fehler beim Laden der Historie",
        "msg_no_history": "Noch keine Analysen in der Datenbank vorhanden.",
        "caption_agents": "Agents: Input · Orchestrator · Domain · Email · CVE · Phone · File · Identity · Output",
        
        # ── Language Selector ──────────────────────────────────────────────────
        "label_language": "UI-Sprache",
        "lang_english": "English",
        "lang_german": "Deutsch",
        
        # ── Performance ────────────────────────────────────────────────────────
        "caption_performance": "**Performance-Metriken pro Knoten:**",
        "caption_pipeline": "AGENT PIPELINE · {elapsed}s",
    },
}


def t(key: str, lang: Language = "en", **kwargs) -> str:
    """
    Translate a UI string by key.
    
    Args:
        key: Translation key (e.g., "btn_analyze")
        lang: Language code ("en" or "de"), defaults to "en"
        **kwargs: Format arguments for strings with placeholders
    
    Returns:
        Translated string formatted with provided kwargs
    
    Example:
        t("msg_analysis_complete", lang="en", elapsed=42)
        → "✅ Analysis completed in 42s"
    """
    try:
        text = STRINGS[lang][key]
        return text.format(**kwargs) if kwargs else text
    except KeyError as e:
        # Fallback to English if key not found
        if lang == "de":
            return STRINGS["en"].get(key, f"MISSING_KEY: {key}")
        return f"MISSING_KEY: {key}"


def get_language_options() -> list[tuple[str, str]]:
    """Returns language options for UI selector: [(code, display_name), ...]"""
    return [
        ("en", "English"),
        ("de", "Deutsch"),
    ]
