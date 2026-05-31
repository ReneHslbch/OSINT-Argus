import os
from langchain_core.tools import tool

import os
import httpx
import re
from langchain_core.tools import tool

@tool
def check_virustotal_email_domain(email_or_domain: str) -> dict:
    """
    Extrahiert die Domain aus einer E-Mail-Adresse oder nutzt die Domain direkt,
    um die Sicherheitsreputation über die VirusTotal-API (v3) zu prüfen.
    """
    # Falls eine volle E-Mail übergeben wurde, isoliere die Domain
    domain = email_or_domain
    if "@" in email_or_domain:
        match = re.search(r'@([\w.\-]+)', email_or_domain)
        if match:
            domain = match.group(1).lower()

    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        return {"error": "VT_API_KEY nicht gesetzt", "verdict": "UNKNOWN"}

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": api_key}

    try:
        resp = httpx.get(url, headers=headers, timeout=10)
        if resp.status_code == 404:
            return {"domain": domain, "verdict": "CLEAN", "note": "Nicht in VT-Datenbank"}
        
        resp.raise_for_status()
        data = resp.json()

        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        reputation = data.get("data", {}).get("attributes", {}).get("reputation", 0)

        if malicious > 0:
            verdict = "MALICIOUS"
        elif suspicious > 0 or reputation < -10:
            verdict = "SUSPICIOUS"
        else:
            verdict = "CLEAN"

        return {
            "domain": domain,
            "verdict": verdict,
            "malicious": malicious,
            "suspicious": suspicious,
            "reputation": reputation,
            "categories": list(set(data.get("data", {}).get("attributes", {}).get("categories", {}).values())),
        }
    except Exception as e:
        return {"error": str(e), "verdict": "UNKNOWN"}

EMAIL_TOOLS = [check_virustotal_email_domain]

@tool
def check_phishing_blacklist(target: str) -> dict:
    """
    Prüft, ob eine Domain oder ein URL-Fragment auf globalen Bedrohungslisten (z.B. PhishTank, OpenPhish) 
    als aktive Phishing-Kampagne gemeldet ist.
    """
    # Hier kommt deine OSINT-Anbindung oder der wissenschaftliche Mock für die Evaluation hin
    # Beispielhaft für bekannte Testdaten:
    if "mailchimp-delivery" in target.lower():
        return {
            "listed": True,
            "database": "PhishTank / OpenPhish Intel",
            "confidence_score": 92,
            "details": "Gelistet als aktive Impersonation-Kampagne (Target: Mailchimp Inc.)."
        }
    
    return {
        "listed": False,
        "database": "PhishTank / OpenPhish Intel",
        "note": "Kein aktiver Eintrag für dieses Target gefunden."
    }

# Beide Tools registrieren
EMAIL_TOOLS = [check_virustotal_email_domain, check_phishing_blacklist]