import re
import os
import httpx
from urllib.parse import urlparse
from langchain_core.tools import tool


# ── URL-Extraktion ──────────────────────────────────────────────────────────
URL_PATTERN = re.compile(
    r'https?://[^\s<>"\')\]]+',
    re.IGNORECASE
)

def extract_urls(text: str) -> list[str]:
    """Alle URLs aus einem Text extrahieren."""
    return list(set(URL_PATTERN.findall(text)))


def extract_domain_from_url(url: str) -> str | None:
    """Domain aus einer URL extrahieren (ohne www.)."""
    try:
        host = urlparse(url).netloc
        return host.lstrip("www.") if host else None
    except Exception:
        return None


# ── E-Mail-Header-Parsing ───────────────────────────────────────────────────
def parse_email_headers(email_text: str) -> dict:
    """
    Extrahiert From, To, Subject, Reply-To, Date aus einem Raw-Email-Text.
    Funktioniert mit vollständigen Emails (mit Headers) und reinen Body-Texten.
    """
    headers = {}
    for field in ["From", "To", "Subject", "Reply-To", "Date"]:
        pattern = re.compile(rf"^{field}:\s*(.+)$", re.MULTILINE | re.IGNORECASE)
        match = pattern.search(email_text)
        headers[field.lower().replace("-", "_")] = match.group(1).strip() if match else None
    return headers


def extract_sender_domain(from_header: str | None) -> str | None:
    """
    Sender-Domain aus einem From-Header extrahieren.
    Handles: 'Name <user@domain.com>' und 'user@domain.com'
    """
    if not from_header:
        return None
    match = re.search(r'@([\w.\-]+)', from_header)
    return match.group(1).lower() if match else None


def check_reply_to_mismatch(headers: dict) -> dict:
    """
    Prüft ob Reply-To von der Absender-Domain abweicht —
    klassischer Phishing-Indikator.
    """
    from_domain    = extract_sender_domain(headers.get("from"))
    reply_to       = headers.get("reply_to")
    reply_to_domain = extract_sender_domain(reply_to) if reply_to else None

    mismatch = (
        reply_to_domain is not None
        and from_domain is not None
        and reply_to_domain != from_domain
    )
    return {
        "from_domain":      from_domain,
        "reply_to_domain":  reply_to_domain,
        "mismatch_detected": mismatch,
    }


# ── VirusTotal Domain-Check ─────────────────────────────────────────────────
@tool
def check_virustotal_domain(domain: str) -> dict:
    """
    Prüft eine Domain gegen die VirusTotal-API (v3).
    Gibt Reputationsscore, Kategorie und Erkennungsrate zurück.
    Benötigt VT_API_KEY in der .env.
    """
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        return {"error": "VT_API_KEY nicht gesetzt", "verdict": "UNKNOWN"}

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": api_key}

    try:
        resp = httpx.get(url, headers=headers, timeout=10)

        if resp.status_code == 404:
            return {"domain": domain, "verdict": "UNKNOWN", "note": "Nicht in VT-Datenbank"}
        if resp.status_code == 401:
            return {"error": "VT API-Key ungültig", "verdict": "UNKNOWN"}
        if resp.status_code == 429:
            return {"error": "VT Rate Limit erreicht", "verdict": "UNKNOWN"}

        resp.raise_for_status()
        data = resp.json()

        stats = (
            data.get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
        )
        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total      = sum(stats.values()) or 1
        reputation = data.get("data", {}).get("attributes", {}).get("reputation", 0)
        categories = data.get("data", {}).get("attributes", {}).get("categories", {})

        if malicious > 0:
            verdict = "MALICIOUS"
        elif suspicious > 0:
            verdict = "SUSPICIOUS"
        elif reputation < -10:
            verdict = "SUSPICIOUS"
        else:
            verdict = "CLEAN"

        return {
            "domain":      domain,
            "verdict":     verdict,
            "malicious":   malicious,
            "suspicious":  suspicious,
            "total_scans": total,
            "reputation":  reputation,
            "categories":  list(set(categories.values())),
        }

    except httpx.RequestError as e:
        return {"error": str(e), "verdict": "UNKNOWN"}