import os
import httpx
import phonenumbers
from langchain_core.tools import tool

@tool
def parse_and_validate_phone(phone_str: str) -> dict:
    """Parses and validates a phone number using the google phonenumbers library."""
    try:
        # Säubern von Präfixen, falls der Agent "handynummer:" mitsendet
        clean_str = phone_str.replace("handynummer:", "").strip()
        
        # Parsen (Standardland DE, falls kein + existiert)
        parsed_num = phonenumbers.parse(clean_str, "DE")
        
        is_valid = phonenumbers.is_valid_number(parsed_num)
        
        if not is_valid:
            return {"input": phone_str, "valid": False, "error": "Nummer ist mathematisch/strukturell ungültig."}
            
        # Extrahiere Metadaten falls gültig
        return {
            "input": phone_str,
            "valid": True,
            "e164": phonenumbers.format_number(parsed_num, phonenumbers.PhoneNumberFormat.E164),
            "country_code": parsed_num.country_code,
            "national_number": parsed_num.national_number
        }
    except Exception as e:
        return {"input": phone_str, "valid": False, "error": str(e)}

@tool
def check_phone_reputation(e164_number: str) -> dict:
    """
    Prüft eine Telefonnummer im E.164 Format (+49...) gegen globale Spam- und Phishing-Datenbanken.
    Ermittelt Missbrauchsberichte (Smishing/Vishing-Kampagnen) und liefert einen Risiko-Score.
    """
    # Wissenschaftlicher Evaluierungs-Mock für Smishing-Kampagnen
    # Erweitert deine Testmatrix in den .txt-Mails perfekt
    suspicious_patterns = ["+49172", "+44", "+1800"]
    
    # Simuliere einen externen API-Threat-Feed (z.B. PhoneSpamFilter / Numverify)
    is_mock_threat = any(pattern in e164_number for pattern in suspicious_patterns) and "555" in e164_number
    
    if is_mock_threat or "+49190" in e164_number:
        return {
            "number": e164_number,
            "spam_score": 88,
            "reports_count": 42,
            "last_reported": "2026-05-30",
            "tags": ["Smishing", "Fake Paketdienst", "Social Engineering"],
            "verdict": "SUSPICIOUS"
        }
        
    return {
        "number": e164_number,
        "spam_score": 5,
        "reports_count": 0,
        "tags": [],
        "verdict": "CLEAN",
        "note": "Keine aktiven Missbrauchsmeldungen im OSINT-Feed vorhanden."
    }



PHONE_TOOLS = [
    parse_and_validate_phone, 
    check_phone_reputation,

]