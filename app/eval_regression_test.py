"""
Automatisiertes Eval-Skript für Risk-Score-Kalibrierung.

Lädt alle Test-Mails aus app/test_mails/, führt die Analyse-Pipeline durch
und vergleicht die Ergebnisse mit den erwarteten Risk-Levels.

Aufruf:
    python -m app.eval_regression_test
"""

import os
import sys
import re
from pathlib import Path

# Projekt-Root zum Path hinzufügen
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from typing import Dict, List, Tuple
from app.agents.output_agent import OutputAgent, _format_findings_for_llm
from app.state import ArgusState
from app.models.findings import Findings
from app.models.agent_type import AgentType


# ─────────────────────────────────────────────────────────────────────────────
# Erwartete Results für das Regressionstest-Set
# ─────────────────────────────────────────────────────────────────────────────

EXPECTED_RESULTS = {
    "crit_mail_test.txt": {
        "risk_level": "CRITICAL",
        "min_score": 85,
        "max_score": 100,
        "description": "Aktiver Phishing-Angriff mit Typosquatting + URLhaus/Blacklist"
    },
    "email_test.txt": {
        "risk_level": "HIGH",
        "min_score": 67,
        "max_score": 84,
        "description": "Einzelnes starkes Phishing-Signal (Typosquatting + .ru)"
    },
    "low_risk_test.txt": {
        "risk_level": "LOW",
        "min_score": 0,
        "max_score": 33,
        "description": "Konfigurations-Schwachstellen (SPF/DMARC) OHNE jegliche Bedrohungsindikatoren"
    },
    "legit_mail_test.txt": {
        "risk_level": "LOW",
        "min_score": 0,
        "max_score": 33,
        "description": "Legitime Kommunikation mit kleinen Mängeln"
    },
    "phone_test.txt": {
        "risk_level": "MEDIUM",
        "min_score": 34,
        "max_score": 66,
        "description": "Gemischte Kommunikation mit Telefonnummer-Risiko (Spam-Score + SMS-Warning)"
    },
}


def extract_domains_from_mail(mail_content: str) -> List[str]:
    """Extrahiert alle Domains aus einer E-Mail (From, Reply-To, URLs)."""
    domains = set()
    
    # From/Reply-To/To-Adressen
    email_pattern = r'[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'
    for match in re.findall(email_pattern, mail_content):
        domains.add(match.lower())
    
    # URLs
    url_pattern = r'https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'
    for match in re.findall(url_pattern, mail_content):
        domains.add(match.lower())
    
    return list(domains)


def create_mock_findings(mail_content: str, domains: List[str]) -> List[Findings]:
    """
    Erstellt simulierte Findings basierend auf Mail-Analyse.
    Dies ersetzt den EmailAgent und DomainAgent für das Eval-Skript.
    """
    findings = []
    
    # EmailAgent-Mock: Analysiert Mail-Inhalt auf Phishing-Muster
    threat_indicators = []
    
    # Dringlichkeits-Erpressung
    if re.search(r'(dringend|sofort|innerhalb.*24.*stunde|kontosperrung|gesperrt)', mail_content.lower()):
        threat_indicators.append("Dringlichkeits-Erpressung erkannt")
    
    # Typosquatting-Erkennung
    known_brands = ['deutsche-bank', 'paypal', 'amazon', 'google', 'microsoft']
    for brand in known_brands:
        if brand.replace('-', '') in mail_content.lower().replace('-', ''):
            if re.search(r'[a-z0-9-]*' + brand.replace('-', '') + r'[a-z0-9-]*\.(com|ru|net|xyz)', mail_content.lower()):
                threat_indicators.append(f"Typosquatting auf {brand} möglich")
                break
    
    # Reply-To Mismatch
    from_match = re.search(r'From:\s*([^\n]+)', mail_content, re.IGNORECASE)
    reply_to_match = re.search(r'Reply-To:\s*([^\n]+)', mail_content, re.IGNORECASE)
    if from_match and reply_to_match:
        from_domain = re.search(r'@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', from_match.group(1))
        reply_domain = re.search(r'@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', reply_to_match.group(1))
        if from_domain and reply_domain and from_domain.group(1) != reply_domain.group(1):
            threat_indicators.append("Reply-To weicht von From ab")
    
    # Suspicious TLD
    if re.search(r'\.(ru|xyz|top|tk)\b', mail_content.lower()):
        threat_indicators.append("Verdächtige TLD (.ru/.xyz/.top) in Domain")
    
    findings.append(Findings(
        agent=AgentType.EMAIL,
        input="E-Mail-Inhalt",
        threat_sum=threat_indicators if threat_indicators else ["Keine aktiven Phishing-Indikatoren"],
        vulnerability_sum=[]
    ))
    
    # DomainAgent-Mock: Prüft extrahierte Domains
    for domain in domains:
        domain_threats = []
        domain_vulns = []
        
        # Suspicious TLD
        if domain.endswith(('.ru', '.xyz', '.top', '.tk')):
            domain_threats.append(f"Verdächtige TLD: {domain}")
        
        # Typosquatting
        known_brands = ['deutschebank', 'deutsche-bank', 'paypal', 'amazon']
        for brand in known_brands:
            if brand.replace('-', '') in domain.replace('-', '') and brand not in domain:
                domain_threats.append(f"Typosquatting auf {brand}")
                break
        
        # Neue Domain (simuliert - immer als neu markieren für Test)
        domain_vulns.append("Domain neu registriert (<30 Tage)")
        domain_vulns.append("Kein SPF-Record")
        domain_vulns.append("Kein DMARC-Record")
        
        findings.append(Findings(
            agent=AgentType.DOMAIN,
            input=domain,
            threat_sum=domain_threats if domain_threats else ["Keine Bedrohungsindikatoren"],
            vulnerability_sum=domain_vulns
        ))
    
    return findings


def load_test_mail(filename: str) -> str:
    """Lädt eine Test-Mail aus app/test_mails/."""
    mail_path = PROJECT_ROOT / "app" / "test_mails" / filename
    if not mail_path.exists():
        raise FileNotFoundError(f"Test-Mail nicht gefunden: {mail_path}")
    return mail_path.read_text(encoding="utf-8")


def run_analysis_pipeline(mail_content: str) -> Tuple[str, int]:
    """
    Führt die Analyse-Pipeline für eine Mail durch und gibt (risk_level, risk_score) zurück.
    
    Vereinfachte Pipeline: Mock-Analyse -> OutputAgent
    (EmailAgent/DomainAgent werden durch Heuristik ersetzt, OutputAgent nutzt kalibrierten Prompt)
    """
    # Domains extrahieren
    domains = extract_domains_from_mail(mail_content)
    
    # Mock-Findings erstellen
    findings = create_mock_findings(mail_content, domains)
    
    # State initialisieren
    state: ArgusState = {
        "user_input": mail_content,
        "input_type": "email",
        "to_scan": [],
        "scanned": [],
        "findings": findings,
        "current_check": None,
        "next_agent": None,
        "risk_level": None,
        "risk_score": None,
        "summary": None,
        "action_advice": None,
        "memory_context": "",
        "scanned": [],
    }
    
    try:
        # OutputAgent ausfuhren (erstelt Report basierend auf kalibriertem Prompt)
        state = OutputAgent().run(state)
        
        return state.get("risk_level", "UNKNOWN"), state.get("risk_score", 0)
        
    except Exception as e:
        print(f"  [WARN] Pipeline-Fehler: {e}")
        return "ERROR", 0


def evaluate_result(
    expected: Dict,
    actual_level: str,
    actual_score: int
) -> Tuple[bool, str]:
    """
    Vergleicht erwartete vs. tatsächliche Results.
    Gibt (passed, message) zurück.
    """
    # Risk-Level Check
    if actual_level != expected["risk_level"]:
        return False, f"Level mismatch: expected {expected['risk_level']}, got {actual_level}"
    
    # Score Range Check
    if not (expected["min_score"] <= actual_score <= expected["max_score"]):
        return False, f"Score out of range: {actual_score} (expected {expected['min_score']}-{expected['max_score']})"
    
    return True, f"✓ Level: {actual_level}, Score: {actual_score}"


def run_regression_tests(verbose: bool = True) -> Dict[str, bool]:
    """
    Führt alle Regressionstests durch.
    
    Args:
        verbose: Wenn True, wird detaillierter Output in die Konsole geschrieben.
    
    Returns:
        Dict mit Test-Namen als Key und True/False als Value.
    """
    results: Dict[str, bool] = {}
    test_mails = list(EXPECTED_RESULTS.keys())
    
    if verbose:
        print("\n" + "=" * 70)
        print("  OSINT-ARGUS REGRESSIONSTEST-SUITE")
        print("=" * 70 + "\n")
    
    for test_name in test_mails:
        expected = EXPECTED_RESULTS[test_name]
        
        if verbose:
            print(f"Test: {test_name}")
            print(f"   Erwartet: {expected['description']}")
            print(f"   Ziel-Level: {expected['risk_level']}, Score: {expected['min_score']}-{expected['max_score']}")
        
        try:
            # Mail laden
            mail_content = load_test_mail(test_name)
            
            # Pipeline durchlaufen
            actual_level, actual_score = run_analysis_pipeline(mail_content)
            
            # Ergebnis evaluieren
            passed, message = evaluate_result(expected, actual_level, actual_score)
            results[test_name] = passed
            
            if verbose:
                status_icon = "[PASS]" if passed else "[FAIL]"
                print(f"   {status_icon} {message}\n")
                
        except Exception as e:
            results[test_name] = False
            if verbose:
                print(f"   [ERROR] {e}\n")
    
    if verbose:
        # Summary
        passed_count = sum(1 for v in results.values() if v)
        total_count = len(results)
        
        print("=" * 70)
        print(f"  SUMMARY: {passed_count}/{total_count} Tests bestanden")
        print("=" * 70)
        
        if passed_count < total_count:
            print("\n[FALLENDE] Folgende Tests sind fehlgeschlagen:")
            for test_name, passed in results.items():
                if not passed:
                    print(f"   - {test_name}")
            print()
        else:
            print("\n[OK] Alle Tests bestanden! Prompt-Aenderungen sind sicher.\n")
    
    return results


def main():
    """Entry-Point für das Eval-Skript."""
    run_regression_tests(verbose=True)


if __name__ == "__main__":
    main()
