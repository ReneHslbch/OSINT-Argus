# Regressions-Testset für Risk-Score-Kalibrierung

## Zweck
Dieses Eval-Set dient dazu, Prompt-Änderungen im `OutputAgent` gegen erwartete Risk-Levels zu testen, bevor sie in Produktion gehen. Ziel ist die Vermeidung von Alarm-Müdigkeit durch kalibrierte Score-Einstufungen.

## Test-Dateien und erwartete Results

### 1. `crit_mail_test.txt` — Erwartet: **CRITICAL**
**Typ:** Aktiver Phishing-Angriff  
**Begründung:**
- Typosquatting auf `deutsche-bank.de` (`deutsche-bank-verify.com`)
- Zweite Phishing-Domain im selben Mail (`db-secure-login.net`)
- Dringlichkeits-Erpressung ("SOFORTiger Handlungsbedarf")
- Reply-To weicht stark ab (`no-reply@db-security-alert.ru`)
- Erwartete Signale: [email] + [domain] + [domain] → 3 unabhängige Phishing-Signale

**Erwartete Scores:**
- threat_score: 85-95
- vulnerability_score: 30-50
- risk_level: CRITICAL

---

### 2. `email_test.txt` — Erwartet: **HIGH**
**Typ:** Einzelnes starkes Phishing-Signal  
**Begründung:**
- Typosquatting auf `paypal.com` (`paypa1-verify.ru` mit "1" statt "l")
- .ru TLD (verdächtig für Bank-Phishing)
- Dringlichkeits-Erpressung ("innerhalb 24 Stunden")
- Reply-To weicht ab (`support@account-helpdesk.xyz`)
- Erwartete Signale: [email] + [domain] → 2 unabhängige Signale, aber keine URLhaus/Blacklist-Bestätigung

**Erwartete Scores:**
- threat_score: 67-80
- vulnerability_score: 25-40
- risk_level: HIGH (kein CRITICAL ohne URLhaus/Blacklist-Bestätigung)

---

### 3. `low_risk_test.txt` — Erwartet: **MEDIUM**
**Typ:** Konfigurations-Schwachstellen OHNE aktive Bedrohung  
**Begründung:**
- Ungewöhnlich hohes Gehaltsversprechen (8.000€/Monat)
- Generische Ansprache ("Sehr geehrte/r Bewerber/in")
- Reply-To weicht ab (`hr-team@apply-now-jobs.com`)
- Keine aktiven Phishing/Malware-Signale erkennbar
- Erwartete Signale: [email] + [domain] + [domain] → nur Konfigurationsmängel (SPF/DMARC fehlen)

**Erwartete Scores:**
- threat_score: 30-45
- vulnerability_score: 20-35
- risk_level: MEDIUM (keine akute Bedrohung, nur Best-Practice-Mängel)

---

### 4. `legit_mail_test.txt` — Erwartet: **LOW**
**Typ:** Legitime Kommunikation mit kleinen Mängeln  
**Begründung:**
- Legitimer Newsletter-ähnlicher Inhalt
- Keine Dringlichkeits-Erpressung
- Keine Typosquatting-Domains
- Reply-To stimmt mit From überein
- Erwartete Signale: Nur kleiner Konfigurationsmangel (fehlender DMARC möglich)

**Erwartete Scores:**
- threat_score: 0-15
- vulnerability_score: 5-20
- risk_level: LOW

---

### 5. `phone_test.txt` — Erwartet: **MEDIUM**
**Typ:** Gemischte Kommunikation mit Telefonnummer-Risiko  
**Begründung:**
- Hauptinhalt ist legitimer Newsletter (Mailchimp)
- ABER: Sicherheitswarnung mit Rufnummer (+49 172 555 4321) eingebaut
- Typische Social-Engineering-Taktik ("ungewöhnliche Anmeldeversuche")
- Erwartete Signale: [email] (legit) + [phone] (verdächtige Nummer in Warnung)

**Erwartete Scores:**
- threat_score: 35-50
- vulnerability_score: 10-25
- risk_level: MEDIUM (gemischtes Signal, keine klare böswillige Absicht)

---

### 6. `demo_test.txt` — Erwartet: **VARIIERT**
**Typ:** Demo-Testmail (Inhalt prüfen)  
**Begründung:** Inhalt der Datei muss separat analysiert werden.

---

## Ausführen der Regressionstests

### Manuelles Testen
```bash
# Für jede Test-Mail den OutputAgent durchlaufen lassen
python -c "
from app.agents.output_agent import OutputAgent
from app.state import ArgusState
from app.agents.email_agent import EmailAgent
from app.agents.domain_agent import DomainAgent

# Test-Mail laden
with open('app/test_mails/crit_mail_test.txt', 'r') as f:
    mail_content = f.read()

# State initialisieren
state: ArgusState = {
    'user_input': mail_content,
    'input_type': 'email',
    'to_scan': [mail_content],
    'scanned': [],
    'findings': [],
    'current_check': None,
    'next_agent': None
}

# Pipeline durchlaufen
state = EmailAgent().run(state)
state = DomainAgent().run(state)
state = OutputAgent().run(state)

# Resultat prüfen
print(f\"Risk Level: {state['risk_level']}\")
print(f\"Score: {state['risk_score']}\")
"
```

### Automatisiertes Eval (zukünftig)
Ein Skript sollte alle Test-Mails durchlaufen und die Results gegen die erwarteten Werte vergleichen:
```python
expected_results = {
    "crit_mail_test.txt": {"risk_level": "CRITICAL", "min_score": 85},
    "email_test.txt": {"risk_level": "HIGH", "min_score": 67},
    "low_risk_test.txt": {"risk_level": "MEDIUM", "min_score": 34},
    "legit_mail_test.txt": {"risk_level": "LOW", "max_score": 33},
    "phone_test.txt": {"risk_level": "MEDIUM", "min_score": 34},
}
```

## Prompt-Änderungen validieren

Bevor Prompt-Änderungen deployed werden:
1. Alle 5 Test-Mails durchlaufen lassen
2. Ergebnisse gegen `expected_results` vergleichen
3. Bei Abweichungen: Prompt anpassen und erneut testen
4. Keine Regression zulassen (z.B. darf `legit_mail_test.txt` nicht plötzlich HIGH sein)

## Kalibrierungs-Prinzipien

1. **Korroborations-Regel:** HIGH/CRITICAL erfordert 2+ unabhängige Signale
2. **Fehler-Neutralität:** Tool-Fehler/Timeouts = 0 Punkte
3. **Deckelung:** SPF/DMARC-Alone = maximal MEDIUM/HIGH, nie CRITICAL
4. **Tendenz bei Unsicherheit:** MEDIUM statt HIGH (Alarm-Müdigkeit vermeiden)
