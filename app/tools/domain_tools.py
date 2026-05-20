import ssl
import socket
import dns.resolver
import httpx
import certifi
from datetime import datetime, timezone
from langchain.tools import tool

@tool
def run_ssl_check(domain: str) -> dict:
    """
    Prüft das SSL/TLS-Zertifikat einer Domain.
    Erkennt: abgelaufene Zertifikate, selbst-signierte Certs, bald ablaufende Certs.
    Gibt Aussteller, Ablaufdatum und alle SANs zurück.
    """
    try:
        ctx = ssl.create_default_context(cafile=certifi.where())
        
        with socket.create_connection((domain, 443), timeout=8) as conn:
            with ctx.wrap_socket(conn, server_hostname=domain) as sock:
                cert = sock.getpeercert()

        # FIX: Robustes Parsing über Unix-Timestamp statt fehleranfälligem String-Matching
        if not cert or "notAfter" not in cert:
            raise ValueError("Keine Zertifikatsdaten empfangen.")
            
        expiry_timestamp = ssl.cert_time_to_seconds(cert["notAfter"])
        expiry = datetime.fromtimestamp(expiry_timestamp, tz=timezone.utc)
        now = datetime.now(timezone.utc)
        days_left = (expiry - now).days

        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))
        sans = [
            name for typ, name in cert.get("subjectAltName", []) if typ == "DNS"
        ]

        issues = []
        if days_left < 0:
            issues.append(f"Zertifikat seit {abs(days_left)} Tagen ABGELAUFEN")
        elif days_left < 14:
            issues.append(f"Zertifikat läuft in {days_left} Tagen ab — KRITISCH")
        elif days_left < 30:
            issues.append(f"Zertifikat läuft in {days_left} Tagen ab — Warnung")

        self_signed = issuer.get("organizationName") == subject.get("organizationName") if issuer and subject else False
        if self_signed:
            issues.append("Selbst-signiertes Zertifikat — Browser zeigen Warnung")

        return {
            "valid": True,
            "expires": cert["notAfter"],
            "days_until_expiry": days_left,
            "issuer": issuer.get("organizationName", "Unbekannt"),
            "common_name": subject.get("commonName"),
            "san_count": len(sans),
            "san_entries": sans[:10],
            "self_signed": self_signed,
            "issues": issues,
            "verdict": "CRITICAL" if days_left < 14 or self_signed else
                       "WARNING" if days_left < 30 else "OK",
        }

    except ssl.SSLCertVerificationError as e:
        try:
            bad_ctx = ssl._create_unverified_context()
            with socket.create_connection((domain, 443), timeout=5) as bad_conn:
                with bad_ctx.wrap_socket(bad_conn, server_hostname=domain) as bad_sock:
                    unverified_cert = bad_sock.getpeercert(binary_form=False)
                    bad_issuer = dict(x[0] for x in unverified_cert.get("issuer", []))
                    issuer_org = bad_issuer.get("organizationName", "Unbekannt")
                    
                    if "Myra" in issuer_org or "Cloudflare" in issuer_org:
                        return {
                            "valid": False,
                            "issues": [f"Anfrage wurde von der WAF ({issuer_org}) blockiert (TLS-Interception)."],
                            "verdict": "WARNING"
                        }
                    
                    return {
                        "valid": False,
                        "issues": [f"Zertifikat nicht vertrauenswürdig. Aussteller: {issuer_org}"],
                        "verdict": "CRITICAL"
                    }
        except Exception:
            return {
                "valid": False,
                "issues": ["TLS-Handshake fehlgeschlagen oder von einer Firewall/WAF abgebrochen."],
                "verdict": "WARNING"
            }
            
    except (ConnectionRefusedError, socket.timeout):
        return {
            "valid": False,
            "issues": ["Port 443 nicht erreichbar oder Timeout — kein HTTPS"],
            "verdict": "CRITICAL",
        }
    except Exception as e:
        return {"valid": False, "issues": [str(e)], "verdict": "UNKNOWN"}

@tool
def run_spf_dmarc_check(domain: str) -> dict:
    """
    Prüft ob SPF, DMARC und DKIM korrekt konfiguriert sind.
    Fehlende Records bedeuten: E-Mail-Spoofing auf diese Domain ist möglich.
    Kritisch für den Exposure-Check bei eigenen Domains.
    """

    def query_txt(name: str) -> list[str]:
        try:
            answers = dns.resolver.resolve(name, "TXT", lifetime=8)
            return [r.to_text().strip('"') for r in answers]
        except Exception:
            return []

    # SPF
    spf_records = [r for r in query_txt(domain) if r.startswith("v=spf1")]
    spf_ok = len(spf_records) == 1
    spf_issues = []
    if len(spf_records) == 0:
        spf_issues.append("Kein SPF-Record — Spoofing möglich")
    elif len(spf_records) > 1:
        spf_issues.append("Mehrere SPF-Records — ungültige Konfiguration")
    elif "-all" not in spf_records[0] and "~all" not in spf_records[0]:
        spf_issues.append("SPF ohne -all/~all — unzureichend")

    # DMARC
    dmarc_records = [r for r in query_txt(f"_dmarc.{domain}") if "v=DMARC1" in r]
    dmarc_ok = len(dmarc_records) == 1
    dmarc_policy = None
    if dmarc_records:
        for part in dmarc_records[0].split(";"):
            if part.strip().startswith("p="):
                dmarc_policy = part.strip()[2:]
    dmarc_issues = []
    if not dmarc_ok:
        dmarc_issues.append("Kein DMARC-Record — keine Spoofing-Richtlinie")
    elif dmarc_policy == "none":
        dmarc_issues.append("DMARC policy=none — nur Monitoring, kein Schutz")

    # DKIM (gängige Selektoren prüfen)
    dkim_found = []
    for selector in ["default", "google", "mail", "k1", "dkim", "s1", "s2"]:
        records = query_txt(f"{selector}._domainkey.{domain}")
        if records:
            dkim_found.append(selector)

    all_issues = spf_issues + dmarc_issues
    if not dkim_found:
        all_issues.append("Kein DKIM-Record gefunden — E-Mail-Authentizität unprüfbar")

    return {
        "spf": {
            "configured": spf_ok,
            "record": spf_records[0] if spf_records else None,
            "issues": spf_issues,
        },
        "dmarc": {
            "configured": dmarc_ok,
            "policy": dmarc_policy,
            "record": dmarc_records[0] if dmarc_records else None,
            "issues": dmarc_issues,
        },
        "dkim": {
            "selectors_found": dkim_found,
            "configured": len(dkim_found) > 0,
        },
        "email_spoofing_possible": not (spf_ok and dmarc_ok),
        "all_issues": all_issues,
        "verdict": "EXPOSED" if all_issues else "SECURE",
    }


@tool
def run_urlhaus(domain: str) -> dict:
    """
    Prüft eine Domain gegen die URLhaus Malware-Datenbank von abuse.ch.
    Kein API-Key nötig. Gibt zurück ob die Domain aktive Malware verteilt.
    Wichtigstes Tool für Threat Detection im DomainAgent.
    """
    try:
        # Die WAF von abuse.ch ist extrem strikt. Wir setzen die Header
        # so nativ und unauffällig wie möglich auf Standard-Form-Inhalte.
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) MultiAgent-OSINT-Argus/1.0",
            "Accept": "application/json",
        }
        
        # Der Host-Lookup verlangt zwingend x-www-form-urlencoded Daten.
        # Bei httpx erzwingen wir das, indem wir 'data=' verwenden und sicherstellen,
        # dass keine verschachtelten Objekte übergeben werden.
        payload = {"host": domain.strip().lower()}
        
        # Isolation des Clients, um Wechselwirkungen mit anderen Tools zu vermeiden
        with httpx.Client(headers=headers, follow_redirects=True) as client:
            resp = client.post(
                "https://urlhaus-api.abuse.ch/v1/host/",
                data=payload,
                timeout=15.0, # Etwas mehr Puffer für die API-Response
            )
        
        # Falls die WAF uns mit 401/403 aussperrt oder ein 429 (Rate Limit) kommt,
        # fangen wir das hier dediziert ab.
        resp.raise_for_status()
        data = resp.json()

        status = data.get("query_status", "not_found")
        urls = data.get("urls") or []

        # Extraktion der Malware-Familien (Tags)
        malware_families = list({
            tag
            for u in urls
            for tag in (u.get("tags") or [])
            if tag
        })

        threat_found = status == "is_host"

        return {
            "threat_found": threat_found,
            "query_status": status,
            "active_malware_urls": sum(
                1 for u in urls if u.get("url_status") == "online"
            ),
            "total_malware_urls": len(urls),
            "malware_families": malware_families,
            "blacklisted": data.get("blacklists", {}),
            "verdict": "MALICIOUS" if threat_found else "CLEAN",
        }

    except httpx.HTTPStatusError as http_err:
        # Hier fangen wir den 401er oder 429er ab und geben dem Agenten
        # eine klare Rückmeldung, anstatt das Framework crashen zu lassen.
        code = http_err.response.status_code
        error_msg = f"API-Blockade (HTTP {code})"
        if code == 401:
            error_msg = "HTTP 401: Unauthorized (WAF-Block oder Header-Fehler bei abuse.ch)"
        elif code == 429:
            error_msg = "HTTP 429: Rate Limit überschritten (Fair Use Principle)"
            
        return {
            "error": error_msg,
            "threat_found": False,
            "verdict": "UNKNOWN",
            "raw_response": http_err.response.text[:200]
        }
    except Exception as e:
        return {
            "error": f"Unerwarteter Fehler: {str(e)}", 
            "threat_found": False, 
            "verdict": "UNKNOWN"
        }
    
@tool
def run_crtsh(domain: str) -> dict:
    """
    Findet alle Subdomains einer Domain via Certificate Transparency (crt.sh).
    Nützlich um die Angriffsfläche einer Domain zu kartieren.
    Gibt Subdomain-Liste und Zertifikat-Anzahl zurück.
    """
    try:
        # FIX: Nur direkte Subdomains suchen, um DB-Overload bei Groß-Domains zu verhindern
        # Zudem setzen wir einen strengen Timeout
        resp = httpx.get(
            f"https://crt.sh/?q={domain}&output=json",
            timeout=10,
            headers={"Accept": "application/json"},
        )
        resp.raise_for_status()
        
        # Manchmal liefert crt.sh leeren Content zurück, wenn nichts gefunden wurde
        if not resp.text.strip():
            return {"subdomain_count": 0, "subdomains": [], "cert_count": 0}
            
        certs = resp.json()

        # FIX: Auf die ersten 100 Zertifikate kappen, um Speicher-Overhead zu vermeiden
        subdomains = sorted({
            entry["name_value"].lower().strip()
            for entry in certs[:100]
            if "*" not in entry["name_value"]
            and entry["name_value"].endswith(domain)
        })

        return {
            "subdomain_count": len(subdomains),
            "subdomains": subdomains[:20],  # Dem Agenten reichen die Top 20 vollkommen
            "cert_count": len(certs),
            "exposure_note": (
                "Hohe Subdomain-Anzahl erhöht Angriffsfläche"
                if len(subdomains) > 15
                else "Normale Subdomain-Anzahl"
            ),
        }
    except Exception as e:
        return {"error": f"crt.sh temporär nicht erreichbar oder überlastet: {str(e)}", "subdomain_count": 0, "subdomains": []}

