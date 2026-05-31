import ssl
import socket
import dns.resolver
import httpx
import certifi
from datetime import datetime, timezone
from langchain.tools import tool
import whois

# Erweitert um CNAME und TXT für die Erkennung von Schatten-IT und Subdomain-Takeovers
RECORD_TYPES = ["A", "MX", "NS", "CNAME", "TXT"]

@tool
def run_whois(domain: str) -> dict:
    """
    Run a WHOIS lookup on a given domain to find registration details.
    Hilft beim Erkennen von Domain-Alter (Phishing-Indikator) und Registrar-Daten.
    """
    try:
        data = whois.whois(domain)

        # Normalisierung, da WHOIS-Daten oft Listen oder Einzelwerte liefern
        def parse_date(date_val):
            if isinstance(date_val, list):
                return str(date_val[0])
            return str(date_val)

        return {
            "domain": domain,
            "registrar": data.registrar,
            "creation_date": parse_date(data.get("creation_date")),
            "expiration_date": parse_date(data.get("expiration_date")),
            "name_servers": data.name_servers if isinstance(data.name_servers, list) else [data.name_servers] if data.name_servers else [],
        }
    except Exception as e:
        return {
            "domain": domain,
            "error": f"WHOIS-Abfrage fehlgeschlagen: {str(e)}"
        }


@tool
def run_dns_lookup(domain: str) -> dict:
    """
    Perform a DNS lookup to retrieve A, MX, NS, CNAME, and TXT records.
    Wichtig für die Analyse von Mail-Sicherheit (SPF/DMARC) und Fehlkonfigurationen (CNAME-Verwaisung).
    """
    results = {}

    for record_type in RECORD_TYPES:
        try:
            # Expliziter Timeout für DNS-Anfragen, um Hänger im Graphen zu vermeiden
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5.0
            resolver.lifetime = 5.0
            
            answers = resolver.resolve(domain, record_type)
            results[record_type] = [str(r) for r in answers]
        except Exception:
            results[record_type] = []

    return results


@tool
def run_ssl_check(domain: str) -> dict:
    """
    Prüft das SSL/TLS-Zertifikat einer Domain über Port 443.
    Erkennt abgelaufene Zertifikate, selbst-signierte Certs und bald ablaufende Certs.
    Gibt Aussteller, Restlaufzeit und SANs zurück.
    """
    try:
        ctx = ssl.create_default_context(cafile=certifi.where())
        
        with socket.create_connection((domain, 443), timeout=8) as conn:
            with ctx.wrap_socket(conn, server_hostname=domain) as sock:
                cert = sock.getpeercert()

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
            "verdict": "CRITICAL" if days_left < 14 or self_signed else "WARNING" if days_left < 30 else "OK",
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
            "issues": ["Port 443 nicht erreichbar oder Timeout — kein HTTPS aktiv"],
            "verdict": "CRITICAL",
        }
    except Exception as e:
        return {"valid": False, "issues": [str(e)], "verdict": "UNKNOWN"}


@tool
def run_spf_dmarc_check(domain: str) -> dict:
    """
    Prüft ob SPF, DMARC und DKIM korrekt konfiguriert sind.
    Fehlende Records bedeuten: E-Mail-Spoofing auf diese Domain ist möglich.
    Kritisch für den Exposure-Check bei Phishing-Abwehr.
    """
    def query_txt(name: str) -> list[str]:
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 4.0
            resolver.lifetime = 4.0
            answers = resolver.resolve(name, "TXT")
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
        spf_issues.append("SPF ohne -all/~all Quantor — unzureichender Schutz")

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
        dmarc_issues.append("Kein DMARC-Record — keine Spoofing-Durchsetzungsrichtlinie")
    elif dmarc_policy == "none":
        dmarc_issues.append("DMARC policy=none — nur Monitoring aktiv, kein aktiver Schutz")

    # DKIM (gängige Standard-Selektoren im Web abfragen)
    dkim_found = []
    for selector in ["default", "google", "mail", "k1", "dkim", "s1", "s2"]:
        records = query_txt(f"{selector}._domainkey.{domain}")
        if records:
            dkim_found.append(selector)

    all_issues = spf_issues + dmarc_issues
    if not dkim_found:
        all_issues.append("Kein gängiger DKIM-Record gefunden — E-Mail-Authentizität unprüfbar")

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
        "email_spoofing_possible": not (spf_ok and dmarc_ok and dmarc_policy in ["quarantine", "reject"]),
        "all_issues": all_issues,
        "verdict": "EXPOSED" if all_issues else "SECURE",
    }


@tool
def run_urlhaus(domain: str) -> dict:
    """
    Prüft eine Domain gegen die URLhaus Malware-Datenbank von abuse.ch.
    """
    try:
        # URLhaus erwartet den Host sauber formatiert im POST-Body
        # Wir nutzen ein cleanes Daten-Dictionary und Standard-Header
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        }
        data = {"host": domain.strip().lower()}
        
        with httpx.Client(headers=headers, follow_redirects=True) as client:
            # WICHTIG: abuse.ch erwartet oft einen klassischen Form-Post
            resp = client.post(
                "https://urlhaus-api.abuse.ch/v1/host/",
                data=data,
                timeout=10.0
            )
        
        # Falls abuse.ch uns blockt, fangen wir das hier ab
        if resp.status_code in [401, 403]:
            return {
                "threat_found": False,
                "note": "URLhaus API verweigert Zugriff (WAF-Schutz). Werte als CLEAN/UNKNOWN.",
                "verdict": "UNKNOWN"
            }
            
        resp.raise_for_status()
        res_data = resp.json()

        status = res_data.get("query_status", "not_found")
        urls = res_data.get("urls") or []
        threat_found = status == "is_host"

        return {
            "threat_found": threat_found,
            "query_status": status,
            "active_malware_urls": sum(1 for u in urls if u.get("url_status") == "online"),
            "total_malware_urls": len(urls),
            "verdict": "MALICIOUS" if threat_found else "CLEAN",
        }
    except Exception as e:
        return {"threat_found": False, "error": str(e), "verdict": "UNKNOWN"}
    
@tool
def run_crtsh(domain: str) -> dict:
    """
    Findet alle Subdomains einer Domain via Certificate Transparency (crt.sh).
    Nützlich, um die Angriffsfläche (Attack Surface) einer Organisation zu kartieren.
    Erkennt potenzielle Schatten-IT oder vergessene Test-Subdomains.
    """
    try:
        resp = httpx.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",  # %25 steht für das SQL Wildcard-Zeichen '%'
            timeout=12,
            headers={"User-Agent": "Mozilla/5.0 OSINT-Argus/1.0"},
        )
        resp.raise_for_status()
        
        if not resp.text.strip() or resp.text.startswith("<"):
            return {"subdomain_count": 0, "subdomains": [], "cert_count": 0}
            
        certs = resp.json()

        # Filtere Duplikate und Wildcards heraus
        subdomains = set()
        for entry in certs:
            name = entry.get("name_value", "").lower().strip()
            # Falls crt.sh mehrere Domains per Newline getrennt zurückgibt
            for sub in name.split("\n"):
                sub = sub.strip()
                if sub.endswith(domain) and "*" not in sub:
                    subdomains.add(sub)

        sorted_subs = sorted(list(subdomains))

        return {
            "subdomain_count": len(sorted_subs),
            "subdomains": sorted_subs[:30],  # Dem Agenten die Top 30 für Triage übergeben
            "cert_count": len(certs),
            "exposure_note": (
                "Kritischer Wildwuchs an Subdomains! Erhöhte Angriffsfläche für verwaiste Hosts."
                if len(sorted_subs) > 20
                else "Normale/Geringe Angriffsfläche."
            ),
        }
    except Exception as e:
        return {
            "error": f"crt.sh temporär überlastet oder Timeout: {str(e)}",
            "subdomain_count": 0,
            "subdomains": []
        }


@tool
def run_tech_detection(domain: str) -> dict:
    """
    Analysiert die HTTP-Header und die HTML-Struktur der Webseite, um eingesetzte Technologien 
    (CMS, Webserver, OS, Frameworks) zu identifizieren.
    Extrahiert saubere Strings für die Weiterverarbeitung im CVEAgent.
    """
    url = f"https://{domain}" if not domain.startswith(("http://", "https://")) else domain
    detected_tech = []
    headers_found = {}
    
    try:
        # TLS-Verifizierung auf False gesetzt, falls wir eine unkonfigurierte/abgelaufene Dev-Domain scannen
        with httpx.Client(timeout=8.0, follow_redirects=True, verify=False) as client:
            resp = client.get(url)
            
        # 1. Fingerprinting über HTTP-Response-Header
        server = resp.headers.get("Server")
        if server:
            headers_found["Server"] = server
            detected_tech.append({"name": server, "category": "Webserver"})
            
        powered_by = resp.headers.get("X-Powered-By")
        if powered_by:
            headers_found["X-Powered-By"] = powered_by
            detected_tech.append({"name": powered_by, "category": "Backend-Framework"})

        # 2. Heuristische Erkennung gängiger CMS/Technologien im DOM-Inhalt
        html_content = resp.text.lower()
        if "wp-content" in html_content or "wordpress" in html_content:
            detected_tech.append({"name": "WordPress", "category": "CMS"})
        if "joomla" in html_content:
            detected_tech.append({"name": "Joomla", "category": "CMS"})
        if "drupal" in html_content:
            detected_tech.append({"name": "Drupal", "category": "CMS"})
            
        # 3. PLACEHOLDER FÜR KOSTENLOSE EXTERNE API-ERWEITERUNG (z.B. BuiltWith / Wappalyzer Community)
        # Hier kann später bei Bedarf ein API-Request eingebunden werden:
        # API_KEY = "DEIN_KEY"

        # Aufbereitung für den CVEAgent: Bereinige Versions-Slashes (z.B. "nginx/1.18.0" -> "nginx 1.18.0")
        cve_targets = []
        for tech in detected_tech:
            clean_name = tech["name"].replace("/", " ").strip()
            cve_targets.append(clean_name)

        return {
            "domain": domain,
            "status_code": resp.status_code,
            "detected_technologies": detected_tech,
            "headers": headers_found,
            "cve_targets": list(set(cve_targets)),  # Duplikate filtern
            "verdict": "INFO" if detected_tech else "UNKNOWN"
        }

    except Exception as e:
        return {
            "domain": domain,
            "error": f"Technologie-Erkennung fehlgeschlagen: {str(e)}",
            "cve_targets": [],
            "verdict": "UNKNOWN"
        }


# Export-Liste für den DomainAgent
DOMAIN_TOOLS = [
    run_whois,
    run_dns_lookup,
    run_ssl_check,
    run_spf_dmarc_check,
    run_urlhaus,
    run_crtsh,
    run_tech_detection
]