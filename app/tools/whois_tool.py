from langchain.tools import tool
import whois

@tool
def run_whois(domain: str):
    """Run a WHOIS lookup on a given domain to find registration details."""
    try:
        data = whois.whois(domain)

        return {
            "domain": domain,
            "registrar": data.registrar,
            "creation_date": str(data.creation_date),
            "expiration_date": str(data.expiration_date),
            "name_servers": data.name_servers,
        }

    except Exception as e:
        return {
            "error": str(e)
        }