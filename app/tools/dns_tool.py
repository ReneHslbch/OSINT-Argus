import dns.resolver
from langchain.tools import tool


RECORD_TYPES = ["A", "MX", "NS"]


@tool
def run_dns_lookup(domain: str):
    """Perform a DNS lookup to retrieve A, AAAA, MX, and TXT records."""
    results = {}

    for record_type in RECORD_TYPES:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            results[record_type] = [str(r) for r in answers]

        except Exception:
            results[record_type] = []

    return results