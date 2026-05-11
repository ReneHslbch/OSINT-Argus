import dns.resolver


RECORD_TYPES = ["A", "MX", "NS"]



def run_dns_lookup(domain: str):
    results = {}

    for record_type in RECORD_TYPES:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            results[record_type] = [str(r) for r in answers]

        except Exception:
            results[record_type] = []

    return results