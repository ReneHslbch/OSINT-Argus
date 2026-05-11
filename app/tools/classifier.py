import re


def classify_input(user_input: str) -> str:
    email_pattern = r"^[^@]+@[^@]+\.[^@]+$"
    domain_pattern = r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"

    if re.match(email_pattern, user_input):
        return "email"

    if re.match(domain_pattern, user_input):
        return "domain"

    return "unknown"