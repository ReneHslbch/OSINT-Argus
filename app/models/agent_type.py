from enum import Enum

class AgentType(str, Enum):
    INPUT = "input"
    ORCHESTRATOR = "orchestrator"
    DOMAIN = "domain"
    EMAIL = "email"
    CVE = "cve"
    PHONE = "phone"  
    OUTPUT = "output"
    FILE = "file"
    IDENTITY = "identity"
    LEAK = "leak"