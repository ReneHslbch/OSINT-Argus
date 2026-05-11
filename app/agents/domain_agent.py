from app.agents.base_agent import BaseAgent
from app.state import ArgusState

from app.tools.whois_tool import run_whois
from app.tools.dns_tool import run_dns_lookup


class DomainAgent(BaseAgent):

    def run(self, state: ArgusState) -> ArgusState:
        domain = state["user_input"]

        whois_data = run_whois(domain)
        dns_data = run_dns_lookup(domain)

        state["findings"].append({
            "agent": "DomainAgent",
            "whois": whois_data,
            "dns": dns_data,
        })

        state["next_agent"] = "output"

        return state