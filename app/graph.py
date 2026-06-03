from langgraph.graph import StateGraph, END
from app.agents.cve_agent import CVEAgent
from app.agents.file_agent import FileAgent
from app.agents.identity_agent import IdentityAgent
from app.agents.output_agent import OutputAgent
from app.agents.phone_agent import PhoneAgent
from app.state import ArgusState
from app.agents.orchestrator_agent import OrchestratorAgent
from app.agents.domain_agent import DomainAgent
from app.agents.email_agent import EmailAgent
from app.agents.input_agent import InputAgent

orchestrator = OrchestratorAgent()
domain_agent  = DomainAgent()
email_agent   = EmailAgent()
output_agent = OutputAgent()
input_agent = InputAgent()
cve_agent = CVEAgent()
phone_agent = PhoneAgent()
file_agent = FileAgent()
identity_agent = IdentityAgent()

builder = StateGraph(ArgusState)

# ── Nodes ──────────────────────────────────────────────────────────────────
builder.add_node("orchestrator", orchestrator.run)
builder.add_node("domain",       domain_agent.run)
builder.add_node("email",        email_agent.run)
builder.add_node("output",        output_agent.run)
builder.add_node("cve", cve_agent.run)
builder.add_node("file", file_agent.run)
builder.add_node ("input", input_agent.run)
builder.add_node("phone", phone_agent.run)
builder.add_node("identity", identity_agent.run)
# ── Entry ──────────────────────────────────────────────────────────────────
builder.set_entry_point("input")

# ── Orchestrator entscheidet wohin ────────────────────────────────────────
builder.add_conditional_edges(
    "orchestrator",
    lambda state: state["next_agent"],
    {
        "domain": "domain",
        "email":  "email",
        "cve":    "cve",       
        "output": "output",   
        "phone": "phone",   
        "file": "file", 
        "identity": "identity"
    },
)

# ── Nach jedem Agent → immer zurück zum Orchestrator (kein direktes END) ──
builder.add_edge("domain", "orchestrator")
builder.add_edge("email",  "orchestrator")
builder.add_edge("cve",  "orchestrator")
builder.add_edge("output", END)
builder.add_edge("input", "orchestrator")
builder.add_edge("phone", "orchestrator")
builder.add_edge("file", "orchestrator")
builder.add_edge("identity", "orchestrator")

graph = builder.compile()