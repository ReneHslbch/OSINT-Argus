from langgraph.graph import StateGraph, END
from app.agents.cve_agent import CVEAgent
from app.agents.output_agent import OutputAgent
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

builder = StateGraph(ArgusState)

# ── Nodes ──────────────────────────────────────────────────────────────────
builder.add_node("orchestrator", orchestrator.run)
builder.add_node("domain",       domain_agent.run)
builder.add_node("email",        email_agent.run)
builder.add_node("output",        output_agent.run)
builder.add_node("cve", cve_agent.run)
builder.add_node ("input", input_agent.run)
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
    },
)

# ── Nach jedem Agent → immer zurück zum Orchestrator (kein direktes END) ──
builder.add_edge("domain", "orchestrator")
builder.add_edge("email",  "orchestrator")
builder.add_edge("cve",  "orchestrator")
builder.add_edge("output", END)
builder.add_edge("input", "orchestrator")

graph = builder.compile()