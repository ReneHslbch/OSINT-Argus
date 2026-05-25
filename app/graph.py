from langgraph.graph import StateGraph, END
from app.agents.output_agent import OutputAgent
from app.state import ArgusState
from app.agents.orchestrator_agent import OrchestratorAgent
from app.agents.domain_agent import DomainAgent
from app.agents.email_agent import EmailAgent

orchestrator = OrchestratorAgent()
domain_agent  = DomainAgent()
email_agent   = EmailAgent()
output_agent = OutputAgent()

builder = StateGraph(ArgusState)

# ── Nodes ──────────────────────────────────────────────────────────────────
builder.add_node("orchestrator", orchestrator.run)
builder.add_node("domain",       domain_agent.run)
builder.add_node("email",        email_agent.run)
builder.add_node("output",        output_agent.run)
# ── Entry ──────────────────────────────────────────────────────────────────
builder.set_entry_point("orchestrator")

# ── Orchestrator entscheidet wohin ────────────────────────────────────────
builder.add_conditional_edges(
    "orchestrator",
    lambda state: state["next_agent"],
    {
        "domain": "domain",
        "email":  "email",
        "cve":    END,       # Sprint 3
        "output": "output",       # OutputAgent kommt in Sprint 2 Part 2
    },
)

# ── Nach jedem Agent → immer zurück zum Orchestrator (kein direktes END) ──
builder.add_edge("domain", "orchestrator")
builder.add_edge("email",  "orchestrator")
builder.add_edge("output", END)

graph = builder.compile()