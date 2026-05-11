from langgraph.graph import StateGraph, END

from app.state import ArgusState

from app.agents.orchestrator_agent import OrchestratorAgent
from app.agents.domain_agent import DomainAgent


orchestrator = OrchestratorAgent()
domain_agent = DomainAgent()


builder = StateGraph(ArgusState)


# Nodes
builder.add_node(
    "orchestrator",
    orchestrator.run,
)

builder.add_node(
    "domain",
    domain_agent.run,
)


# Entry
builder.set_entry_point("orchestrator")


# Routing
builder.add_conditional_edges(
    "orchestrator",
    lambda state: state["next_agent"],
    {
        "domain": "domain",
        "email": END,
        "cve": END,
        "output": END,
    },
)


builder.add_edge("domain", END)


graph = builder.compile()