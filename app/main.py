from pprint import pprint

from app.graph import graph
from app.tools.classifier import classify_input



def main():

    user_input = input("🔍 Input : ")

    state = {
        "user_input": user_input,
        "input_type": classify_input(user_input),
        "current_agent": "orchestrator",
        "next_agent": "",
        "findings": [],
        "risk_score": None,
        "summary": None,
        "memory_context": None,
    }

    result = graph.invoke(state)

    pprint(result)


if __name__ == "__main__":
    print("╔══════════════════════════════════════════════╗")
    print("║       👁️  OSINT-Argus Multi-Agent           ║")
    print("║     DomainAgent · EmailAgent · CVEAgent      ║")
    print("║          RAG Memory · LangGraph              ║")
    print("╚══════════════════════════════════════════════╝\n")

    main()