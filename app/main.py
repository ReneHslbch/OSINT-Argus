from pprint import pprint

from app.graph import graph
from app.tools.classifier import classify_input



def main():

    user_input = input("Target: ")

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
    main()