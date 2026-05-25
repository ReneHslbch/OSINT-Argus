import sys
from pprint import pprint
from app.graph import graph
from app.tools.classifier import classify_input


def read_multiline_input() -> str:
    lines = []
    while True:
        try:
            line = input()
            if line == "" and lines:
                break
            lines.append(line)
        except EOFError:
            # Pipe-Modus: alles auf einmal lesen
            break
    return "\n".join(lines).strip()


def main():
    print("📝 Eingabe (leere Zeile zum Abschließen):\n")
    user_input = read_multiline_input()

    if not user_input:
        print("❌ Kein Input erhalten.")
        return

    print(f"\n📨 Input empfangen ({len(user_input.splitlines())} Zeilen)\n")

    state = {
        "user_input":       user_input,
        "input_type":       classify_input(user_input),
        "current_agent":    "orchestrator",
        "next_agent":       "",
        "findings":         [],
        "risk_score":       None,
        "summary":          None,
        "memory_context":   None,
        "email_pass":       0,
        "domains_to_scan":  [],
        "domains_scanned":  [],
        "current_domain":   None,
        "email_extraction": None,
    }

    try:
        result = graph.invoke(state)
        pprint(result)
    except Exception as e:
        print(f"\n❌ Fehler: {type(e).__name__}: {e}")
        print("   → Tipp: SAIA API manchmal langsam, nochmal versuchen.")
        sys.exit(1)


if __name__ == "__main__":
    print("╔══════════════════════════════════════════════╗")
    print("║       👁️  OSINT-Argus Multi-Agent            ║")
    print("║     DomainAgent · EmailAgent · CVEAgent      ║")
    print("║          RAG Memory · LangGraph              ║")
    print("╚══════════════════════════════════════════════╝\n")
    main()