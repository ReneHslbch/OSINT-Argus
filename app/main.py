import sys

from app.graph import graph


def read_input() -> str:
    if not sys.stdin.isatty():
        return sys.stdin.buffer.read().decode(
            "utf-8",
            errors="replace"
        ).strip()

    print("📝 Eingabe (leere Zeile zum Abschließen):")
    lines = []
    while True:
        try:
            line = input()
            if line == "" and lines:
                break
            lines.append(line)
        except EOFError:
            break
    return "\n".join(lines).strip()

def main():
    user_input = read_input()

    if not user_input:
        print("❌ Kein Input erhalten.")
        return

    print(f"\n📨 Input empfangen ({len(user_input.splitlines())} Zeilen)\n")

    # Der absolut minimale Start-State. 
    # Alles andere baut der InputAgent oder Orchestrator dynamisch auf.
    state = {
        "user_input":       user_input,
        "input_type":       "unknown", # Wird vom InputAgent überschrieben
        "current_agent":    "input",
        "next_agent":       "",
        "findings":         [],
        "risk_score":       None,
        "summary":          None,
        "memory_context":   None,
        "to_scan":          [],
        "scanned":          [],
        "current_check":    None
    }

    try:
        # LangGraph Pipeline starten
        result = graph.invoke(state)
        print("🏁 Pipeline erfolgreich beendet!")
    except Exception as e:
        print(f"\n❌ Fehler: {type(e).__name__}: {e}")
        sys.exit(1)

if __name__ == "__main__":
    print("╔══════════════════════════════════════════════╗")
    print("║       👁️  OSINT-Argus Multi-Agent            ║")
    print("║     DomainAgent · EmailAgent · CVEAgent      ║")
    print("╚══════════════════════════════════════════════╝\n")
    main()