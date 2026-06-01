import sys
from app.graph import graph

def read_input() -> str:
    # 1. Fall: Automatisierter Stream (z.B. Get-Content ... | python -m app.main)
    if not sys.stdin.isatty():
        return sys.stdin.buffer.read().decode(
            "utf-8",
            errors="replace"
        ).strip()

    # 2. Fall: Interaktive Konsole / Reinkopieren
    print("📝 Eingabe (Ganze Mail reinkopieren und mit einer leeren Zeile/Enter abschließen):")
    lines = []
    while True:
        try:
            line = input()
            # Sobald EINE leere Zeile kommt, brechen wir sofort ab
            if line.strip() == "":
                break
            lines.append(line)
        except EOFError:
            break
        except KeyboardInterrupt:
            print("\n👋 Scan abgebrochen.")
            sys.exit(0)
            
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
    print("║        👁️  OSINT-Argus Multi-Agent            ║")
    print("║     DomainAgent · EmailAgent · CVEAgent      ║")
    print("╚══════════════════════════════════════════════╝\n")
    main()