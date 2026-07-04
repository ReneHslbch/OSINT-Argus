"""Test der LLM-Verbindung zum Provider."""
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

from app.models.llm import get_llm

def test_llm_connection():
    """Testet ob die LLM-Verbindung funktioniert."""
    print("=" * 60)
    print("LLM VERBINDUNGSTEST")
    print("=" * 60)
    
    try:
        llm = get_llm()
        print("[OK] LLM-Instanz erstellt")
        print(f"  Model: {llm.model_name}")
        print(f"  Timeout: {llm.request_timeout}")
        
        print("\nTeste einfache Chat-Anfrage...")
        response = llm.invoke("Hallo, antworte kurz mit OK.")
        print("[OK] Antwort erhalten:")
        print(f"  {response.content}")
        
        print("\n" + "=" * 60)
        print("[OK] ALLE TESTE BESTANDEN - LLM ist betriebsbereit")
        print("=" * 60)
        return True
        
    except Exception as e:
        print(f"\n[FEHLER] {type(e).__name__}: {e}")
        print("\n" + "=" * 60)
        print("[FEHLER] LLM VERBINDUNG FEHLGESCHLAGEN")
        print("=" * 60)
        return False

if __name__ == "__main__":
    test_llm_connection()
