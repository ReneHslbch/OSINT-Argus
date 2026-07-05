"""Test der LLM-Verbindung zum Provider."""
import sys
import time
import os
from dotenv import load_dotenv

load_dotenv()

def log(msg: str):
    print(msg, flush=True)   # explizites flush statt Buffer-Hacks


def test_llm_connection():
    log("=" * 60)
    log("LLM VERBINDUNGSTEST")
    log("=" * 60)

    log(f"OPENAI_BASE_URL = {os.getenv('OPENAI_BASE_URL')!r}")
    log(f"MODEL_NAME      = {os.getenv('MODEL_NAME')!r}")
    log(f"API_KEY gesetzt = {bool(os.getenv('OPENAI_API_KEY'))}")

    # 1) Reiner Netzwerk-Test OHNE langchain — isoliert Provider/DNS/Firewall
    log("\n[1/2] Teste rohen HTTP-Request zum Base-URL (10s Timeout)...")
    try:
        import httpx
        t0 = time.time()
        resp = httpx.get(os.getenv("OPENAI_BASE_URL"), timeout=10.0)
        log(f"[OK] HTTP-Antwort nach {time.time() - t0:.1f}s — Status: {resp.status_code}")
    except Exception as e:
        log(f"[FEHLER] Roher HTTP-Request fehlgeschlagen/Timeout: {type(e).__name__}: {e}")

    # 2) LangChain ChatOpenAI Call MIT explizitem, hartem Timeout
    log("\n[2/2] Teste ChatOpenAI-Call (30s Timeout)...")
    from app.models.llm import get_llm
    try:
        llm = get_llm()
        log("[OK] LLM-Instanz erstellt")
        log(f"  Model: {llm.model_name}")

        t0 = time.time()
        response = llm.invoke("Hallo, antworte kurz mit OK.")
        log(f"[OK] Antwort erhalten nach {time.time() - t0:.1f}s:")
        log(f"  {response.content}")

    except Exception as e:
        log(f"[FEHLER] {type(e).__name__}: {e}")


if __name__ == "__main__":
    test_llm_connection()