import os
import hashlib
import httpx
from langchain_core.tools import tool

try:
    from pypdf import PdfReader
except Exception:
    PdfReader = None

try:
    import exiftool
except Exception:
    exiftool = None


@tool
def calculate_sha256(file_path: str) -> str:
    """
    Berechnet den SHA256-Hash einer lokalen Datei. Nützlich für die spätere Überprüfung bei VirusTotal.
    """
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        return f"Error: {str(e)}"


@tool
def extract_document_metadata(file_path: str) -> dict:
    """
    Extrahiert Metadaten exklusiv von PDF-Dateien (.pdf) mithilfe von pypdf.
    """
    metadata = {}
    try:
        if PdfReader and file_path.lower().endswith(".pdf"):
            reader = PdfReader(file_path)
            metadata = dict(reader.metadata or {})
        return {"file_path": file_path, "metadata": metadata}
    except Exception as e:
        return {"error": str(e)}


@tool
def extract_universell_document_metadata(file_path: str) -> dict:
    """
    Extrahiert universell Metadaten für verschiedene Dateitypen. 
    Nutzt pypdf als primären Parser für PDFs und exiftool als Fallback für andere Dateitypen.
    """
    # Überprüfen, ob die Datei überhaupt existiert
    if not os.path.exists(file_path):
        return {"file_path": file_path, "error": f"Datei lokal unter dem Pfad '{file_path}' nicht gefunden."}

    # Fall 1: Es ist eine PDF -> pypdf nutzen (läuft nativ in Python ohne externe .exe)
    if file_path.lower().endswith(".pdf") and PdfReader is not None:
        try:
            reader = PdfReader(file_path)
            raw_meta = reader.metadata or {}
            cleaned_meta = {}
            for k, v in raw_meta.items():
                # Bereinigt Schrägstriche aus den PDF-Keys (z.B. /Author -> Author)
                key_name = k.replace("/", "")
                cleaned_meta[key_name] = str(v)
            
            # Anzahl der Seiten als Extra-Metadaten mitgeben
            cleaned_meta["Pages"] = len(reader.pages)
            
            return {"file_path": file_path, "source": "pypdf", "metadata": cleaned_meta}
        except Exception as pdf_err:
            pass # Falls die PDF korrupt ist, versuchen wir es mit exiftool

    # Fall 2: Andere Dateitypen oder Fallback zu ExifTool
    if exiftool is not None:
        try:
            with exiftool.ExifToolHelper() as et:
                metadata = et.get_metadata(file_path)
            return {
                "file_path": file_path,
                "source": "exiftool",
                "metadata": metadata[0] if metadata else {}
            }
        except Exception as e:
            return {
                "file_path": file_path,
                "error": f"ExifTool Fehler: {str(e)}."
            }
            
    return {"file_path": file_path, "error": "Kein geeigneter Parser (pypdf/exiftool) installiert oder verfügbar."}


@tool
def check_file_hash_virustotal(file_hash: str) -> dict:
    """
    Analysiert einen Datei-Hash (MD5, SHA1, SHA256) über die VirusTotal v3 API auf Malware-Befunde.
    """
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        return {"error": "VT_API_KEY nicht gesetzt", "verdict": "UNKNOWN"}

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}

    try:
        r = httpx.get(url, headers=headers, timeout=15)
        if r.status_code == 404:
            return {"verdict": "UNKNOWN", "file_hash": file_hash, "info": "Hash bei VirusTotal unbekannt."}

        data = r.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        verdict = "CLEAN"
        if malicious > 0:
            verdict = "MALICIOUS"
        elif suspicious > 0:
            verdict = "SUSPICIOUS"

        return {
            "file_hash": file_hash,
            "verdict": verdict,
            "malicious": malicious,
            "suspicious": suspicious
        }
    except Exception as e:
        return {"error": str(e), "verdict": "UNKNOWN"}


FILE_TOOLS = [
    calculate_sha256, 
    extract_document_metadata, 
    extract_universell_document_metadata, 
    check_file_hash_virustotal
]