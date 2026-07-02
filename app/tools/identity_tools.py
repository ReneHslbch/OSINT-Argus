import os
import shutil
import subprocess
from langchain_core.tools import tool

@tool
def check_email_with_holehe(email: str) -> dict:
    """
    Nutzt das Holehe-Framework, um zu prüfen, bei welchen Plattformen 
    (z.B. Twitter, LinkedIn, Imgur) diese E-Mail-Adresse registriert ist.
    Gibt eine Liste von genutzten Plattformen zurück.
    """
    if not "@" in email:
        return {"error": f"'{email}' ist keine valide E-Mail-Adresse für Holehe."}
        
    print(f"🔍 [Holehe] Scanne Registrierungen für E-Mail: {email}...")
    
    holehe_path = shutil.which("holehe")
    if not holehe_path:
        return {"error": "Holehe CLI nicht gefunden. Bitte mit 'pip install holehe' installieren."}
    
    try:
        result = subprocess.run(
            ["holehe", email, "--output", "/dev/null"],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        platforms = []
        for line in result.stdout.split("\n"):
            if "+" in line or "✓" in line:
                parts = line.strip().split()
                if parts:
                    platforms.append(parts[0].rstrip("+"))
        
        return {
            "email": email,
            "platforms_found": platforms,
            "total_matches": len(platforms),
            "source": "Holehe OSINT"
        }
    except subprocess.TimeoutExpired:
        return {"error": "Holehe-Scan zeitüberschritten."}
    except Exception as e:
        return {"error": f"Holehe-Fehler: {str(e)}"}


@tool
def search_username_with_sherlock(username: str) -> dict:
    """
    Nutzt das Sherlock-Tool, um nach der Existenz eines Social-Media-Handles/Usernames 
    auf über 400 Plattformen (GitHub, Reddit, Instagram etc.) zu suchen.
    """
    clean_username = username.split("@")[0] if "@" in username else username
    
    print(f"🔍 [Sherlock] Suche Profile für Username: {clean_username}...")
    
    sherlock_path = shutil.which("sherlock")
    if not sherlock_path:
        return {"error": "Sherlock CLI nicht gefunden. Bitte mit 'pip install sherlock-project' installieren."}
    
    try:
        result = subprocess.run(
            ["sherlock", clean_username, "--timeout", "5", "--disable-progress"],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        profiles = []
        for line in result.stdout.split("\n"):
            if "✓" in line or "+" in line:
                parts = line.strip().split()
                if len(parts) >= 2:
                    site = parts[0].rstrip(":+")
                    profiles.append(f"https://{site.lower()}.com/{clean_username}")
        
        return {
            "username": clean_username,
            "profiles": profiles,
            "total_profiles_found": len(profiles),
            "source": "Sherlock OSINT"
        }
    except subprocess.TimeoutExpired:
        return {"error": "Sherlock-Scan zeitüberschritten (>30s)."}
    except Exception as e:
        return {"error": f"Sherlock-Fehler: {str(e)}"}