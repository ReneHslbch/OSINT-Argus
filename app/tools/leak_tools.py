import requests
from langchain_core.tools import tool

@tool
def check_hibp(email: str) -> dict:
    """
    Sucht via XposedOrNot API nach realen Datenlecks einer E-Mail-Adresse.
    Vollständig kostenlos, Open-Source und ohne API-Key nutzbar.
    """
    email_clean = email.strip().lower()
    
    # Offizielle, freie API-Schnittstelle von XposedOrNot
    url = f"https://api.xposedornot.com/v1/check-email/{email_clean}"
    
    # Ein korrekter User-Agent ist Best Practice bei OSINT-Abfragen
    headers = {
        "User-Agent": "OSINT-Argus-Cybersecurity-Analyzer-Student-Project"
    }
    
    try:
        # Die API erlaubt bis zu 2 Anfragen pro Sekunde (perfekt für uns)
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            # XposedOrNot liefert ein Array aus Listen zurück, z.B. [["Adobe"], ["LinkedIn"]]
            raw_breaches = data.get("breaches", [])
            
            # Flachklopfen der verschachtelten Liste zu sauberen Strings für die UI
            breaches = []
            for item in raw_breaches:
                if isinstance(item, list) and len(item) > 0:
                    breaches.append(f"Breach: {item[0]}")
                elif isinstance(item, str):
                    breaches.append(f"Breach: {item}")
                    
            return {"breaches": breaches}
            
        elif response.status_code == 404:
            # 404 bedeutet bei dieser API: Die E-Mail ist in keinem bekannten Leak!
            return {"breaches": []}
            
        elif response.status_code == 429:
            return {"error": "API-Rate-Limit überschritten (Max 2 Requests/Sekunde). Bitte kurz warten."}
        else:
            return {"error": f"Alternative API lieferte Status Code {response.status_code}"}
            
    except requests.exceptions.Timeout:
        return {"error": "Zeitüberschreitung bei der Anfrage an die Leak-Datenbank."}
    except Exception as e:
        return {"error": f"Verbindungsfehler zur OSINT-Schnittstelle: {str(e)}"}