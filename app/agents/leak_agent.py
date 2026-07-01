from app.agents.base_agent import BaseAgent
from app.models.findings import Findings
from app.models.agent_type import AgentType
from app.tools.leak_tools import check_hibp
from app.memory.chroma_memory import get_user_profile


class LeakAgent(BaseAgent):

    def run(self, state):
        target = state.get("current_check")
        findings_list = state.get("findings", [])
        
        # 1. Lade das erlernte Nutzerprofil aus Schritt 2
        user_profile = get_user_profile()
        profile_email = user_profile.get("email", "Unbekannt")

        # 2. Dynamische Target-Ermittlung
        # Fall A: Das aktuelle Target selbst ist eine E-Mail
        if target and "@" in target:
            leak_target = target
            source_info = f"Direktes Target '{target}'"
        
        # Fall B: Das aktuelle Target ist keine E-Mail, aber wir haben eine im Profil gelernt
        elif profile_email and profile_email != "Unbekannt" and "@" in profile_email:
            leak_target = profile_email
            source_info = f"Aus Nutzerprofil korrelierte E-Mail-Adresse '{profile_email}' (während Scan von: {target})"
        
        # Fall C: Keine E-Mail-Adresse verfügbar
        else:
            print(f"[INFO] [LEAK] Uberspringe Leak-Check. Weder Target noch Profil enthalten eine E-Mail-Adresse.")

        print(f"[LEAK] Prufe Datenlecks fur: {leak_target} ({source_info})...")

        # 3. Tool aufrufen
        result = check_hibp.invoke({
            "email": leak_target
        })

        # 4. Befunde strukturieren
        breaches = result.get("breaches", [])
        error = result.get("error")

        if error:
            threat_sum = [f"Fehler bei HIBP-Abfrage für {leak_target}"]
            vulnerability_sum = [f"API-Fehler: {error}"]
        else:
            threat_sum = [
                f"{len(breaches)} Breaches gefunden für {leak_target} ({source_info})"
            ]
            vulnerability_sum = breaches if breaches else ["Keine bekannten Datenlecks in HIBP hinterlegt."]

        # 5. In die globalen Findings eintragen
        finding = Findings(
            agent=AgentType.LEAK,
            input=leak_target,
            threat_sum=threat_sum,
            vulnerability_sum=vulnerability_sum
        )

        findings_list.append(finding)
        state["findings"] = findings_list

        print(f"[LEAK] Analyse fur {leak_target} abgeschlossen. Funde: {len(breaches)}")
        return state