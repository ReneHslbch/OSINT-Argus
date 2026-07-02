from app.agents.base_agent import BaseAgent
from app.models.llm import get_llm
from app.models.findings import Findings
from app.models.agent_type import AgentType
from app.state import ArgusState
from pydantic import BaseModel, Field
from typing import List, Literal

from app.tools.identity_tools import check_email_with_holehe, search_username_with_sherlock
from app.prompts import IDENTITY_AGENT_SYSTEM_PROMPT
from app.memory.chroma_memory import get_user_profile, generate_username_variants
from app.tools.result_cache import cache_exists, load_cached_result, save_result


class PlatformFinding(BaseModel):
    platform: str = Field(description="Name der Plattform (z.B. GitHub, Reddit, Instagram)")
    url: str = Field(description="Direkter Link zum Profil")
    angriffsvektor: str = Field(description="Konkreter Angriffsvektor für Spear-Phishing auf dieser Plattform")
    pretexts: List[str] = Field(description="Liste möglicher Phishing-Betreffzeilen oder Pretext-Szenarien")


class IdentityAnalysis(BaseModel):
    social_engineering_vector: str = Field(description="Wie leicht kann diese Person basierend auf den Funden per Spear-Phishing angegriffen werden?")
    risk_assessment: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = Field(description="Gefahreneinstufung der digitalen Identität")
    platform_details: List[PlatformFinding] = Field(description="Strukturierte Liste aller verifizierten Profile mit Details")
    reasoning: str = Field(description="Detaillierte Begründung des Agenten für seine Bewertung")

class IdentityAgent(BaseAgent):

    def __init__(self):
        # Das LLM liefert uns am Ende strukturierte JSON-Befunde
        self.llm = get_llm().with_structured_output(IdentityAnalysis)

    def run(self, state: ArgusState) -> ArgusState:
        target = state.get("current_check")
        if not target:
            return state

        print(f"\n[IDENT] Analysiere digitale Identitat fur Target: '{target}'")

        # Cache-Check für gesamten Target
        cache_key = f"identity:{target}"
        if cache_exists(cache_key):
            cached_result = load_cached_result(cache_key)
            if cached_result:
                print(f"💾 [Cache] Geladene Ergebnisse für '{target}'")
                state["findings"].append(cached_result)
                return state

        user_profile = get_user_profile()
        username_variants = generate_username_variants(user_profile)
        
        # Nur die relevantesten Varianten verwenden (max 2)
        search_variants = []
        target_clean = target.replace(" ", "").lower()
        
        # Primär: Target selbst
        if len(target_clean) > 2:
            search_variants.append(target_clean)
        
        # Sekundär: E-Mail-Localpart falls im Profil
        email = user_profile.get("email", "")
        if "@" in email:
            email_local = email.split("@")[0].lower()
            if email_local not in search_variants and len(email_local) > 2:
                search_variants.append(email_local)
        
        # Tertiär: Gamer-Tag
        gamer_tag = user_profile.get("gamer_tag", "").strip().lower()
        if gamer_tag and gamer_tag != "unbekannt" and gamer_tag not in search_variants:
            search_variants.append(gamer_tag)
        
        # Max 3 Varianten
        search_variants = search_variants[:3]
        
        print(f"🔍 [IDENT] Suche {len(search_variants)} Username-Variante(n): {search_variants}")

        osint_raw_data = []
        found_profiles = []
        
        for variant in search_variants:
            # Cache-Check pro Variante
            variant_cache_key = f"sherlock:{variant}"
            if cache_exists(variant_cache_key):
                cached = load_cached_result(variant_cache_key)
                if cached and cached.get("profiles"):
                    print(f"💾 [Cache] Variante '{variant}' aus Cache")
                    found_profiles.extend(cached.get("profiles", []))
                    continue
            
            # Sherlock-Suche
            result = search_username_with_sherlock.invoke({"username": variant})
            
            if "profiles" in result and result["profiles"]:
                found_profiles.extend(result["profiles"])
                osint_raw_data.append(result)
                
                # Cache speichern
                save_result(variant_cache_key, result)
            elif "error" not in result:
                osint_raw_data.append(result)

        # LLM-Analyse
        analysis: IdentityAnalysis = self.llm.invoke([
            {
                "role": "system",
                "content": IDENTITY_AGENT_SYSTEM_PROMPT
            },
            {
                "role": "user",
                "content": f"""
Target-Eingabe: {target}
Username-Varianten gesucht: {search_variants}
Gefundene Profile: {found_profiles if found_profiles else "Keine"}
OSINT-Rohdaten:
{osint_raw_data}
"""
            }
        ])

        # Befunde strukturieren
        platform_entries = []
        for pf in analysis.platform_details:
            platform_entries.append(f"Plattform: {pf.platform} ({pf.url})")
            platform_entries.append(f"Angriffsvektor: {pf.angriffsvektor}")
            for pretext in pf.pretexts:
                platform_entries.append(f"• {pretext}")

        finding = Findings(
            agent=AgentType.FILE,
            input=target,
            threat_sum=[f"Spear-Phishing Vektor: {analysis.social_engineering_vector}"],
            vulnerability_sum=platform_entries if platform_entries else [f"Keine Profile gefunden für: {search_variants}"],
        )

        state["findings"].append(finding)
        
        # Gesamtergebnis cachen
        save_result(cache_key, {
            "agent": AgentType.FILE,
            "input": target,
            "threat_sum": finding.threat_sum,
            "vulnerability_sum": finding.vulnerability_sum
        })

        print(f"[IDENT] {target} abgeschlossen.")
        print(f"[WARN] Profil-Risiko: {analysis.risk_assessment}")
        return state

        print(f"\n[IDENT] Analysiere digitale Identitat fur Target: '{target}'")

        user_profile = get_user_profile()
        username_variants = generate_username_variants(user_profile)
        
        osint_raw_data = []
        searched_usernames = set()

        if "@" in target:
            holehe_res = check_email_with_holehe.invoke({"email": target})
            osint_raw_data.append(holehe_res)
            
            username_handle = target.split("@")[0]
            if username_handle not in searched_usernames:
                searched_usernames.add(username_handle)
                sherlock_res = search_username_with_sherlock.invoke({"username": username_handle})
                osint_raw_data.append(sherlock_res)
        else:
            searched_usernames.add(target.replace(" ", "").lower())
            sherlock_res = search_username_with_sherlock.invoke({"username": target.replace(" ", "").lower()})
            osint_raw_data.append(sherlock_res)

        for variant in username_variants:
            if variant not in searched_usernames and len(variant) > 2:
                searched_usernames.add(variant)
                print(f"🔍 [Sherlock] Erweiterte Suche für Username-Variante: {variant}...")
                sherlock_res = search_username_with_sherlock.invoke({"username": variant})
                osint_raw_data.append(sherlock_res)

        analysis: IdentityAnalysis = self.llm.invoke([
            {
                "role": "system",
                "content": IDENTITY_AGENT_SYSTEM_PROMPT
            },
            {
                "role": "user",
                "content": f"""
Target-Eingabe: {target}
Benutzerprofil-Varianten: {username_variants}
Ermittelte OSINT-Rohdaten:
{osint_raw_data}
"""
            }
        ])

        # 5. Befunde in die globalen Findings eintragen
        platform_entries = []
        for pf in analysis.platform_details:
            platform_entries.append(f"Plattform: {pf.platform} ({pf.url})")
            platform_entries.append(f"Angriffsvektor: {pf.angriffsvektor}")
            for pretext in pf.pretexts:
                platform_entries.append(f"• {pretext}")

        state["findings"].append(
            Findings(
                agent=AgentType.FILE,
                input=target,
                threat_sum=[f"Spear-Phishing Vektor: {analysis.social_engineering_vector}"],
                vulnerability_sum=platform_entries,
            )
        )

        print(f"[IDENT] {target} abgeschlossen.")
        print(f"[WARN] Profil-Risiko: {analysis.risk_assessment}")
        print(f"[INFO] {analysis.reasoning}")

        return state