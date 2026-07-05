import json

from app.agents.base_agent import BaseAgent
from app.models.llm import get_llm
from app.models.findings import Findings
from app.models.agent_type import AgentType
from app.state import ArgusState
from pydantic import BaseModel, Field
from typing import List, Literal

from app.tools.identity_tools import search_username_with_sherlock
from app.prompts import IDENTITY_AGENT_SYSTEM_PROMPT
from app.memory.chroma_memory import get_user_profile, generate_username_variants
from app.tools.result_cache import cache_exists, load_cached_result, save_result
from app.utils.prompt_cleaner import clean_llm_output


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
                if isinstance(cached_result, dict):
                    agent_raw = cached_result.get("agent", {})
                    agent_value = agent_raw.get("value") if isinstance(agent_raw, dict) else str(agent_raw)
                    finding = Findings(
                        agent=AgentType(agent_value) if agent_value else AgentType.IDENTITY,
                        input=cached_result.get("input", target),
                        threat_sum=cached_result.get("threat_sum", []),
                        vulnerability_sum=cached_result.get("vulnerability_sum", [])
                    )
                    state["findings"].append(finding)
                else:
                    state["findings"].append(cached_result)
                return state

        user_profile = get_user_profile()
        username_variants = generate_username_variants(user_profile)

        # Nur die relevantesten Varianten verwenden (max 3)
        search_variants = []
        target_clean = target.replace(" ", "").lower()

        if len(target_clean) > 2:
            search_variants.append(target_clean)

        email = user_profile.get("email", "")
        if "@" in email:
            email_local = email.split("@")[0].lower()
            if email_local not in search_variants and len(email_local) > 2:
                search_variants.append(email_local)

        gamer_tag = user_profile.get("gamer_tag", "").strip().lower()
        if gamer_tag and gamer_tag != "unbekannt" and gamer_tag not in search_variants:
            search_variants.append(gamer_tag)

        search_variants = search_variants[:3]

        print(f"🔍 [IDENT] Suche {len(search_variants)} Username-Variante(n): {search_variants}")

        osint_raw_data = []
        found_profiles = []

        for variant in search_variants:
            variant_cache_key = f"sherlock:{variant}"
            if cache_exists(variant_cache_key):
                cached = load_cached_result(variant_cache_key)
                if cached and cached.get("profiles"):
                    print(f"💾 [Cache] Variante '{variant}' aus Cache")
                    found_profiles.extend(cached.get("profiles", []))
                    continue

            result = search_username_with_sherlock.invoke({"username": variant})

            if "profiles" in result and result["profiles"]:
                found_profiles.extend(result["profiles"])
                osint_raw_data.append(result)
                save_result(variant_cache_key, result)
            elif "error" not in result:
                osint_raw_data.append(result)

        analysis_raw = self.llm.invoke([
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

        if hasattr(analysis_raw, 'model_dump'):
            analysis = analysis_raw
        else:
            cleaned = clean_llm_output(str(analysis_raw))
            try:
                analysis = IdentityAnalysis(**json.loads(cleaned))
            except Exception as e:
                print(f"[WARN] [IDENT] Parsing-Fehler: {e}")
                analysis = IdentityAnalysis(
                    social_engineering_vector="Parsing-Fehler bei OSINT-Analyse",
                    risk_assessment="UNKNOWN",
                    platform_details=[],
                    reasoning="Konnte OSINT-Ergebnisse nicht korrekt parsen."
                )

        platform_entries = []
        for pf in analysis.platform_details:
            platform_entries.append(f"Plattform: {pf.platform} ({pf.url})")
            platform_entries.append(f"Angriffsvektor: {pf.angriffsvektor}")
            for pretext in pf.pretexts:
                platform_entries.append(f"• {pretext}")

        finding = Findings(
            agent=AgentType.IDENTITY,
            input=target,
            threat_sum=[f"Spear-Phishing Vektor: {analysis.social_engineering_vector}"],
            vulnerability_sum=platform_entries if platform_entries else [f"Keine Profile gefunden für: {search_variants}"],
        )

        state["findings"].append(finding)

        save_result(cache_key, {
            "agent": AgentType.IDENTITY,
            "input": target,
            "threat_sum": finding.threat_sum,
            "vulnerability_sum": finding.vulnerability_sum
        })

        print(f"[IDENT] {target} abgeschlossen.")
        print(f"[WARN] Profil-Risiko: {analysis.risk_assessment}")
        return state