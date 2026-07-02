"""
app/ui/analyse_tab.py
Tab 1: Analyse-Pipeline mit Live-Agent-Log und Ergebnisdarstellung.
"""

import time
import streamlit as st
import asyncio
from typing import Any

from app.graph import graph, graph_async
from app.ui.styles import AGENT_ICON
from app.ui.results import render_results
from app.tools.classifier import classify_input
from app.state import ArgusState


# ── State-Builder ─────────────────────────────────────────────────────────────

def build_initial_state(user_input: str) -> dict:
    return {
        "user_input":     user_input,
        "input_type":     "unknown",
        "current_agent":  "input",
        "next_agent":     "",
        "findings":       [],
        "risk_score":     None,
        "summary":        None,
        "memory_context": None,
        "to_scan":        [],
        "scanned":        [],
        "current_check":  None,
        "file_paths":     [],
        "file_hashes":    [],
    }


# ── Live-Pipeline ─────────────────────────────────────────────────────────────

def _is_independent_target(target: str, current_agent: str) -> bool:
    """Prüft ob ein Target unabhängig vom aktuellen Kontext ist (für Parallelisierung)."""
    classification = classify_input(target)
    return classification in ("email", "domain")

async def _run_single_target(state: ArgusState, target: str, agent_name: str, 
                              log_slot, t0) -> dict:
    """Führt die Analyse für ein einzelnes Target aus."""
    target_state = state.copy()
    target_state["current_check"] = target
    target_state["next_agent"] = agent_name
    target_state["findings"] = []
    target_state["node_timings"] = {}
    target_state["to_scan"] = []
    target_state["scanned"] = []
    
    final_state = {}
    async for chunk in graph_async.astream(target_state, stream_mode="updates"):
        for node_name, node_state in chunk.items():
            for key in ("findings", "to_scan", "scanned", "node_timings", 
                        "memory_context", "risk_score", "risk_level"):
                if node_state.get(key) is not None:
                    if key not in final_state:
                        final_state[key] = [] if key in ("findings", "to_scan", "scanned") else {}
                    if isinstance(node_state[key], list):
                        final_state[key].extend(node_state[key])
                    elif isinstance(node_state[key], dict):
                        final_state[key].update(node_state[key])
                    else:
                        final_state[key] = node_state[key]
    
    return final_state

async def _run_parallel_pipeline(user_input: str, state: ArgusState, 
                                  log_slot, timing_slot, t0) -> dict:
    """Führt parallele Analyse für unabhängige Targets durch."""
    all_findings: list = []
    all_timings: dict[str, list[dict]] = {}
    all_scanned: list = []
    all_to_scan: list = []
    
    remaining = state.get("to_scan", [])[:]
    
    while remaining:
        independent_tasks = []
        sequential_targets = []
        
        for target in remaining:
            classification = classify_input(target)
            if classification == "email":
                independent_tasks.append((target, "email"))
            elif classification == "domain":
                independent_tasks.append((target, "domain"))
            else:
                sequential_targets.append(target)
        
        if independent_tasks:
            print(f"\n⚡ [Parallel] Verarbeite {len(independent_tasks)} unabhängige Targets parallel...")
            
            tasks = [_run_single_target(state, target, agent, log_slot, t0) 
                     for target, agent in independent_tasks]
            results = await asyncio.gather(*tasks)
            
            for result in results:
                if "findings" in result:
                    all_findings.extend(result["findings"])
                if "node_timings" in result:
                    for node, timings in result["node_timings"].items():
                        if node not in all_timings:
                            all_timings[node] = []
                        all_timings[node].extend(timings)
                if "scanned" in result:
                    all_scanned.extend(result["scanned"])
                if "to_scan" in result:
                    all_to_scan.extend(result["to_scan"])
            
            processed = [target for target, _ in independent_tasks]
            remaining = [t for t in sequential_targets if t not in processed]
        else:
            break
    
    state["findings"] = all_findings
    state["node_timings"] = all_timings
    state["scanned"] = list(set(all_scanned))
    state["to_scan"] = list(set(all_to_scan))
    
    return state

def run_with_live_log(user_input: str, skip_targets: set = None) -> dict:
    """Streamt die Graph-Pipeline und zeigt den Agent-Fortschritt live an.
    
    Optimierungen:
    1. Zeitmessung pro Graph-Knoten (Performance-Metriken)
    2. Deterministisches Routing für Regex-klassifizierte Targets
    3. Parallele Verarbeitung unabhängiger Targets
    4. Skip-Funktion für individuelle Targets
    """
    if skip_targets is None:
        skip_targets = set()
    
    state    = build_initial_state(user_input)
    log_slot = st.empty()
    timing_slot = st.empty()
    log_rows: list[tuple] = []   # (agent, target, done, start_time)
    t0 = time.time()
    
    node_timings: dict[str, list[dict[str, Any]]] = {}

    def render_log() -> None:
        from app.ui.styles import CSS

        rows_html = ""
        for i, (agent, target, done, start_time) in enumerate(log_rows[-14:]):
            icon   = AGENT_ICON.get(agent, "⚙️")
            status = "✅" if done else "⏳"
            tgt    = target[:60] if target else ""
            elapsed_ms = int((time.time() - start_time) * 1000) if not done else ""
            time_str = f"{elapsed_ms}ms" if elapsed_ms else ""
            
            row_class = "live-row"
            if not done:
                row_class += " live-row-active"
            
            rows_html += (
                f'<div class="{row_class}">'
                f'<span style="font-size:1rem;">{icon}</span>'
                f'<span class="live-agent">{agent.upper()}</span>'
                f'<span class="live-target">{tgt}</span>'
                f'<span class="live-time">{time_str}</span>'
                f'<span class="live-status">{status}</span>'
                f'</div>'
            )
            
        elapsed = round(time.time() - t0, 1)
        log_slot.markdown(
            f'{CSS}'
            f'<div style="border:1px solid rgba(128,128,128,0.15);border-radius:10px;'
            f'padding:1rem 1.2rem;margin:0.5rem 0">'
            f'<div style="font-size:0.7rem;opacity:0.4;margin-bottom:0.6rem;'
            f'letter-spacing:0.08em">AGENT PIPELINE · {elapsed}s</div>'
            f'{rows_html}'
            f'</div>',
            unsafe_allow_html=True,
        )
    
    def render_timings() -> None:
        """Rendert Performance-Metriken als Streamlit-Markdown."""
        if not node_timings:
            return
        
        lines = ["**Performance-Metriken pro Knoten:**"]
        for node, timings in node_timings.items():
            for t in timings:
                target_preview = (t["target"][:30] + "...") if t["target"] and len(t["target"]) > 30 else (t["target"] or "-")
                lines.append(f"- `{node}`: {t['duration_ms']:.1f}ms (Target: {target_preview})")
        
        timing_slot.markdown("\n".join(lines))

    all_findings: list = []
    final_state = state.copy()

    has_parallel = any(
        classify_input(t) in ("email", "domain") 
        for t in state.get("to_scan", []) if t not in skip_targets
    )
    
    if has_parallel and len([t for t in state.get("to_scan", []) 
                              if classify_input(t) in ("email", "domain") and t not in skip_targets]) > 1:
        print("\n⚡ [Parallel Mode] Starte parallele Verarbeitung unabhängiger Targets...")
        
        try:
            import nest_asyncio
            nest_asyncio.apply()
        except Exception:
            pass
        
        async def run_parallel():
            return await _run_parallel_pipeline(user_input, state, log_slot, timing_slot, t0)
        
        loop = asyncio.get_event_loop()
        final_state = loop.run_until_complete(run_parallel())
        
        for key in ("risk_score", "risk_level", "summary", "action_advice",
                    "input_type", "memory_context", "next_agent", "current_check"):
            if final_state.get(key) is not None:
                final_state[key] = final_state[key]

        if final_state.get("findings"):
            all_findings.extend(final_state["findings"])
        if final_state.get("node_timings"):
            node_timings = final_state["node_timings"]
        render_log()
        render_timings()
    else:
        for chunk in graph.stream(state, stream_mode="updates"):
            for node_name, node_state in chunk.items():
                if log_rows:
                    prev = log_rows[-1]
                    log_rows[-1] = (prev[0], prev[1], True, prev[3])

                target = node_state.get("current_check") or ""
                
                if target in skip_targets:
                    print(f"⏭️ [SKIP] Überspringe Target: {target}")
                    continue
                
                log_rows.append((node_name, target, False, time.time()))
                render_log()

                for key in ("risk_score", "risk_level", "summary", "action_advice",
                            "input_type", "memory_context", "next_agent", "current_check"):
                    if node_state.get(key) is not None:
                        final_state[key] = node_state[key]

                if node_state.get("findings"):
                    all_findings.extend(node_state["findings"])

                for key in ("to_scan", "scanned", "node_timings"):
                    if key in node_state:
                        final_state[key] = node_state[key]

        if log_rows:
            prev = log_rows[-1]
            log_rows[-1] = (prev[0], prev[1], True, prev[3])
        render_log()
        render_timings()

    final_state["findings"] = all_findings
    
    if "node_timings" not in final_state:
        final_state["node_timings"] = node_timings
    
    return final_state


# ── Tab-Render ────────────────────────────────────────────────────────────────

def render_analyse_tab() -> None:
    """Rendert den kompletten Analyse-Pipeline Tab."""
    col_input, col_help = st.columns([3, 1])

    with col_input:
        user_input = st.text_area(
            "Input",
            placeholder=(
                "Domain          →  example.com\n"
                "E-Mail-Adresse  →  user@domain.com\n"
                "E-Mail-Inhalt   →  komplette Mail hier reinkopieren\n"
                "Telefonnummer   →  +49 151 12345678\n"
                "Dateipfad/Hash  →  /pfad/zur/datei.pdf"
            ),
            height=190,
            label_visibility="collapsed",
        )
    with col_help:
        st.markdown("**Unterstützte Inputs**")
        for line in [
            "🌐 Domain / URL", "📧 E-Mail-Adresse", "📨 E-Mail-Inhalt",
            "📞 Telefonnummer", "📄 Datei / Hash", "🔎 Software + Version",
        ]:
            st.caption(line)

    run_col, clear_col, _ = st.columns([1, 1, 4])
    with run_col:
        run_btn = st.button("🔍 Analysieren", type="primary", use_container_width=True)
    with clear_col:
        if st.button("✕ Leeren", use_container_width=True):
            st.session_state.pop("last_result", None)
            st.rerun()

    if run_btn:
        if not user_input or not user_input.strip():
            st.warning("Bitte einen Input eingeben.")
        else:
            t0 = time.time()
            try:
                result  = run_with_live_log(user_input.strip())
                elapsed = round(time.time() - t0, 1)
                st.success(f"✅ Analyse abgeschlossen in {elapsed}s")
            except Exception as e:
                st.error(f"❌ Pipeline-Fehler: {type(e).__name__}: {e}")
                st.stop()

            if "history" not in st.session_state:
                st.session_state["history"] = []
            st.session_state["history"].append({
                "query":      user_input.strip()[:60],
                "risk_level": result.get("risk_level", "UNKNOWN"),
                "score":      result.get("risk_score", 0),
            })
            st.session_state["last_result"] = result

    if "last_result" in st.session_state:
        render_results(st.session_state["last_result"])