"""
CrewAI ObservableCrew wrapper.
Wraps before kickoff() — same pattern as LangGraph.

Usage:
    from integrations.crewai import observe

    crew   = Crew(agents=[...], tasks=[...])
    secure = observe(crew, name="my_pipeline")
    result = secure.kickoff()
"""
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), "../../src"))

from interceptor import wrap_agent, get_message_log, clear_message_log


class ObservableCrew:
    def __init__(self, crew, name: str = "crewai"):
        self._crew = crew
        self._name = name
        self._patch_agents()

    def _patch_agents(self):
        agents  = getattr(self._crew, "agents", [])
        patched = 0
        for agent in agents:
            wrap_agent(agent, self._name)
            patched += 1
        _print_banner(self._name, patched)

    def kickoff(self, inputs=None):
        if inputs is not None:
            return self._crew.kickoff(inputs=inputs)
        return self._crew.kickoff()

    async def kickoff_async(self, inputs=None):
        if inputs is not None:
            return await self._crew.kickoff_async(inputs=inputs)
        return await self._crew.kickoff_async()

    def get_log(self):
        return get_message_log()

    def get_threats(self):
        return [r for r in get_message_log() if r["scan"]["detected"]]

    def report(self):
        _print_report(self._name)

    def monitor(self, last=None):
        from monitor import print_summary
        print_summary(graph=self._name, last=last)

    def query(self, node=None, severity=None, last=None, limit=50):
        from monitor import query
        return query(graph=self._name, node=node, severity=severity, last=last, limit=limit)

    def export_graph(self, path="anticipator_crewai.html"):
        from visualizer import export_html
        return export_html(self._name, path)

    def export_report(self, path="anticipator_crewai.json"):
        from exporter import export_json
        return export_json(self._name, path)

    def __getattr__(self, name):
        return getattr(self._crew, name)


# ── Colors ───────────────────────────────────────────────────────
RESET  = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
RED    = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"
CYAN   = "\033[96m"; WHITE = "\033[97m"; BG_RED = "\033[41m"


def _sev_color(s):
    return {"critical": f"{BG_RED}{WHITE}{BOLD}", "warning": f"{YELLOW}{BOLD}", "none": GREEN}.get(s, RESET)


def _print_banner(name, patched):
    ok = f"{GREEN}{patched} agent(s) patched{RESET}" if patched else f"{RED}0 agents patched{RESET}"
    print(f"\n{CYAN}{BOLD}┌─ ANTICIPATOR (CrewAI) {'─'*24}┐{RESET}")
    print(f"{CYAN}│{RESET}  Crew   : {BOLD}{name}{RESET}")
    print(f"{CYAN}│{RESET}  Agents : {ok}")
    print(f"{CYAN}└{'─'*46}┘{RESET}\n")


def _print_report(name):
    log     = get_message_log()
    threats = [r for r in log if r["scan"]["detected"]]

    print(f"\n{CYAN}{BOLD}╔══ ANTICIPATOR REPORT (CrewAI) {'═'*25}╗{RESET}")
    print(f"{CYAN}║{RESET}  Crew    : {BOLD}{name}{RESET}")
    print(f"{CYAN}║{RESET}  Scanned : {BOLD}{len(log)} messages{RESET}")
    print(f"{CYAN}║{RESET}  Threats : {(RED+BOLD) if threats else GREEN}{len(threats)}{RESET}")
    print(f"{CYAN}╠{'═'*56}╣{RESET}")

    if not threats:
        print(f"{CYAN}║{RESET}  {GREEN}All clear — no threats detected{RESET}")
    else:
        seen = {}
        for t in threats:
            key = t["input_preview"][:65]
            if key not in seen:
                seen[key] = {"nodes": [], "scan": t["scan"]}
            seen[key]["nodes"].append(t["node"])
        for i, (preview, data) in enumerate(seen.items(), 1):
            col       = _sev_color(data["scan"]["severity"])
            node_path = " -> ".join(data["nodes"])
            print(f"{CYAN}║{RESET}  {col}[{i}] {data['scan']['severity'].upper()}{RESET}  ->  {BOLD}{node_path}{RESET}")
            print(f"{CYAN}║{RESET}      {DIM}{preview}{RESET}")
            print(f"{CYAN}║{RESET}")

    print(f"{CYAN}╚{'═'*56}╝{RESET}\n")