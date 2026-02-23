import hashlib
import warnings

from anticipator.integrations.langgraph.interceptor import (
    wrap_node,
    get_message_log,
    clear_message_log,
)
from anticipator.integrations.exporter import export_json
from anticipator.integrations.monitor import print_summary, query as db_query

RESET  = "\033[0m";  BOLD   = "\033[1m";  DIM    = "\033[2m"
RED    = "\033[91m"; GREEN  = "\033[92m"; YELLOW = "\033[93m"
CYAN   = "\033[96m"; WHITE  = "\033[97m"; BG_RED = "\033[41m"


def _sev_color(s: str) -> str:
    return {
        "critical": f"{BG_RED}{WHITE}{BOLD}",
        "high":     f"{RED}{BOLD}",
        "warning":  f"{YELLOW}{BOLD}",
        "none":     GREEN,
    }.get(s, RESET)



def _patch_graph(graph, name: str) -> int:

    patched = 0
    nodes = getattr(graph, "nodes", None)
    if not nodes:
        return patched

    for node_name, spec in list(nodes.items()):
        if node_name in ("__start__", "__end__"):
            continue

        if hasattr(spec, "runnable") and hasattr(spec.runnable, "func"):
            fn = spec.runnable.func
            if not getattr(fn, "__wrapped_node__", False):
                spec.runnable.func = wrap_node(node_name, fn, name)
                patched += 1
            continue

        if callable(spec):
            if not getattr(spec, "__wrapped_node__", False):
                try:
                    nodes[node_name] = wrap_node(node_name, spec, name)
                    patched += 1
                except (TypeError, AttributeError):
                    warnings.warn(
                        f"[ANTICIPATOR] Could not patch node '{node_name}' "
                        f"(nodes dict is read-only). "
                        f"Use the runnable.func form or upgrade LangGraph.",
                        stacklevel=4,
                    )

    return patched


class _AnticipatorMixin:

    def get_log(self) -> list:
        return get_message_log()

    def get_threats(self) -> list:
        return [r for r in get_message_log() if r["scan"]["detected"]]

    def clear_log(self) -> None:
        clear_message_log()

    def report(self) -> None:
        _print_report(self._name)

    def monitor(self, last: str = None) -> None:
        print_summary(graph=self._name, last=last)

    def query(self, node=None, severity=None, last=None, limit: int = 50) -> list:
        return db_query(
            graph=self._name, node=node,
            severity=severity, last=last, limit=limit,
        )

    def export_report(self, path: str = None) -> str:
        return export_json(log=get_message_log(), name=self._name, path=path)



class ObservableGraph(_AnticipatorMixin):

    def __init__(self, graph, name: str = "langgraph"):
        self._graph = graph
        self._name  = name
        patched = _patch_graph(graph, name)
        _print_banner(name, patched)

    def compile(self, **kwargs) -> "_CompiledGraph":
        compiled = self._graph.compile(**kwargs)
        return _CompiledGraph(compiled, self._name)

    def __getattr__(self, name: str):
        return getattr(self._graph, name)


class _CompiledGraph(_AnticipatorMixin):

    def __init__(self, compiled, name: str):
        self._compiled = compiled
        self._name     = name

    def invoke(self, input, config=None):
        if config is not None:
            return self._compiled.invoke(input, config)
        return self._compiled.invoke(input)

    async def ainvoke(self, input, config=None):
        if config is not None:
            return await self._compiled.ainvoke(input, config)
        return await self._compiled.ainvoke(input)

    def stream(self, input, config=None):

        if config is not None:
            return self._compiled.stream(input, config)
        return self._compiled.stream(input)

    async def astream(self, input, config=None):
        if config is not None:
            async for chunk in self._compiled.astream(input, config):
                yield chunk
        else:
            async for chunk in self._compiled.astream(input):
                yield chunk

    def __getattr__(self, name: str):
        return getattr(self._compiled, name)



def _print_banner(name: str, patched: int) -> None:
    ok = (
        f"{GREEN}{patched} node(s) patched{RESET}"
        if patched
        else f"{RED}0 nodes patched — check graph structure{RESET}"
    )
    print(f"\n{CYAN}{BOLD}┌─ ANTICIPATOR {'─'*30}┐{RESET}")
    print(f"{CYAN}│{RESET}  Graph : {BOLD}{name}{RESET}")
    print(f"{CYAN}│{RESET}  Nodes : {ok}")
    print(f"{CYAN}└{'─'*46}┘{RESET}\n")


def _print_report(name: str) -> None:
    log     = get_message_log()
    threats = [r for r in log if r["scan"]["detected"]]

    print(f"\n{CYAN}{BOLD}╔══ ANTICIPATOR REPORT {'═'*34}╗{RESET}")
    print(f"{CYAN}║{RESET}  Graph   : {BOLD}{name}{RESET}")
    print(f"{CYAN}║{RESET}  Scanned : {BOLD}{len(log)} messages{RESET}")
    thr_col = f"{RED}{BOLD}" if threats else GREEN
    print(f"{CYAN}║{RESET}  Threats : {thr_col}{len(threats)}{RESET}")
    print(f"{CYAN}╠{'═'*56}╣{RESET}")

    if not threats:
        print(f"{CYAN}║{RESET}  {GREEN}All clear — no threats detected{RESET}")
    else:

        seen: dict = {}
        for t in threats:
            key = hashlib.sha256(t["input_preview"].encode()).hexdigest()
            if key not in seen:
                seen[key] = {
                    "nodes":   [],
                    "scan":    t["scan"],
                    "preview": t["input_preview"][:65],
                }
            seen[key]["nodes"].append(t["node"])

        for i, data in enumerate(seen.values(), 1):
            col       = _sev_color(data["scan"]["severity"])
            node_path = " → ".join(data["nodes"])
            print(
                f"{CYAN}║{RESET}  {col}[{i}] "
                f"{data['scan']['severity'].upper()}{RESET}"
                f"  →  {BOLD}{node_path}{RESET}"
            )
            print(f"{CYAN}║{RESET}      {DIM}{data['preview']}{RESET}")
            print(f"{CYAN}║{RESET}")

    print(f"{CYAN}╚{'═'*56}╝{RESET}\n")



def observe(graph, name: str = "langgraph") -> ObservableGraph:
    """Wrap a LangGraph StateGraph with Anticipator threat detection."""
    return ObservableGraph(graph, name)