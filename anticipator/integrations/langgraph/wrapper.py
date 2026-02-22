import threading
from anticipator.integrations.langgraph.interceptor import wrap_node, get_message_log
from anticipator.integrations.exporter import export_json
from anticipator.integrations.monitor import print_summary, query as db_query


class ObservableGraph:
    def __init__(self, graph, name: str = "langgraph"):
        self._graph = graph
        self._name  = name
        self._patch_done = threading.Event()
        threading.Thread(target=self._patch_nodes, daemon=True).start()

    def _patch_nodes(self):
        patched = 0
        nodes = getattr(self._graph, "nodes", None)
        if isinstance(nodes, dict):
            for node_name, spec in list(nodes.items()):
                if node_name in ("__start__", "__end__"):
                    continue
                if hasattr(spec, "runnable") and hasattr(spec.runnable, "func"):
                    if not getattr(spec.runnable.func, "__wrapped_node__", False):
                        spec.runnable.func = wrap_node(node_name, spec.runnable.func, self._name)
                        patched += 1
                elif callable(spec):
                    if not getattr(spec, "__wrapped_node__", False):
                        nodes[node_name] = wrap_node(node_name, spec, self._name)
                        patched += 1
        _print_banner(self._name, patched)
        self._patched = patched > 0
        self._patch_done.set()

    def compile(self, **kwargs):
        self._patch_done.wait()
        compiled = self._graph.compile(**kwargs)
        return _CompiledGraph(compiled, self._name)

    def __getattr__(self, name):
        return getattr(self._graph, name)


class _CompiledGraph:
    def __init__(self, compiled, name):
        self._compiled = compiled
        self._name     = name

    def invoke(self, input, config=None):
        return self._compiled.invoke(input, config) if config else self._compiled.invoke(input)

    async def ainvoke(self, input, config=None):
        return await (self._compiled.ainvoke(input, config) if config else self._compiled.ainvoke(input))

    def stream(self, input, config=None):
        return self._compiled.stream(input, config) if config else self._compiled.stream(input)

    def get_log(self):
        return get_message_log()

    def get_threats(self):
        return [r for r in get_message_log() if r["scan"]["detected"]]

    def report(self):
        _print_report(self._name)

    def monitor(self, last: str = None):
        print_summary(graph=self._name, last=last)

    def query(self, node=None, severity=None, last=None, limit=50):
        return db_query(graph=self._name, node=node, severity=severity, last=last, limit=limit)

    def export_report(self, path=None):
        return export_json(log=get_message_log(), name=self._name, path=path)

    def __getattr__(self, name):
        return getattr(self._compiled, name)


RESET  = "\033[0m";  BOLD   = "\033[1m";  DIM    = "\033[2m"
RED    = "\033[91m"; GREEN  = "\033[92m"; YELLOW = "\033[93m"
CYAN   = "\033[96m"; WHITE  = "\033[97m"; BG_RED = "\033[41m"


def _sev_color(s):
    return {"critical": f"{BG_RED}{WHITE}{BOLD}", "warning": f"{YELLOW}{BOLD}", "none": GREEN}.get(s, RESET)


def _print_banner(name, patched):
    ok = f"{GREEN}{patched} node(s) patched{RESET}" if patched else f"{RED}0 nodes patched{RESET}"
    print(f"\n{CYAN}{BOLD}┌─ ANTICIPATOR {'─'*30}┐{RESET}")
    print(f"{CYAN}│{RESET}  Graph : {BOLD}{name}{RESET}")
    print(f"{CYAN}│{RESET}  Nodes : {ok}")
    print(f"{CYAN}└{'─'*46}┘{RESET}\n")


def _print_report(name):
    log     = get_message_log()
    threats = [r for r in log if r["scan"]["detected"]]
    print(f"\n{CYAN}{BOLD}╔══ ANTICIPATOR REPORT {'═'*34}╗{RESET}")
    print(f"{CYAN}║{RESET}  Graph   : {BOLD}{name}{RESET}")
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


def observe(graph, name: str = "langgraph") -> ObservableGraph:
    return ObservableGraph(graph, name)