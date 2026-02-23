import json
import logging
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Dict, Generator, List, Optional

log = logging.getLogger(__name__)

DB_PATH = os.path.join(os.path.expanduser("~"), ".anticipator", "anticipator.db")



@contextmanager
def _connect() -> Generator[sqlite3.Connection, None, None]:

    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row

    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")   # safe + faster than FULL
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    """Create tables and indexes if they don't already exist."""
    try:
        with _connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp     TEXT    NOT NULL,
                    framework     TEXT    NOT NULL,
                    graph         TEXT    NOT NULL,
                    node          TEXT    NOT NULL,
                    severity      TEXT    NOT NULL,
                    detected      INTEGER NOT NULL,
                    input_preview TEXT    NOT NULL,
                    scan_json     TEXT    NOT NULL
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS delegations (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    framework TEXT NOT NULL,
                    graph     TEXT NOT NULL,
                    from_node TEXT NOT NULL,
                    to_node   TEXT NOT NULL
                )
            """)

            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_scans_timestamp"
                " ON scans(timestamp)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_scans_framework"
                " ON scans(framework)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_scans_graph"
                " ON scans(graph)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_scans_severity"
                " ON scans(severity)"
            )
    except Exception as exc:
        log.error("[ANTICIPATOR] init_db failed: %s", exc)


try:
    init_db()
except Exception as _init_exc:
    log.warning("[ANTICIPATOR] Could not initialise DB at import: %s", _init_exc)


def write_scan(
    framework: str,
    graph: str,
    node: str,
    scan_result: dict,
    input_preview: str,
) -> None:
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO scans
              (timestamp, framework, graph, node, severity,
               detected, input_preview, scan_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.utcnow().isoformat(),
                framework,
                graph,
                node,
                scan_result.get("severity", "none"),
                1 if scan_result.get("detected") else 0,
                input_preview[:200],
                json.dumps(scan_result),
            ),
        )


def write_delegation(
    framework: str,
    graph: str,
    from_node: str,
    to_node: str,
) -> None:
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO delegations
              (timestamp, framework, graph, from_node, to_node)
            VALUES (?, ?, ?, ?, ?)
            """,
            (datetime.utcnow().isoformat(), framework, graph, from_node, to_node),
        )


_UNIT_MAP: dict[str, str] = {
    "m": "minutes",
    "h": "hours",
    "d": "days",
    "w": "weeks",
}


def _parse_since(last: str) -> datetime:

    if not last or len(last) < 2:
        raise ValueError(f"Invalid duration string: {last!r}")

    unit  = last[-1].lower()
    try:
        value = int(last[:-1])
    except ValueError:
        raise ValueError(f"Invalid duration value in: {last!r}")

    if unit not in _UNIT_MAP:
        raise ValueError(
            f"Unknown time unit {unit!r} in {last!r}. "
            f"Use one of: {', '.join(_UNIT_MAP)}"
        )

    return datetime.utcnow() - timedelta(**{_UNIT_MAP[unit]: value})


def _build_where(
    framework: Optional[str] = None,
    graph:     Optional[str] = None,
    node:      Optional[str] = None,
    severity:  Optional[str] = None,
    last:      Optional[str] = None,
    detected:  Optional[bool] = None,   
) -> tuple[str, list]:

    clauses: list[str] = []
    params:  list      = []

    if framework is not None:
        clauses.append("framework = ?");  params.append(framework)
    if graph is not None:
        clauses.append("graph = ?");      params.append(graph)
    if node is not None:
        clauses.append("node = ?");       params.append(node)
    if severity is not None:
        clauses.append("severity = ?");   params.append(severity)
    if last is not None:
        clauses.append("timestamp >= ?"); params.append(_parse_since(last).isoformat())
    if detected is not None:
        clauses.append("detected = ?");   params.append(1 if detected else 0)

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    return where, params


def query(
    framework: Optional[str] = None,
    graph:     Optional[str] = None,
    node:      Optional[str] = None,
    severity:  Optional[str] = None,
    last:      Optional[str] = None,
    limit:     int = 100,
) -> List[Dict]:
    where, params = _build_where(
        framework=framework, graph=graph, node=node,
        severity=severity,   last=last,
    )
    with _connect() as conn:
        rows = conn.execute(
            f"SELECT * FROM scans {where} ORDER BY timestamp DESC LIMIT ?",
            params + [limit],
        ).fetchall()
    return [dict(r) for r in rows]


def summary(
    framework: Optional[str] = None,
    graph:     Optional[str] = None,
    last:      Optional[str] = None,
) -> Dict:
    w_all,  p_all  = _build_where(framework=framework, graph=graph, last=last)
    w_thr,  p_thr  = _build_where(framework=framework, graph=graph, last=last, detected=True)
    w_crit, p_crit = _build_where(framework=framework, graph=graph, last=last,
                                   detected=True, severity="critical")
    w_warn, p_warn = _build_where(framework=framework, graph=graph, last=last,
                                   severity="warning")

    with _connect() as conn:
        total    = conn.execute(f"SELECT COUNT(*) FROM scans {w_all}",  p_all ).fetchone()[0]
        threats  = conn.execute(f"SELECT COUNT(*) FROM scans {w_thr}",  p_thr ).fetchone()[0]
        critical = conn.execute(f"SELECT COUNT(*) FROM scans {w_crit}", p_crit).fetchone()[0]
        warning  = conn.execute(f"SELECT COUNT(*) FROM scans {w_warn}", p_warn).fetchone()[0]

        top_nodes = conn.execute(
            f"""
            SELECT node, COUNT(*) AS c
            FROM   scans {w_thr}
            GROUP  BY node
            ORDER  BY c DESC
            LIMIT  5
            """,
            p_thr,
        ).fetchall()

    return {
        "total":    total,
        "threats":  threats,
        "critical": critical,
        "warning":  warning,
        "clean":    total - threats,
        "top_threat_nodes": [
            {"node": r["node"], "count": r["c"]} for r in top_nodes
        ],
    }


def print_summary(
    framework: Optional[str] = None,
    graph:     Optional[str] = None,
    last:      Optional[str] = None,
) -> None:
    s = summary(framework=framework, graph=graph, last=last)

    RESET  = "\033[0m"; BOLD   = "\033[1m"
    RED    = "\033[91m"; GREEN  = "\033[92m"; YELLOW = "\033[93m"
    CYAN   = "\033[96m"; WHITE  = "\033[97m"; BG_RED = "\033[41m"

    period = f" (last {last})" if last else " (all time)"
    print(f"\n{CYAN}{BOLD}╔══ ANTICIPATOR DB MONITOR{period} {'═'*28}╗{RESET}")
    print(f"{CYAN}║{RESET}  DB            : anticipator.db")
    print(f"{CYAN}║{RESET}  Total scanned : {BOLD}{s['total']}{RESET}")
    print(f"{CYAN}║{RESET}  Threats       : {RED}{BOLD}{s['threats']}{RESET}")
    print(f"{CYAN}║{RESET}  Critical      : {BG_RED}{WHITE}{BOLD}{s['critical']}{RESET}")
    print(f"{CYAN}║{RESET}  Warning       : {YELLOW}{BOLD}{s['warning']}{RESET}")
    print(f"{CYAN}║{RESET}  Clean         : {GREEN}{s['clean']}{RESET}")

    if s["top_threat_nodes"]:
        print(f"{CYAN}╠{'═'*56}╣{RESET}")
        print(f"{CYAN}║{RESET}  Top threat nodes:")
        for t in s["top_threat_nodes"]:
            print(f"{CYAN}║{RESET}    {RED}•{RESET} {t['node']} — {BOLD}{t['count']}{RESET} hits")

    print(f"{CYAN}╚{'═'*56}╝{RESET}\n")