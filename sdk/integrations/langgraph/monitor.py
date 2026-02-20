"""
Persistent SQLite Monitor
Every scan is written to anticipator.db and accumulates forever.
Survives restarts, works across sessions, 365 days.
"""
import sqlite3
import json
import os
from datetime import datetime, timedelta
from typing import Optional

DB_PATH = os.path.join(os.path.dirname(__file__), "anticipator.db")


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = _connect()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp     TEXT    NOT NULL,
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
            graph     TEXT NOT NULL,
            from_node TEXT NOT NULL,
            to_node   TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON scans(timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_graph     ON scans(graph)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_severity  ON scans(severity)")
    conn.commit()
    conn.close()


def write_scan(graph: str, node: str, scan_result: dict, input_preview: str):
    conn = _connect()
    conn.execute(
        "INSERT INTO scans (timestamp, graph, node, severity, detected, input_preview, scan_json) VALUES (?,?,?,?,?,?,?)",
        (
            datetime.now().isoformat(),
            graph,
            node,
            scan_result.get("severity", "none"),
            1 if scan_result.get("detected") else 0,
            input_preview[:200],
            json.dumps(scan_result),
        )
    )
    conn.commit()
    conn.close()


def write_delegation(graph: str, from_node: str, to_node: str):
    conn = _connect()
    conn.execute(
        "INSERT INTO delegations (timestamp, graph, from_node, to_node) VALUES (?,?,?,?)",
        (datetime.now().isoformat(), graph, from_node, to_node)
    )
    conn.commit()
    conn.close()


def _build_where(graph=None, node=None, severity=None, last=None, extra=None):
    clauses = []
    params  = []
    if graph:
        clauses.append("graph = ?")
        params.append(graph)
    if node:
        clauses.append("node = ?")
        params.append(node)
    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    if last:
        clauses.append("timestamp >= ?")
        params.append(_parse_since(last).isoformat())
    if extra:
        clauses.append(extra)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    return where, params


def _parse_since(last: str) -> datetime:
    now   = datetime.now()
    unit  = last[-1]
    value = int(last[:-1])
    if unit == "h": return now - timedelta(hours=value)
    if unit == "d": return now - timedelta(days=value)
    if unit == "y": return now - timedelta(days=value * 365)
    return now - timedelta(days=7)


# ── Query API ────────────────────────────────────────────────────

def query(graph=None, node=None, severity=None, last=None, limit=100):
    where, params = _build_where(graph=graph, node=node, severity=severity, last=last)
    conn = _connect()
    rows = conn.execute(
        f"SELECT * FROM scans {where} ORDER BY timestamp DESC LIMIT ?",
        params + [limit]
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def summary(graph=None, last=None):
    conn = _connect()

    where_all,      p_all      = _build_where(graph=graph, last=last)
    where_threat,   p_threat   = _build_where(graph=graph, last=last, extra="detected = 1")
    where_critical, p_critical = _build_where(graph=graph, last=last, extra="severity = 'critical'")
    where_warning,  p_warning  = _build_where(graph=graph, last=last, extra="severity = 'warning'")
    where_top,      p_top      = _build_where(graph=graph, last=last, extra="detected = 1")

    total    = conn.execute(f"SELECT COUNT(*) FROM scans {where_all}",      p_all).fetchone()[0]
    threats  = conn.execute(f"SELECT COUNT(*) FROM scans {where_threat}",   p_threat).fetchone()[0]
    critical = conn.execute(f"SELECT COUNT(*) FROM scans {where_critical}", p_critical).fetchone()[0]
    warning  = conn.execute(f"SELECT COUNT(*) FROM scans {where_warning}",  p_warning).fetchone()[0]

    top_nodes = conn.execute(
        f"SELECT node, COUNT(*) as c FROM scans {where_top} GROUP BY node ORDER BY c DESC LIMIT 5",
        p_top
    ).fetchall()

    conn.close()
    return {
        "total":    total,
        "threats":  threats,
        "critical": critical,
        "warning":  warning,
        "clean":    total - threats,
        "top_threat_nodes": [{"node": r["node"], "count": r["c"]} for r in top_nodes],
    }


def print_summary(graph=None, last=None):
    s = summary(graph, last)

    RESET  = "\033[0m"; BOLD   = "\033[1m"
    RED    = "\033[91m"; GREEN  = "\033[92m"; YELLOW = "\033[93m"
    CYAN   = "\033[96m"; WHITE  = "\033[97m"; BG_RED = "\033[41m"

    period = f" (last {last})" if last else " (all time)"
    print(f"\n{CYAN}{BOLD}╔══ ANTICIPATOR DB MONITOR{period} {'═'*28}╗{RESET}")
    print(f"{CYAN}║{RESET}  DB            : anticipator.db")
    print(f"{CYAN}║{RESET}  Total scanned : {BOLD}{s['total']}{RESET}")
    print(f"{CYAN}║{RESET}  Threats       : {RED+BOLD}{s['threats']}{RESET}")
    print(f"{CYAN}║{RESET}  Critical      : {BG_RED+WHITE+BOLD}{s['critical']}{RESET}")
    print(f"{CYAN}║{RESET}  Warning       : {YELLOW+BOLD}{s['warning']}{RESET}")
    print(f"{CYAN}║{RESET}  Clean         : {GREEN}{s['clean']}{RESET}")

    if s["top_threat_nodes"]:
        print(f"{CYAN}╠{'═'*56}╣{RESET}")
        print(f"{CYAN}║{RESET}  Top threat nodes:")
        for t in s["top_threat_nodes"]:
            print(f"{CYAN}║{RESET}    {RED}•{RESET} {t['node']} — {BOLD}{t['count']}{RESET} hits")

    print(f"{CYAN}╚{'═'*56}╝{RESET}\n")


# Init on import
init_db()
