import os
import json
from datetime import datetime


def export_html(log: list, name: str = "graph", path: str = None):
    if path is None:
        path = os.path.join(os.getcwd(), "anticipator_graph.html")

    threats        = {r["node"] for r in log if r["scan"]["detected"]}
    threat_records = [r for r in log if r["scan"]["detected"]]
    critical_count = len([r for r in log if r["scan"]["severity"] == "critical"])
    warning_count  = len([r for r in log if r["scan"]["severity"] == "warning"])
    threat_count   = len(threat_records)
    clean_count    = len(log) - threat_count

    seen = []
    for r in log:
        if r["node"] not in seen:
            seen.append(r["node"])
    nodes = seen
    edges = [(seen[i], seen[i+1]) for i in range(len(seen) - 1)]

    node_threats = {}
    for r in log:
        n = r["node"]
        if r["scan"]["detected"]:
            if n not in node_threats:
                node_threats[n] = []
            node_threats[n].append(r["scan"]["severity"].upper() + ": " + r["input_preview"][:80])

    def node_bg(n):     return "#7f1d1d" if n in threats else "#1e3a2f"
    def node_border(n): return "#ef4444" if n in threats else "#22c55e"
    def node_hbg(n):    return "#991b1b" if n in threats else "#166534"
    def node_shadow(n): return "rgba(239,68,68,0.5)" if n in threats else "rgba(34,197,94,0.3)"
    def node_title(n):
        items = node_threats.get(n, [])
        inner = "<br>".join("<b>" + t + "</b>" for t in items[:3]) if items else "<b style='color:#22c55e'>Clean</b>"
        return "<div style='font-family:monospace;padding:8px;max-width:280px;background:#1a1a2e;color:#e2e8f0;border-radius:6px;border:1px solid #334155'>" + inner + "</div>"

    def edge_color(a, b): return "#ef4444" if a in threats or b in threats else "#334155"
    def edge_width(a, b): return "2" if a in threats or b in threats else "1"

    nodes_js = ",\n".join([
        '{ id: "' + n + '", label: "' + n.replace("_", " ") + '",'
        ' color: { background: "' + node_bg(n) + '", border: "' + node_border(n) + '",'
        ' highlight: { background: "' + node_hbg(n) + '", border: "' + node_border(n) + '" } },'
        ' shadow: { enabled: true, color: "' + node_shadow(n) + '", size: 20, x: 0, y: 0 },'
        ' font: { color: "#f1f5f9", size: 12, face: "monospace" },'
        ' shape: "box", margin: 10,'
        ' title: "' + node_title(n).replace('"', "'") + '" }'
        for n in nodes
    ])

    edges_js = ",\n".join([
        '{ from: "' + a + '", to: "' + b + '",'
        ' color: { color: "' + edge_color(a, b) + '", opacity: 0.9 },'
        ' width: ' + edge_width(a, b) + ','
        ' arrows: { to: { enabled: true, scaleFactor: 0.6 } },'
        ' smooth: { type: "cubicBezier", forceDirection: "horizontal" } }'
        for a, b in edges
    ])

    incident_rows = ""
    for r in threat_records[-8:]:
        sev = r["scan"]["severity"]
        if sev == "critical":
            badge = "<span style='background:#7f1d1d;color:#fca5a5;border:1px solid #ef4444;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;letter-spacing:1px'>CRITICAL</span>"
        else:
            badge = "<span style='background:#78350f;color:#fcd34d;border:1px solid #f59e0b;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;letter-spacing:1px'>WARNING</span>"
        ts = datetime.fromtimestamp(r["timestamp"]).strftime("%H:%M:%S")
        incident_rows += (
            "<tr>"
            "<td style='padding:10px 14px;color:#94a3b8;font-size:11px;white-space:nowrap'>" + ts + "</td>"
            "<td style='padding:10px 14px;color:#e2e8f0;font-size:12px'>" + r["node"].replace("_", " ") + "</td>"
            "<td style='padding:10px 14px'>" + badge + "</td>"
            "<td style='padding:10px 14px;color:#64748b;font-size:11px;font-family:monospace;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap'>" + r["input_preview"][:60] + "...</td>"
            "</tr>"
        )

    sev_data    = json.dumps([critical_count, warning_count, clean_count])
    node_names  = json.dumps([n.replace("_", " ") for n in nodes])
    node_counts = json.dumps([len([r for r in log if r["node"] == n and r["scan"]["detected"]]) for n in nodes])
    node_colors = json.dumps(["#ef4444" if n in threats else "#22c55e" for n in nodes])

    html = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Anticipator</title>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=Space+Mono:wght@400;700&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/vis/4.21.0/vis.min.js"></script>
<link  href="https://cdnjs.cloudflare.com/ajax/libs/vis/4.21.0/vis.min.css" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Space Grotesk', sans-serif;
    background: #080b14;
    color: #e2e8f0;
    height: 100vh;
    overflow: hidden;
    background-image: radial-gradient(ellipse at 60% 40%, rgba(127,29,29,0.18) 0%, transparent 60%),
                      radial-gradient(ellipse at 20% 80%, rgba(99,102,241,0.08) 0%, transparent 50%);
  }
  .topbar {
    height: 58px;
    background: rgba(15,20,35,0.95);
    border-bottom: 1px solid rgba(255,255,255,0.06);
    display: flex;
    align-items: center;
    padding: 0 28px;
    gap: 20px;
    backdrop-filter: blur(10px);
  }
  .logo { font-size: 18px; font-weight: 700; color: #fff; letter-spacing: -0.5px; }
  .logo span { color: #ef4444; }
  .logo-sub { font-size: 10px; color: #475569; margin-left: 12px; font-family: 'Space Mono', monospace; }
  .pipeline-pill {
    margin-left: auto;
    background: rgba(255,255,255,0.05);
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 20px;
    padding: 5px 14px;
    font-size: 12px;
    color: #94a3b8;
  }
  .pipeline-pill b { color: #e2e8f0; }
  .status-dot {
    width: 8px; height: 8px; border-radius: 50%;
    background: #22c55e;
    box-shadow: 0 0 8px #22c55e;
    animation: pulse 2s infinite;
    margin-left: 16px;
  }
  .status-label { font-size: 11px; color: #22c55e; margin-left: 6px; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
  .layout { display: grid; grid-template-columns: 1fr 380px; height: calc(100vh - 58px); gap: 1px; background: rgba(255,255,255,0.04); }
  .panel { background: #0d1220; padding: 20px 24px; overflow: hidden; display: flex; flex-direction: column; gap: 16px; }
  .panel-right { background: #0a0f1c; padding: 20px; overflow-y: auto; display: flex; flex-direction: column; gap: 14px; }
  .bubbles { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }
  .bubble {
    background: rgba(255,255,255,0.03);
    border: 1px solid rgba(255,255,255,0.06);
    border-radius: 16px;
    padding: 18px 16px;
    position: relative;
    overflow: hidden;
  }
  .bubble::before {
    content: '';
    position: absolute;
    top: -30px; right: -30px;
    width: 80px; height: 80px;
    border-radius: 50%;
    opacity: 0.12;
  }
  .bubble.red::before    { background: #ef4444; }
  .bubble.yellow::before { background: #f59e0b; }
  .bubble.green::before  { background: #22c55e; }
  .bubble.indigo::before { background: #6366f1; }
  .bubble .num  { font-size: 36px; font-weight: 700; line-height: 1; font-family: 'Space Mono', monospace; }
  .bubble.red    .num { color: #f87171; }
  .bubble.yellow .num { color: #fbbf24; }
  .bubble.green  .num { color: #4ade80; }
  .bubble.indigo .num { color: #818cf8; }
  .bubble .lbl { font-size: 11px; color: #475569; margin-top: 6px; text-transform: uppercase; letter-spacing: 0.8px; }
  .bubble .sub { font-size: 10px; color: #334155; margin-top: 3px; }
  .graph-container { flex: 1; border-radius: 12px; overflow: hidden; background: #080b14; position: relative; border: 1px solid rgba(255,255,255,0.05); }
  #graph { width: 100%; height: 100%; }
  .graph-label { position: absolute; top: 12px; left: 16px; font-size: 11px; color: #334155; text-transform: uppercase; letter-spacing: 1px; z-index: 10; font-family: 'Space Mono', monospace; }
  .chart-box { background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.05); border-radius: 12px; padding: 16px; }
  .chart-box .chart-title { font-size: 12px; font-weight: 600; color: #94a3b8; margin-bottom: 12px; }
  .chart-wrap { height: 130px; position: relative; }
  .incident-box { background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.05); border-radius: 12px; overflow: hidden; }
  .incident-header { padding: 12px 16px; border-bottom: 1px solid rgba(255,255,255,0.05); font-size: 12px; font-weight: 600; color: #94a3b8; text-transform: uppercase; letter-spacing: 1px; display: flex; justify-content: space-between; align-items: center; }
  .incident-count { background: #7f1d1d; color: #fca5a5; border-radius: 10px; padding: 1px 8px; font-size: 11px; }
  table { width: 100%; border-collapse: collapse; font-size: 12px; }
  td { padding: 9px 14px; border-bottom: 1px solid rgba(255,255,255,0.04); vertical-align: middle; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: rgba(255,255,255,0.02); }
  .empty { text-align: center; padding: 24px; color: #334155; font-size: 13px; }
</style>
</head>
<body>
<div class="topbar">
  <div class="logo">Antici<span>p</span>ator</div>
  <div class="logo-sub">MULTI-AGENT RUNTIME SECURITY</div>
  <div class="pipeline-pill">Pipeline: <b>""" + name + """</b></div>
  <div class="status-dot"></div>
  <div class="status-label">Live</div>
</div>
<div class="layout">
  <div class="panel">
    <div class="bubbles">
      <div class="bubble indigo">
        <div class="num">""" + str(len(log)) + """</div>
        <div class="lbl">Total Scanned</div>
        <div class="sub">messages intercepted</div>
      </div>
      <div class="bubble red">
        <div class="num">""" + str(threat_count) + """</div>
        <div class="lbl">Threats</div>
        <div class="sub">detected this session</div>
      </div>
      <div class="bubble yellow">
        <div class="num">""" + str(critical_count) + """</div>
        <div class="lbl">Critical</div>
        <div class="sub">immediate action needed</div>
      </div>
      <div class="bubble green">
        <div class="num">""" + str(clean_count) + """</div>
        <div class="lbl">Clean</div>
        <div class="sub">no threats found</div>
      </div>
    </div>
    <div class="graph-container">
      <div class="graph-label">Agent Pipeline Topology</div>
      <div id="graph"></div>
    </div>
    <div class="incident-box">
      <div class="incident-header">
        Incident Log
        <span class="incident-count">""" + str(threat_count) + """ threats</span>
      </div>
      """ + (
        '<table><tbody>' + incident_rows + '</tbody></table>'
        if incident_rows else
        '<div class="empty">No threats detected this session</div>'
      ) + """
    </div>
  </div>
  <div class="panel-right">
    <div class="chart-box">
      <div class="chart-title">Severity Breakdown</div>
      <div class="chart-wrap"><canvas id="donutChart"></canvas></div>
    </div>
    <div class="chart-box">
      <div class="chart-title">Threats per Agent</div>
      <div class="chart-wrap"><canvas id="barChart"></canvas></div>
    </div>
    <div class="chart-box" style="flex:1">
      <div class="chart-title">Legend</div>
      <div style="display:flex;flex-direction:column;gap:10px;margin-top:8px">
        <div style="display:flex;align-items:center;gap:10px;font-size:12px;color:#94a3b8">
          <div style="width:12px;height:12px;border-radius:3px;background:#7f1d1d;border:1.5px solid #ef4444"></div>
          Threat detected node
        </div>
        <div style="display:flex;align-items:center;gap:10px;font-size:12px;color:#94a3b8">
          <div style="width:12px;height:12px;border-radius:3px;background:#1e3a2f;border:1.5px solid #22c55e"></div>
          Clean node
        </div>
        <div style="display:flex;align-items:center;gap:10px;font-size:12px;color:#94a3b8">
          <div style="width:24px;height:2px;background:#ef4444"></div>
          Threat propagation path
        </div>
        <div style="display:flex;align-items:center;gap:10px;font-size:12px;color:#94a3b8">
          <div style="width:24px;height:2px;background:#334155"></div>
          Clean message path
        </div>
      </div>
    </div>
  </div>
</div>
<script>
  new Chart(document.getElementById('donutChart'), {
    type: 'doughnut',
    data: {
      labels: ['Critical', 'Warning', 'Clean'],
      datasets: [{
        data: """ + sev_data + """,
        backgroundColor: ['#ef4444','#f59e0b','#22c55e'],
        borderColor: ['#7f1d1d','#78350f','#166534'],
        borderWidth: 1,
        hoverOffset: 6
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false, cutout: '70%',
      plugins: {
        legend: { position: 'right', labels: { color: '#64748b', font: { family: 'Space Grotesk', size: 11 }, padding: 12, boxWidth: 10 } }
      }
    }
  });
  new Chart(document.getElementById('barChart'), {
    type: 'bar',
    data: {
      labels: """ + node_names + """,
      datasets: [{ data: """ + node_counts + """, backgroundColor: """ + node_colors + """, borderRadius: 6, borderSkipped: false }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { display: false }, ticks: { color: '#475569', font: { size: 10 } }, border: { display: false } },
        y: { grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { color: '#475569', font: { size: 10 }, stepSize: 1 }, beginAtZero: true, border: { display: false } }
      }
    }
  });
  var visNodes = new vis.DataSet([""" + nodes_js + """]);
  var visEdges = new vis.DataSet([""" + edges_js + """]);
  new vis.Network(document.getElementById('graph'), { nodes: visNodes, edges: visEdges }, {
    layout: { hierarchical: { enabled: true, direction: 'LR', levelSeparation: 180, nodeSpacing: 90 } },
    physics: false,
    nodes: { borderWidth: 2, font: { size: 12 }, margin: { top: 10, bottom: 10, left: 14, right: 14 } },
    edges: { smooth: { type: 'cubicBezier', forceDirection: 'horizontal' } },
    interaction: { hover: true, tooltipDelay: 80, zoomView: true, dragView: true }
  });
</script>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[ANTICIPATOR] Dashboard exported -> {path}")
    return path