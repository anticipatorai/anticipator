from interceptor import get_message_log


def export_html(name: str = "graph", path: str = "anticipator_graph.html"):
    log     = get_message_log()
    threats = {r["node"] for r in log if r["scan"]["detected"]}

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

    # Pre-compute per-node values to avoid backslashes in f-strings
    def node_bg(n):     return "#ff4444" if n in threats else "#1e88e5"
    def node_border(n): return "#cc0000" if n in threats else "#1565c0"
    def node_hbg(n):    return "#ff6666" if n in threats else "#42a5f5"
    def node_shadow(n): return "rgba(255,0,0,0.4)" if n in threats else "rgba(30,136,229,0.3)"
    def node_title(n):
        items = node_threats.get(n, [])
        if items:
            inner = "<br>".join("<b>" + t + "</b>" for t in items[:3])
        else:
            inner = "<b style='color:#56d364'>Clean</b>"
        return "<div style='font-family:Segoe UI;padding:8px;max-width:300px'>" + inner + "</div>"

    def edge_color(a, b): return "#ff4444" if a in threats or b in threats else "#42a5f5"
    def edge_width(a, b): return "2.5" if a in threats or b in threats else "1.5"

    nodes_js = ",\n".join([
        '{ id: "' + n + '", label: "' + n + '",'
        ' color: { background: "' + node_bg(n) + '", border: "' + node_border(n) + '",'
        ' highlight: { background: "' + node_hbg(n) + '", border: "' + node_border(n) + '" } },'
        ' shadow: { enabled: true, color: "' + node_shadow(n) + '", size: 15 },'
        ' font: { color: "#ffffff", size: 13, face: "Segoe UI" },'
        ' shape: "box", margin: 12,'
        ' title: "' + node_title(n).replace('"', "'") + '" }'
        for n in nodes
    ])

    edges_js = ",\n".join([
        '{ from: "' + a + '", to: "' + b + '",'
        ' color: { color: "' + edge_color(a, b) + '", opacity: 0.9 },'
        ' width: ' + edge_width(a, b) + ','
        ' arrows: { to: { enabled: true, scaleFactor: 0.8 } },'
        ' smooth: { type: "cubicBezier", forceDirection: "horizontal" } }'
        for a, b in edges
    ])

    threat_count = len([r for r in log if r["scan"]["detected"]])
    clean_count  = len(log) - threat_count

    html = """<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Anticipator -- """ + name + """</title>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/vis/4.21.0/vis.min.js"></script>
  <link href="https://cdnjs.cloudflare.com/ajax/libs/vis/4.21.0/vis.min.css" rel="stylesheet">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: #0d1117; color: #e6edf3; font-family: 'Segoe UI', sans-serif; height: 100vh; overflow: hidden; }
    header { padding: 0 28px; height: 64px; background: #161b22; border-bottom: 1px solid #21262d; display: flex; align-items: center; gap: 24px; }
    .logo { font-size: 16px; font-weight: 700; color: #fff; }
    .logo-sub { font-size: 11px; color: #6e7681; margin-top: 2px; }
    .divider { width: 1px; height: 28px; background: #21262d; }
    .graph-label { font-size: 11px; color: #6e7681; }
    .graph-name { font-size: 14px; font-weight: 600; color: #e6edf3; }
    .badges { margin-left: auto; display: flex; gap: 8px; }
    .badge { padding: 5px 14px; border-radius: 20px; font-size: 12px; font-weight: 600; }
    .badge.threat { background: rgba(255,68,68,0.15); color: #ff6b6b; border: 1px solid rgba(255,68,68,0.4); }
    .badge.clean  { background: rgba(86,211,100,0.12); color: #56d364; border: 1px solid rgba(86,211,100,0.35); }
    #graph { width: 100%; height: calc(100vh - 64px); background: #0d1117; }
    .legend { position: absolute; bottom: 24px; left: 24px; background: #161b22; border: 1px solid #21262d; border-radius: 10px; padding: 14px 18px; font-size: 12px; color: #8b949e; min-width: 160px; }
    .legend-title { font-size: 11px; font-weight: 600; color: #6e7681; text-transform: uppercase; letter-spacing: 0.6px; margin-bottom: 10px; }
    .legend-item { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; color: #c9d1d9; }
    .legend-item:last-child { margin-bottom: 0; }
    .dot { width: 13px; height: 13px; border-radius: 3px; flex-shrink: 0; }
    .line { width: 22px; height: 3px; border-radius: 2px; flex-shrink: 0; }
    .stats { position: absolute; bottom: 24px; right: 24px; background: #161b22; border: 1px solid #21262d; border-radius: 10px; padding: 14px 20px; font-size: 12px; color: #8b949e; }
    .stat-row { display: flex; gap: 24px; }
    .stat-item { display: flex; flex-direction: column; align-items: center; gap: 4px; }
    .stat-num { font-size: 28px; font-weight: 700; color: #e6edf3; line-height: 1; }
    .stat-num.red { color: #ff4444; }
    .stat-num.green { color: #56d364; }
    .stat-label { font-size: 11px; color: #6e7681; }
  </style>
</head>
<body>
  <header>
    <div>
      <div class="logo">Anticipator</div>
      <div class="logo-sub">Runtime observability for multi-agent systems</div>
    </div>
    <div class="divider"></div>
    <div>
      <div class="graph-label">GRAPH</div>
      <div class="graph-name">""" + name + """</div>
    </div>
    <div class="badges">
      <div class="badge clean">""" + str(clean_count) + """ clean</div>
      <div class="badge threat">""" + str(threat_count) + """ threats</div>
    </div>
  </header>

  <div id="graph"></div>

  <div class="legend">
    <div class="legend-title">Legend</div>
    <div class="legend-item"><div class="dot" style="background:#1e88e5;border:2px solid #1565c0"></div> Clean node</div>
    <div class="legend-item"><div class="dot" style="background:#ff4444;border:2px solid #cc0000"></div> Threat detected</div>
    <div class="legend-item"><div class="line" style="background:#42a5f5"></div> Clean edge</div>
    <div class="legend-item"><div class="line" style="background:#ff4444"></div> Threat path</div>
  </div>

  <div class="stats">
    <div class="stat-row">
      <div class="stat-item"><div class="stat-num">""" + str(len(log)) + """</div><div class="stat-label">Scanned</div></div>
      <div class="stat-item"><div class="stat-num red">""" + str(threat_count) + """</div><div class="stat-label">Threats</div></div>
      <div class="stat-item"><div class="stat-num green">""" + str(clean_count) + """</div><div class="stat-label">Clean</div></div>
    </div>
  </div>

  <script>
    var nodes = new vis.DataSet([""" + nodes_js + """]);
    var edges = new vis.DataSet([""" + edges_js + """]);
    var options = {
      layout: { hierarchical: { enabled: true, direction: 'LR', sortMethod: 'directed', levelSeparation: 220, nodeSpacing: 120 } },
      physics: false,
      nodes: { borderWidth: 2, borderWidthSelected: 3, font: { size: 13 }, margin: { top: 10, bottom: 10, left: 14, right: 14 } },
      edges: { smooth: { type: 'cubicBezier', forceDirection: 'horizontal', roundness: 0.4 } },
      interaction: { hover: true, tooltipDelay: 80, zoomView: true, dragView: true }
    };
    new vis.Network(document.getElementById('graph'), { nodes: nodes, edges: edges }, options);
  </script>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[ANTICIPATOR] Graph exported -> {path}")
    return path