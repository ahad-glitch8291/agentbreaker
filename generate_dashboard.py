"""
generate_dashboard.py
----------------------
Turns one or more results.json files (from run_attacks.py --save ...) into a
single, self-contained HTML dashboard: a red/green coverage grid, similar in
spirit to a MITRE ATT&CK/ATLAS Navigator heatmap, but for this project's own
attack suite. Open the output file directly in any browser -- no server needed.

Usage:
    python3 generate_dashboard.py --out dashboard.html results_a.json results_b.json ...

Each input file becomes one COLUMN in the grid, labeled by its filename (or a
custom label via --labels, comma-separated, matching the file order). Each
attack (ATLAS-01, ATLAS-02, ...) becomes one ROW. This is designed for
exactly the kind of comparison this project produces: multiple models and/or
multiple prompt versions, side by side.

Example (the Phase 3 four-run matrix):
    python3 generate_dashboard.py \\
        --out dashboard.html \\
        --labels "llama3.1 baseline,llama3.1 hardened,qwen2.5:7b baseline,qwen2.5:7b hardened" \\
        results_llama_baseline.json results_llama_hardened.json \\
        results_qwen_baseline.json results_qwen_hardened.json
"""

import sys
import json
import argparse
import html
import datetime


def load_results(path: str) -> dict:
    with open(path) as f:
        data = json.load(f)
    return {r["id"]: r for r in data["results"]}


def cell_class_and_label(result):
    if result is None:
        return "cell-na", "n/a"
    if result.get("errored"):
        return "cell-error", "ERROR"
    if result["succeeded"]:
        return "cell-leak", "LEAKED"
    if result.get("guardrail_intervened"):
        return "cell-blocked", "held (guardrail)"
    return "cell-held", "held"


def build_html(columns: list, labels: list) -> str:
    all_ids = sorted({rid for col in columns for rid in col.keys()})

    # Pull technique metadata from whichever column has it for each id.
    meta = {}
    for col in columns:
        for rid, r in col.items():
            if rid not in meta:
                meta[rid] = {
                    "technique_id": r.get("technique_id", ""),
                    "technique_name": r.get("technique_name", ""),
                    "name": r.get("name", ""),
                    "description": r.get("description", ""),
                }

    totals = []
    for col in columns:
        leaked = sum(1 for r in col.values() if r["succeeded"])
        totals.append((leaked, len(col)))

    header_cells = "".join(
        f"<th>{html.escape(label)}<br><span class='totalline'>{leaked}/{total} leaked</span></th>"
        for label, (leaked, total) in zip(labels, totals)
    )

    rows_html = []
    for rid in all_ids:
        m = meta.get(rid, {})
        row_cells = []
        for col in columns:
            r = col.get(rid)
            cls, label = cell_class_and_label(r)
            tooltip = ""
            if r:
                excerpt = html.escape(r.get("final_response_excerpt", "")[:200])
                tooltip = f" title=\"{excerpt}\""
            row_cells.append(f"<td class='{cls}'{tooltip}>{label}</td>")

        rows_html.append(
            f"<tr>"
            f"<td class='rowlabel'>"
            f"<strong>{html.escape(rid)}</strong><br>"
            f"<span class='technique'>{html.escape(m.get('technique_id',''))}</span><br>"
            f"<span class='attackname'>{html.escape(m.get('name',''))}</span>"
            f"</td>"
            + "".join(row_cells)
            + "</tr>"
        )

    generated_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AgentBreaker — Coverage Dashboard</title>
<style>
  :root {{
    --bg: #0f1117;
    --panel: #171a23;
    --border: #2a2e3a;
    --text: #e6e8ee;
    --muted: #9aa1b2;
    --leak: #ef4444;
    --held: #22c55e;
    --blocked: #3b82f6;
    --error: #f59e0b;
  }}
  body {{
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
    margin: 0;
    padding: 32px;
  }}
  h1 {{
    margin: 0 0 4px 0;
    font-size: 22px;
  }}
  .subtitle {{
    color: var(--muted);
    margin-bottom: 24px;
    font-size: 13px;
  }}
  .legend {{
    display: flex;
    gap: 20px;
    margin-bottom: 20px;
    font-size: 13px;
    color: var(--muted);
    flex-wrap: wrap;
  }}
  .legend span {{
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }}
  .swatch {{
    width: 12px;
    height: 12px;
    border-radius: 3px;
    display: inline-block;
  }}
  table {{
    border-collapse: collapse;
    width: 100%;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
  }}
  th, td {{
    padding: 10px 12px;
    text-align: center;
    border: 1px solid var(--border);
    font-size: 13px;
  }}
  th {{
    background: #1d2130;
    font-size: 12px;
  }}
  .totalline {{
    font-weight: normal;
    color: var(--muted);
    font-size: 11px;
  }}
  .rowlabel {{
    text-align: left;
    background: #1a1d28;
    min-width: 220px;
  }}
  .technique {{
    color: var(--muted);
    font-size: 11px;
  }}
  .attackname {{
    color: var(--muted);
    font-size: 11px;
    font-style: italic;
  }}
  .cell-leak {{ background: rgba(239, 68, 68, 0.18); color: var(--leak); font-weight: 600; }}
  .cell-held {{ background: rgba(34, 197, 94, 0.12); color: var(--held); }}
  .cell-blocked {{ background: rgba(59, 130, 246, 0.18); color: var(--blocked); font-weight: 600; }}
  .cell-error {{ background: rgba(245, 158, 11, 0.18); color: var(--error); }}
  .cell-na {{ color: var(--muted); }}
  .footer {{
    margin-top: 20px;
    font-size: 11px;
    color: var(--muted);
  }}
</style>
</head>
<body>
  <h1>AgentBreaker — Coverage Dashboard</h1>
  <div class="subtitle">MITRE ATLAS-mapped attack results across model/prompt combinations. Hover a cell for a response excerpt.</div>

  <div class="legend">
    <span><span class="swatch" style="background: var(--leak);"></span> Leaked (real defense failure)</span>
    <span><span class="swatch" style="background: var(--held);"></span> Held (no leak attempted or model refused)</span>
    <span><span class="swatch" style="background: var(--blocked);"></span> Held — guardrail actively blocked a leak attempt</span>
    <span><span class="swatch" style="background: var(--error);"></span> Harness error</span>
  </div>

  <table>
    <tr>
      <th style="text-align:left;">Attack</th>
      {header_cells}
    </tr>
    {"".join(rows_html)}
  </table>

  <div class="footer">Generated {html.escape(generated_at)} by generate_dashboard.py</div>
</body>
</html>
"""


def main():
    parser = argparse.ArgumentParser(description="Generate an HTML coverage dashboard from results.json files.")
    parser.add_argument("results_files", nargs="+", help="One or more results.json files.")
    parser.add_argument("--out", default="dashboard.html", help="Output HTML file path.")
    parser.add_argument("--labels", default=None, help="Comma-separated labels, one per input file, in order.")
    args = parser.parse_args()

    columns = [load_results(p) for p in args.results_files]

    if args.labels:
        labels = [l.strip() for l in args.labels.split(",")]
        if len(labels) != len(columns):
            print(
                f"ERROR: --labels has {len(labels)} entries but {len(columns)} files were given.",
                file=sys.stderr,
            )
            sys.exit(1)
    else:
        labels = args.results_files

    output = build_html(columns, labels)
    with open(args.out, "w") as f:
        f.write(output)

    print(f"Dashboard written to {args.out}. Open it in a browser to view.")


if __name__ == "__main__":
    main()
