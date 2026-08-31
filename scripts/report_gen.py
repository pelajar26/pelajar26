#!/usr/bin/env python3
"""Generate HTML bug bounty report from recon output directory."""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path


def parse_httpx_json(filepath: Path) -> list[dict]:
    results = []
    if not filepath.exists():
        return results
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return results


def parse_nuclei_json(filepath: Path) -> list[dict]:
    results = []
    if not filepath.exists():
        return results
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return results


def read_lines(filepath: Path) -> list[str]:
    if not filepath.exists():
        return []
    return [l.strip() for l in filepath.read_text().splitlines() if l.strip()]


def severity_color(sev: str) -> str:
    return {
        "critical": "#dc2626",
        "high":     "#ea580c",
        "medium":   "#d97706",
        "low":      "#65a30d",
        "info":     "#2563eb",
    }.get(sev.lower(), "#6b7280")


def generate_report(output_dir: Path) -> str:
    domain = output_dir.name.rsplit("_", 2)[0]
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    subdomains   = read_lines(output_dir / "subdomains_raw.txt")
    live_hosts   = read_lines(output_dir / "live_hosts.txt")
    httpx_data   = parse_httpx_json(output_dir / "httpx_full.json")
    nuclei_data  = parse_nuclei_json(output_dir / "vuln" / "nuclei_results.json")
    open_redir   = read_lines(output_dir / "vuln" / "open_redirect.txt") + \
                   read_lines(output_dir / "open_redirect.txt")
    cors_issues  = read_lines(output_dir / "vuln" / "cors_issues.txt") + \
                   read_lines(output_dir / "cors_issues.txt")
    exposed      = read_lines(output_dir / "vuln" / "exposed_files.txt") + \
                   read_lines(output_dir / "exposed_files.txt")
    endpoints    = read_lines(output_dir / "js" / "endpoints.txt") + \
                   read_lines(output_dir / "endpoints.txt")
    secrets      = read_lines(output_dir / "js" / "pattern_matches.txt") + \
                   read_lines(output_dir / "pattern_matches.txt")

    # Deduplicate
    open_redir  = list(dict.fromkeys(open_redir))
    cors_issues = list(dict.fromkeys(cors_issues))
    exposed     = list(dict.fromkeys(exposed))
    endpoints   = list(dict.fromkeys(endpoints))
    secrets     = list(dict.fromkeys(secrets))

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for n in nuclei_data:
        sev = n.get("info", {}).get("severity", "info").lower()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    def rows(items, cols=1):
        if not items:
            return '<tr><td colspan="99" style="color:#9ca3af;font-style:italic">None found</td></tr>'
        html = ""
        for item in items:
            if isinstance(item, dict):
                cells = "".join(f"<td>{v}</td>" for v in list(item.values())[:cols])
            else:
                cells = f"<td>{item}</td>"
            html += f"<tr>{cells}</tr>"
        return html

    def nuclei_rows():
        if not nuclei_data:
            return '<tr><td colspan="4" style="color:#9ca3af;font-style:italic">None found</td></tr>'
        html = ""
        for n in nuclei_data:
            sev  = n.get("info", {}).get("severity", "info")
            name = n.get("info", {}).get("name", "")
            host = n.get("host", "")
            tmpl = n.get("template-id", "")
            color = severity_color(sev)
            html += f"""<tr>
                <td><span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px">{sev.upper()}</span></td>
                <td>{name}</td>
                <td>{host}</td>
                <td style="font-family:monospace;font-size:12px">{tmpl}</td>
            </tr>"""
        return html

    def httpx_rows():
        if not httpx_data:
            return rows(live_hosts)
        html = ""
        for h in httpx_data[:200]:
            url    = h.get("url", "")
            code   = h.get("status-code", "")
            title  = h.get("title", "")
            tech   = ", ".join(h.get("tech", []))
            color  = "#16a34a" if str(code).startswith("2") else \
                     "#d97706" if str(code).startswith("3") else \
                     "#dc2626" if str(code).startswith("4") else "#6b7280"
            html += f"""<tr>
                <td><a href="{url}" target="_blank" style="color:#60a5fa">{url}</a></td>
                <td><span style="color:{color};font-weight:bold">{code}</span></td>
                <td>{title}</td>
                <td style="font-size:12px;color:#9ca3af">{tech}</td>
            </tr>"""
        return html

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Bug Bounty Report — {domain}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }}
  .header {{ background: linear-gradient(135deg, #1e3a5f 0%, #0f172a 100%); padding: 40px; border-bottom: 1px solid #1e293b; }}
  .header h1 {{ font-size: 28px; font-weight: 700; color: #38bdf8; }}
  .header .meta {{ color: #94a3b8; margin-top: 8px; font-size: 14px; }}
  .container {{ max-width: 1400px; margin: 0 auto; padding: 32px 40px; }}
  .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin-bottom: 32px; }}
  .stat-card {{ background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 20px; text-align: center; }}
  .stat-card .num {{ font-size: 36px; font-weight: 700; }}
  .stat-card .lbl {{ font-size: 13px; color: #94a3b8; margin-top: 4px; }}
  .section {{ background: #1e293b; border: 1px solid #334155; border-radius: 12px; margin-bottom: 24px; overflow: hidden; }}
  .section-header {{ padding: 16px 24px; background: #0f172a; border-bottom: 1px solid #334155; display: flex; align-items: center; gap: 10px; }}
  .section-header h2 {{ font-size: 16px; font-weight: 600; }}
  .badge {{ font-size: 12px; background: #334155; color: #94a3b8; padding: 2px 8px; border-radius: 999px; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{ text-align: left; padding: 12px 24px; font-size: 12px; text-transform: uppercase; letter-spacing: .05em; color: #64748b; border-bottom: 1px solid #334155; }}
  td {{ padding: 12px 24px; font-size: 14px; border-bottom: 1px solid #1e293b; word-break: break-all; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #0f172a33; }}
  .sev-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 8px; padding: 16px 24px; }}
  .sev-box {{ text-align: center; padding: 12px; border-radius: 8px; }}
  .sev-box .n {{ font-size: 28px; font-weight: 700; }}
  .sev-box .l {{ font-size: 11px; opacity: .8; margin-top: 2px; }}
  .c {{ background: #450a0a; color: #fca5a5; }} .h {{ background: #431407; color: #fdba74; }}
  .m {{ background: #451a03; color: #fcd34d; }} .l2 {{ background: #1a2e05; color: #86efac; }}
  .i {{ background: #172554; color: #93c5fd; }}
  @media (max-width: 768px) {{ .container {{ padding: 16px; }} th, td {{ padding: 8px 12px; }} }}
</style>
</head>
<body>
<div class="header">
  <h1>Bug Bounty Recon Report</h1>
  <div class="meta">Target: <strong style="color:#e2e8f0">{domain}</strong> &nbsp;|&nbsp; Generated: {timestamp}</div>
</div>
<div class="container">

  <!-- Overview Stats -->
  <div class="stats-grid">
    <div class="stat-card"><div class="num" style="color:#38bdf8">{len(subdomains)}</div><div class="lbl">Subdomains</div></div>
    <div class="stat-card"><div class="num" style="color:#34d399">{len(live_hosts)}</div><div class="lbl">Live Hosts</div></div>
    <div class="stat-card"><div class="num" style="color:#f87171">{len(nuclei_data)}</div><div class="lbl">Nuclei Findings</div></div>
    <div class="stat-card"><div class="num" style="color:#fb923c">{len(open_redir)}</div><div class="lbl">Open Redirects</div></div>
    <div class="stat-card"><div class="num" style="color:#a78bfa">{len(cors_issues)}</div><div class="lbl">CORS Issues</div></div>
    <div class="stat-card"><div class="num" style="color:#facc15">{len(exposed)}</div><div class="lbl">Exposed Files</div></div>
    <div class="stat-card"><div class="num" style="color:#f472b6">{len(secrets)}</div><div class="lbl">Potential Secrets</div></div>
    <div class="stat-card"><div class="num" style="color:#67e8f9">{len(endpoints)}</div><div class="lbl">API Endpoints</div></div>
  </div>

  <!-- Nuclei Severity Breakdown -->
  <div class="section">
    <div class="section-header"><h2>Nuclei Severity Breakdown</h2></div>
    <div class="sev-grid">
      <div class="sev-box c"><div class="n">{sev_counts['critical']}</div><div class="l">CRITICAL</div></div>
      <div class="sev-box h"><div class="n">{sev_counts['high']}</div><div class="l">HIGH</div></div>
      <div class="sev-box m"><div class="n">{sev_counts['medium']}</div><div class="l">MEDIUM</div></div>
      <div class="sev-box l2"><div class="n">{sev_counts['low']}</div><div class="l">LOW</div></div>
      <div class="sev-box i"><div class="n">{sev_counts['info']}</div><div class="l">INFO</div></div>
    </div>
  </div>

  <!-- Nuclei Findings -->
  <div class="section">
    <div class="section-header"><h2>Nuclei Findings</h2><span class="badge">{len(nuclei_data)}</span></div>
    <table><thead><tr><th>Severity</th><th>Name</th><th>Host</th><th>Template</th></tr></thead>
    <tbody>{nuclei_rows()}</tbody></table>
  </div>

  <!-- Live Hosts -->
  <div class="section">
    <div class="section-header"><h2>Live Hosts</h2><span class="badge">{len(httpx_data) or len(live_hosts)}</span></div>
    <table><thead><tr><th>URL</th><th>Status</th><th>Title</th><th>Technologies</th></tr></thead>
    <tbody>{httpx_rows()}</tbody></table>
  </div>

  <!-- Open Redirects -->
  <div class="section">
    <div class="section-header"><h2>Open Redirects</h2><span class="badge">{len(open_redir)}</span></div>
    <table><thead><tr><th>Finding</th></tr></thead>
    <tbody>{rows(open_redir)}</tbody></table>
  </div>

  <!-- CORS Issues -->
  <div class="section">
    <div class="section-header"><h2>CORS Misconfigurations</h2><span class="badge">{len(cors_issues)}</span></div>
    <table><thead><tr><th>Finding</th></tr></thead>
    <tbody>{rows(cors_issues)}</tbody></table>
  </div>

  <!-- Exposed Files -->
  <div class="section">
    <div class="section-header"><h2>Exposed Files / Paths</h2><span class="badge">{len(exposed)}</span></div>
    <table><thead><tr><th>Finding</th></tr></thead>
    <tbody>{rows(exposed)}</tbody></table>
  </div>

  <!-- Potential Secrets -->
  <div class="section">
    <div class="section-header"><h2>Potential Secrets / Credentials</h2><span class="badge">{len(secrets)}</span></div>
    <table><thead><tr><th>Finding</th></tr></thead>
    <tbody>{rows(secrets)}</tbody></table>
  </div>

  <!-- API Endpoints -->
  <div class="section">
    <div class="section-header"><h2>API Endpoints (from JS)</h2><span class="badge">{len(endpoints)}</span></div>
    <table><thead><tr><th>Endpoint</th></tr></thead>
    <tbody>{rows(endpoints[:500])}</tbody></table>
  </div>

</div>
</body>
</html>"""


def main():
    parser = argparse.ArgumentParser(description="Generate HTML bug bounty report")
    parser.add_argument("-d", "--dir", required=True, help="Recon output directory")
    parser.add_argument("-o", "--output", help="Output HTML file (default: <dir>/report.html)")
    args = parser.parse_args()

    output_dir = Path(args.dir)
    if not output_dir.exists():
        print(f"Error: directory not found: {output_dir}", file=sys.stderr)
        sys.exit(1)

    out_file = Path(args.output) if args.output else output_dir / "report.html"
    html = generate_report(output_dir)
    out_file.write_text(html)
    print(f"Report saved: {out_file}")


if __name__ == "__main__":
    main()
