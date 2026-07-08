"""HTML Report Generator for the Cybersecurity AI Agent.

Generates professional, self-contained HTML reports from any tool result.
Reports are saved to the reports/ directory with timestamps.
"""

import os
import html
import hashlib
from datetime import datetime
from pathlib import Path

REPORTS_DIR = Path(__file__).parent / "reports"


def _ensure_reports_dir():
    """Create the reports directory if it doesn't exist."""
    REPORTS_DIR.mkdir(exist_ok=True)


def _severity_badge(text: str) -> str:
    """Generate a colored badge based on severity keywords."""
    t = text.lower()
    if any(w in t for w in ("critical", "10.0", "9.")):
        return "critical"
    elif any(w in t for w in ("high", "8.", "7.")):
        return "high"
    elif any(w in t for w in ("medium", "6.", "5.", "4.")):
        return "medium"
    elif any(w in t for w in ("low", "3.", "2.", "1.", "clean", "safe")):
        return "low"
    return ""


def _format_result_html(result: str) -> str:
    """Convert markdown-ish tool output to styled HTML."""
    lines = result.split("\n")
    html_lines = []
    in_list = False

    for line in lines:
        escaped = html.escape(line)

        # Headings
        if escaped.startswith("## "):
            if in_list:
                html_lines.append("</ul>")
                in_list = False
            html_lines.append(f'<h3 class="result-heading">{escaped[3:]}</h3>')
            continue

        # Bold markers
        if "**" in escaped:
            import re
            escaped = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', escaped)

        # Bullet items
        if escaped.strip().startswith("- ") or escaped.strip().startswith("● "):
            if not in_list:
                html_lines.append('<ul class="result-list">')
                in_list = True
            content = escaped.strip().lstrip("-●").strip()
            sev = _severity_badge(content)
            badge = f' <span class="badge {sev}">{sev.upper()}</span>' if sev else ""
            html_lines.append(f"<li>{content}{badge}</li>")
            continue

        if in_list and not escaped.strip():
            html_lines.append("</ul>")
            in_list = False

        # Status lines (OPEN/CLOSED for port scans)
        if "OPEN" in escaped:
            escaped = escaped.replace("OPEN", '<span class="status-open">OPEN</span>')
        if "CLOSED" in escaped:
            escaped = escaped.replace("CLOSED", '<span class="status-closed">CLOSED</span>')

        if escaped.strip():
            html_lines.append(f"<p>{escaped}</p>")

    if in_list:
        html_lines.append("</ul>")

    return "\n".join(html_lines)


def generate_report(
    tool_name: str,
    result: str,
    target: str = "",
    parameters: dict | None = None,
    save: bool = True,
) -> str:
    """Generate an HTML report for a tool result.

    Args:
        tool_name: Name of the tool (e.g., "Port Scanner", "CVE Lookup")
        result: Raw text result from the tool
        target: The target that was scanned/queried
        parameters: Optional dict of parameters used
        save: If True, saves to reports/ directory

    Returns:
        Full HTML string of the report. If save=True, also returns the file path
        as a tuple (html_content, file_path).
    """
    now = datetime.now()
    timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
    file_ts = now.strftime("%Y%m%d_%H%M%S")
    report_id = hashlib.md5(f"{tool_name}{target}{timestamp}".encode()).hexdigest()[:8].upper()

    params_html = ""
    if parameters:
        rows = "".join(
            f"<tr><td>{html.escape(str(k))}</td><td>{html.escape(str(v))}</td></tr>"
            for k, v in parameters.items()
            if v
        )
        if rows:
            params_html = f"""
            <div class="params-section">
                <h3>Parameters</h3>
                <table class="params-table">
                    <tr><th>Parameter</th><th>Value</th></tr>
                    {rows}
                </table>
            </div>"""

    result_html = _format_result_html(result)

    report = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{html.escape(tool_name)} Report — {html.escape(target or 'N/A')}</title>
<style>
  :root {{
    --bg: #0f172a; --surface: #1e293b; --surface2: #273548;
    --border: #334155; --text: #e2e8f0; --muted: #94a3b8;
    --accent: #6366f1; --green: #22c55e; --red: #ef4444;
    --yellow: #eab308; --cyan: #06b6d4; --orange: #f97316;
  }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; }}

  .report-container {{ max-width: 900px; margin: 0 auto; padding: 40px 24px; }}

  /* Header */
  .report-header {{ background: linear-gradient(135deg, var(--surface) 0%, var(--surface2) 100%);
    border: 1px solid var(--border); border-radius: 12px; padding: 32px; margin-bottom: 24px; }}
  .report-header h1 {{ font-size: 24px; font-weight: 700; margin-bottom: 4px; }}
  .report-header .subtitle {{ color: var(--muted); font-size: 14px; margin-bottom: 20px; }}
  .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; }}
  .meta-item {{ background: var(--bg); border-radius: 8px; padding: 12px 16px; }}
  .meta-item .label {{ font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: var(--muted); margin-bottom: 4px; }}
  .meta-item .value {{ font-size: 14px; font-weight: 600; word-break: break-all; }}

  /* Sections */
  .section {{ background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 24px; margin-bottom: 24px; }}
  .section h2 {{ font-size: 18px; margin-bottom: 16px; padding-bottom: 8px; border-bottom: 1px solid var(--border); }}

  /* Results */
  .result-heading {{ font-size: 16px; color: var(--cyan); margin: 16px 0 8px; }}
  .result-list {{ list-style: none; padding: 0; }}
  .result-list li {{ padding: 8px 12px; border-left: 3px solid var(--accent); margin-bottom: 6px; background: var(--bg); border-radius: 0 6px 6px 0; font-size: 14px; }}
  p {{ font-size: 14px; line-height: 1.7; margin-bottom: 8px; }}
  strong {{ color: var(--cyan); }}

  /* Status badges */
  .status-open {{ color: var(--green); font-weight: 700; }}
  .status-closed {{ color: var(--red); font-weight: 700; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: 700; margin-left: 8px; }}
  .badge.critical {{ background: rgba(239,68,68,0.2); color: var(--red); }}
  .badge.high {{ background: rgba(249,115,22,0.2); color: var(--orange); }}
  .badge.medium {{ background: rgba(234,179,8,0.2); color: var(--yellow); }}
  .badge.low {{ background: rgba(34,197,94,0.2); color: var(--green); }}

  /* Params table */
  .params-table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
  .params-table th {{ text-align: left; padding: 8px 12px; background: var(--bg); color: var(--muted);
    font-size: 11px; text-transform: uppercase; letter-spacing: 1px; }}
  .params-table td {{ padding: 8px 12px; border-bottom: 1px solid var(--border); }}

  /* Footer */
  .report-footer {{ text-align: center; color: var(--muted); font-size: 12px; padding: 24px 0; border-top: 1px solid var(--border); margin-top: 24px; }}

  /* Print styles */
  @media print {{
    body {{ background: #fff; color: #000; }}
    .report-container {{ max-width: 100%; padding: 0; }}
    .report-header, .section {{ border: 1px solid #ddd; }}
    .report-header {{ background: #f8f9fa; }}
    .section {{ background: #fff; }}
    .meta-item {{ background: #f8f9fa; }}
    .result-list li {{ background: #f8f9fa; }}
    .status-open {{ color: #16a34a; }}
    .status-closed {{ color: #dc2626; }}
    :root {{ --text: #1a1a1a; --muted: #666; --cyan: #0891b2; --border: #ddd; --accent: #4f46e5; }}
    .no-print {{ display: none; }}
  }}

  /* Action buttons */
  .actions {{ display: flex; gap: 12px; margin-bottom: 24px; }}
  .action-btn {{ background: var(--accent); color: #fff; border: none; padding: 10px 20px;
    border-radius: 8px; cursor: pointer; font-size: 14px; font-weight: 600; transition: opacity 0.15s; }}
  .action-btn:hover {{ opacity: 0.85; }}
  .action-btn.secondary {{ background: var(--surface); border: 1px solid var(--border); }}
</style>
</head>
<body>
<div class="report-container">

  <div class="actions no-print">
    <button class="action-btn" onclick="window.print()">Print / Save PDF</button>
    <button class="action-btn secondary" onclick="copyReport()">Copy to Clipboard</button>
  </div>

  <div class="report-header">
    <h1>{html.escape(tool_name)} Report</h1>
    <div class="subtitle">Cybersecurity AI Agent v2.1.0</div>
    <div class="meta-grid">
      <div class="meta-item">
        <div class="label">Target</div>
        <div class="value">{html.escape(target or 'N/A')}</div>
      </div>
      <div class="meta-item">
        <div class="label">Date & Time</div>
        <div class="value">{timestamp}</div>
      </div>
      <div class="meta-item">
        <div class="label">Report ID</div>
        <div class="value">RPT-{report_id}</div>
      </div>
      <div class="meta-item">
        <div class="label">Tool</div>
        <div class="value">{html.escape(tool_name)}</div>
      </div>
    </div>
  </div>

  {params_html}

  <div class="section">
    <h2>Results</h2>
    {result_html}
  </div>

  <div class="section">
    <h2>Raw Output</h2>
    <pre style="background:var(--bg);padding:16px;border-radius:8px;overflow-x:auto;font-size:13px;line-height:1.6;white-space:pre-wrap;word-break:break-word;">{html.escape(result)}</pre>
  </div>

  <div class="report-footer">
    Generated by Cybersecurity AI Agent v2.1.0 &mdash; {timestamp}<br>
    Report ID: RPT-{report_id} &mdash; Powered by Claude AI + LangGraph
  </div>

</div>

<script>
function copyReport() {{
  const text = document.querySelector('.report-container').innerText;
  navigator.clipboard.writeText(text).then(() => {{
    const btn = event.target;
    btn.textContent = 'Copied!';
    setTimeout(() => btn.textContent = 'Copy to Clipboard', 2000);
  }});
}}
</script>
</body>
</html>"""

    if save:
        _ensure_reports_dir()
        safe_tool = tool_name.lower().replace(" ", "_").replace("/", "_")
        safe_target = (target or "general").replace(".", "_").replace("/", "_").replace(":", "_")[:40]
        filename = f"{file_ts}_{safe_tool}_{safe_target}.html"
        filepath = REPORTS_DIR / filename
        filepath.write_text(report, encoding="utf-8")
        return report, str(filepath)

    return report, ""


def generate_multi_report(
    results: list[dict],
    title: str = "Combined Security Assessment",
) -> tuple[str, str]:
    """Generate a combined report from multiple tool results.

    Args:
        results: List of dicts with keys: tool_name, result, target, parameters
        title: Report title

    Returns:
        Tuple of (html_content, file_path)
    """
    now = datetime.now()
    timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
    file_ts = now.strftime("%Y%m%d_%H%M%S")
    report_id = hashlib.md5(f"{title}{timestamp}".encode()).hexdigest()[:8].upper()

    sections_html = ""
    for i, r in enumerate(results, 1):
        tool = r.get("tool_name", f"Tool {i}")
        target = r.get("target", "")
        result = r.get("result", "")
        result_formatted = _format_result_html(result)

        sections_html += f"""
    <div class="section">
      <h2>{i}. {html.escape(tool)}{(' — ' + html.escape(target)) if target else ''}</h2>
      {result_formatted}
      <details style="margin-top:12px;">
        <summary style="cursor:pointer;color:var(--muted);font-size:13px;">View raw output</summary>
        <pre style="background:var(--bg);padding:12px;border-radius:6px;margin-top:8px;font-size:12px;white-space:pre-wrap;word-break:break-word;">{html.escape(result)}</pre>
      </details>
    </div>"""

    # Reuse same template structure
    report = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{html.escape(title)}</title>
<style>
  :root {{
    --bg: #0f172a; --surface: #1e293b; --surface2: #273548;
    --border: #334155; --text: #e2e8f0; --muted: #94a3b8;
    --accent: #6366f1; --green: #22c55e; --red: #ef4444;
    --yellow: #eab308; --cyan: #06b6d4; --orange: #f97316;
  }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; }}
  .report-container {{ max-width: 900px; margin: 0 auto; padding: 40px 24px; }}
  .report-header {{ background: linear-gradient(135deg, var(--surface) 0%, var(--surface2) 100%);
    border: 1px solid var(--border); border-radius: 12px; padding: 32px; margin-bottom: 24px; }}
  .report-header h1 {{ font-size: 24px; font-weight: 700; margin-bottom: 4px; }}
  .report-header .subtitle {{ color: var(--muted); font-size: 14px; margin-bottom: 20px; }}
  .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; }}
  .meta-item {{ background: var(--bg); border-radius: 8px; padding: 12px 16px; }}
  .meta-item .label {{ font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: var(--muted); margin-bottom: 4px; }}
  .meta-item .value {{ font-size: 14px; font-weight: 600; }}
  .section {{ background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 24px; margin-bottom: 24px; }}
  .section h2 {{ font-size: 18px; margin-bottom: 16px; padding-bottom: 8px; border-bottom: 1px solid var(--border); }}
  .result-heading {{ font-size: 16px; color: var(--cyan); margin: 16px 0 8px; }}
  .result-list {{ list-style: none; padding: 0; }}
  .result-list li {{ padding: 8px 12px; border-left: 3px solid var(--accent); margin-bottom: 6px; background: var(--bg); border-radius: 0 6px 6px 0; font-size: 14px; }}
  p {{ font-size: 14px; line-height: 1.7; margin-bottom: 8px; }}
  strong {{ color: var(--cyan); }}
  .status-open {{ color: var(--green); font-weight: 700; }}
  .status-closed {{ color: var(--red); font-weight: 700; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: 700; margin-left: 8px; }}
  .badge.critical {{ background: rgba(239,68,68,0.2); color: var(--red); }}
  .badge.high {{ background: rgba(249,115,22,0.2); color: var(--orange); }}
  .badge.medium {{ background: rgba(234,179,8,0.2); color: var(--yellow); }}
  .badge.low {{ background: rgba(34,197,94,0.2); color: var(--green); }}
  .report-footer {{ text-align: center; color: var(--muted); font-size: 12px; padding: 24px 0; border-top: 1px solid var(--border); margin-top: 24px; }}
  .actions {{ display: flex; gap: 12px; margin-bottom: 24px; }}
  .action-btn {{ background: var(--accent); color: #fff; border: none; padding: 10px 20px;
    border-radius: 8px; cursor: pointer; font-size: 14px; font-weight: 600; transition: opacity 0.15s; }}
  .action-btn:hover {{ opacity: 0.85; }}
  .action-btn.secondary {{ background: var(--surface); border: 1px solid var(--border); }}
  details summary {{ color: var(--muted); font-size: 13px; cursor: pointer; }}
  @media print {{
    body {{ background: #fff; color: #000; }}
    .report-container {{ max-width: 100%; padding: 0; }}
    .report-header, .section {{ border: 1px solid #ddd; }}
    .report-header {{ background: #f8f9fa; }}
    .section {{ background: #fff; }}
    .meta-item {{ background: #f8f9fa; }}
    .result-list li {{ background: #f8f9fa; }}
    :root {{ --text: #1a1a1a; --muted: #666; --cyan: #0891b2; --border: #ddd; --accent: #4f46e5; }}
    .no-print {{ display: none; }}
  }}
</style>
</head>
<body>
<div class="report-container">
  <div class="actions no-print">
    <button class="action-btn" onclick="window.print()">Print / Save PDF</button>
    <button class="action-btn secondary" onclick="navigator.clipboard.writeText(document.querySelector('.report-container').innerText).then(()=>{{event.target.textContent='Copied!';setTimeout(()=>event.target.textContent='Copy to Clipboard',2000)}})">Copy to Clipboard</button>
  </div>
  <div class="report-header">
    <h1>{html.escape(title)}</h1>
    <div class="subtitle">Cybersecurity AI Agent v2.1.0</div>
    <div class="meta-grid">
      <div class="meta-item">
        <div class="label">Tools Run</div>
        <div class="value">{len(results)}</div>
      </div>
      <div class="meta-item">
        <div class="label">Date & Time</div>
        <div class="value">{timestamp}</div>
      </div>
      <div class="meta-item">
        <div class="label">Report ID</div>
        <div class="value">RPT-{report_id}</div>
      </div>
    </div>
  </div>
  {sections_html}
  <div class="report-footer">
    Generated by Cybersecurity AI Agent v2.1.0 &mdash; {timestamp}<br>
    Report ID: RPT-{report_id} &mdash; Powered by Claude AI + LangGraph
  </div>
</div>
</body>
</html>"""

    _ensure_reports_dir()
    filename = f"{file_ts}_combined_report.html"
    filepath = REPORTS_DIR / filename
    filepath.write_text(report, encoding="utf-8")
    return report, str(filepath)


def list_reports() -> list[dict]:
    """List all saved reports."""
    _ensure_reports_dir()
    reports = []
    for f in sorted(REPORTS_DIR.glob("*.html"), reverse=True):
        stat = f.stat()
        reports.append({
            "filename": f.name,
            "path": str(f),
            "size_kb": round(stat.st_size / 1024, 1),
            "created": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
        })
    return reports
