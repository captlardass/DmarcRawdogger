#!/usr/bin/env python3
"""Local browser UI for dmarc_rawdogger. Upload a DMARC report, see a visual summary.

Stdlib only - no pip installs. Binds to 127.0.0.1 by default (local machine only).
"""

import argparse
import html
import os
import tempfile
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import dmarc_rawdogger as core

MAX_UPLOAD_BYTES = 20 * 1024 * 1024  # 20 MB

PAGE_HEAD = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DMARC Rawdogger</title>
<style>
  :root {
    color-scheme: light;
    --surface-1:      #fcfcfb;
    --page:           #f9f9f7;
    --text-primary:   #0b0b0b;
    --text-secondary: #52514e;
    --text-muted:     #898781;
    --gridline:       #e1e0d9;
    --baseline:       #c3c2b7;
    --border:         rgba(11,11,11,0.10);
    --seq-blue:       #2a78d6;
    --status-good:     #0ca30c;
    --status-critical: #d03b3b;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    padding: 32px 16px 64px;
    background: var(--page);
    color: var(--text-primary);
    font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
  }
  .wrap { max-width: 920px; margin: 0 auto; }
  h1 { font-size: 22px; margin: 0 0 4px; }
  .subtitle { color: var(--text-secondary); font-size: 14px; margin: 0 0 28px; }
  .card {
    background: var(--surface-1);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 20px 24px;
    margin-bottom: 20px;
  }
  .card h2 {
    font-size: 13px;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--text-secondary);
    margin: 0 0 16px;
    font-weight: 600;
  }
  /* Upload form */
  .dropzone {
    border: 2px dashed var(--baseline);
    border-radius: 10px;
    padding: 40px 20px;
    text-align: center;
    color: var(--text-secondary);
  }
  input[type=file] { margin: 12px 0; }
  button {
    background: var(--seq-blue);
    color: #fff;
    border: none;
    border-radius: 6px;
    padding: 10px 20px;
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
  }
  button:hover { background: #256abf; }
  .hint { font-size: 12px; color: var(--text-muted); margin-top: 10px; }

  /* KPI tiles */
  .kpi-row { display: flex; gap: 16px; flex-wrap: wrap; }
  .kpi { flex: 1 1 160px; }
  .kpi .label { font-size: 12px; color: var(--text-secondary); margin-bottom: 6px; }
  .kpi .value { font-size: 32px; font-weight: 600; line-height: 1; }
  .kpi .delta { font-size: 13px; margin-top: 6px; font-weight: 600; }
  .delta.good { color: var(--status-good); }
  .delta.critical { color: var(--status-critical); }
  .delta.muted { color: var(--text-muted); }

  /* Stacked bar (part-to-whole) */
  .stack {
    display: flex;
    height: 24px;
    border-radius: 4px;
    overflow: hidden;
    background: var(--gridline);
    gap: 2px;
  }
  .stack .seg { display: flex; align-items: center; justify-content: center;
    color: #fff; font-size: 12px; font-weight: 600; white-space: nowrap; }
  .seg.good { background: var(--status-good); }
  .seg.critical { background: var(--status-critical); }
  .legend { display: flex; gap: 20px; margin-top: 12px; font-size: 13px; color: var(--text-secondary); }
  .legend .swatch { display: inline-block; width: 10px; height: 10px; border-radius: 2px; margin-right: 6px; }

  /* Horizontal bar chart */
  .barlist { display: flex; flex-direction: column; gap: 10px; }
  .bar-row { display: grid; grid-template-columns: 160px 1fr 56px; align-items: center; gap: 10px; }
  .bar-row .ip { font-size: 13px; color: var(--text-secondary); text-align: right;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .bar-track { background: var(--gridline); border-radius: 4px; height: 20px; position: relative; }
  .bar-fill { background: var(--seq-blue); height: 20px; max-height: 24px; border-radius: 4px; }
  .bar-row .count { font-size: 13px; color: var(--text-secondary); font-variant-numeric: tabular-nums; }

  /* Policy definition list */
  dl.policy { display: grid; grid-template-columns: max-content 1fr; gap: 6px 16px; margin: 0; font-size: 14px; }
  dl.policy dt { color: var(--text-secondary); }
  dl.policy dd { margin: 0; font-weight: 600; }

  /* Table */
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--gridline); }
  th { color: var(--text-secondary); font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: 0.03em; }
  td.num { font-variant-numeric: tabular-nums; text-align: right; }
  .status-badge { display: inline-flex; align-items: center; gap: 6px; font-weight: 600; }
  .status-badge .dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
  .status-badge.pass .dot { background: var(--status-good); }
  .status-badge.pass { color: var(--status-good); }
  .status-badge.fail .dot { background: var(--status-critical); }
  .status-badge.fail { color: var(--status-critical); }

  .error { color: var(--status-critical); font-weight: 600; }
  a.back { color: var(--seq-blue); text-decoration: none; font-size: 14px; }
  a.back:hover { text-decoration: underline; }
</style>
</head>
<body>
<div class="wrap">
"""

PAGE_TAIL = """
</div>
</body>
</html>
"""

UPLOAD_FORM = """
<h1>DMARC Rawdogger</h1>
<p class="subtitle">Upload a DMARC aggregate report and get a readable summary.</p>
<div class="card">
  <form method="POST" action="/upload" enctype="multipart/form-data">
    <div class="dropzone">
      <div>Choose a report file</div>
      <input type="file" name="report" required>
      <div class="hint">.eml / .msg mail file, or a raw .gz / .zip / .xml / .csv report</div>
      <div style="margin-top:16px;"><button type="submit">Analyze report</button></div>
    </div>
  </form>
</div>
"""


def esc(value) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def render_error_page(message: str) -> str:
    return (
        PAGE_HEAD
        + UPLOAD_FORM
        + f'<div class="card"><p class="error">Error: {esc(message)}</p></div>'
        + PAGE_TAIL
    )


def render_report_html(report: dict) -> str:
    records = report["records"]
    total = sum(int(r["count"] or 0) for r in records)
    passed = sum(
        int(r["count"] or 0) for r in records
        if r["dkim_aligned"] == "pass" or r["spf_aligned"] == "pass"
    )
    failed = total - passed
    pass_pct = round(100 * passed / total) if total else 0
    fail_pct = 100 - pass_pct if total else 0

    parts = [PAGE_HEAD]
    parts.append('<a class="back" href="/">&larr; Analyze another report</a>')
    parts.append(f'<h1>{esc(report["policy_domain"] or "DMARC Report")}</h1>')
    parts.append(
        f'<p class="subtitle">{esc(report["org_name"])} &middot; '
        f'{esc(core.fmt_timestamp(report["date_begin"]))} &rarr; '
        f'{esc(core.fmt_timestamp(report["date_end"]))}</p>'
    )

    # KPI row
    fail_delta_class = "critical" if failed else "muted"
    parts.append('<div class="card"><div class="kpi-row">')
    parts.append(
        f'<div class="kpi"><div class="label">Total messages</div>'
        f'<div class="value">{total}</div></div>'
    )
    parts.append(
        f'<div class="kpi"><div class="label">Aligned (pass)</div>'
        f'<div class="value">{passed}</div>'
        f'<div class="delta good">{pass_pct}%</div></div>'
    )
    parts.append(
        f'<div class="kpi"><div class="label">Not aligned (fail)</div>'
        f'<div class="value">{failed}</div>'
        f'<div class="delta {fail_delta_class}">{fail_pct if failed else 0}%</div></div>'
    )
    parts.append('</div></div>')

    # Pass/fail stacked bar
    if total:
        parts.append('<div class="card"><h2>Alignment breakdown</h2>')
        parts.append('<div class="stack">')
        if passed:
            parts.append(
                f'<div class="seg good" style="flex:{passed}" '
                f'title="Pass: {passed} messages ({pass_pct}%)">'
                + (f'{pass_pct}%' if pass_pct >= 12 else '') + '</div>'
            )
        if failed:
            parts.append(
                f'<div class="seg critical" style="flex:{failed}" '
                f'title="Fail: {failed} messages ({fail_pct}%)">'
                + (f'{fail_pct}%' if fail_pct >= 12 else '') + '</div>'
            )
        parts.append('</div>')
        parts.append(
            '<div class="legend">'
            f'<span><span class="swatch" style="background:var(--status-good)"></span>Pass ({passed})</span>'
            f'<span><span class="swatch" style="background:var(--status-critical)"></span>Fail ({failed})</span>'
            '</div>'
        )
        parts.append('</div>')

    # Top source IPs bar chart
    by_ip = {}
    for r in records:
        by_ip[r["source_ip"]] = by_ip.get(r["source_ip"], 0) + int(r["count"] or 0)
    top_ips = sorted(by_ip.items(), key=lambda kv: kv[1], reverse=True)[:10]
    if top_ips:
        max_count = top_ips[0][1] or 1
        parts.append('<div class="card"><h2>Top source IPs by message count</h2><div class="barlist">')
        for ip, count in top_ips:
            width_pct = round(100 * count / max_count)
            parts.append(
                '<div class="bar-row">'
                f'<div class="ip" title="{esc(ip)}">{esc(ip)}</div>'
                f'<div class="bar-track"><div class="bar-fill" style="width:{width_pct}%" '
                f'title="{esc(ip)}: {count} messages"></div></div>'
                f'<div class="count">{count}</div>'
                '</div>'
            )
        parts.append('</div></div>')

    # Policy panel
    parts.append('<div class="card"><h2>Published policy</h2><dl class="policy">')
    for label, key in (
        ("Domain", "policy_domain"), ("p", "policy_p"), ("sp", "policy_sp"),
        ("pct", "policy_pct"), ("adkim", "policy_adkim"), ("aspf", "policy_aspf"),
        ("Report ID", "report_id"), ("Contact", "email"),
    ):
        parts.append(f'<dt>{esc(label)}</dt><dd>{esc(report.get(key) or "-")}</dd>')
    parts.append('</dl></div>')

    # Full records table
    parts.append(f'<div class="card"><h2>{len(records)} record(s)</h2>')
    if records:
        parts.append('<table><thead><tr>'
                      '<th>Source IP</th><th class="num">Count</th><th>Header From</th>'
                      '<th>Disposition</th><th>DKIM</th><th>SPF</th><th>Overall</th>'
                      '</tr></thead><tbody>')
        for r in records:
            ok = r["dkim_aligned"] == "pass" or r["spf_aligned"] == "pass"
            badge_class = "pass" if ok else "fail"
            badge_label = "Pass" if ok else "Fail"
            parts.append(
                '<tr>'
                f'<td>{esc(r["source_ip"])}</td>'
                f'<td class="num">{esc(r["count"])}</td>'
                f'<td>{esc(r["header_from"])}</td>'
                f'<td>{esc(r["disposition"])}</td>'
                f'<td>{esc(r["dkim_aligned"])}</td>'
                f'<td>{esc(r["spf_aligned"])}</td>'
                f'<td><span class="status-badge {badge_class}">'
                f'<span class="dot"></span>{badge_label}</span></td>'
                '</tr>'
            )
        parts.append('</tbody></table>')
    else:
        parts.append('<p style="color:var(--text-muted)">No records in this report.</p>')
    parts.append('</div>')

    parts.append(PAGE_TAIL)
    return "".join(parts)


def parse_multipart(body: bytes, boundary: bytes):
    """Minimal multipart/form-data parser. Returns dict: field name -> (filename, bytes)."""
    delimiter = b"--" + boundary
    parts = body.split(delimiter)
    fields = {}
    for part in parts:
        part = part.strip(b"\r\n")
        if not part or part == b"--":
            continue
        if b"\r\n\r\n" not in part:
            continue
        header_blob, content = part.split(b"\r\n\r\n", 1)
        content = content.rstrip(b"\r\n")
        headers = {}
        for line in header_blob.split(b"\r\n"):
            if b":" in line:
                k, v = line.split(b":", 1)
                headers[k.strip().lower()] = v.strip()

        disposition = headers.get(b"content-disposition", b"").decode("latin-1")
        name = None
        filename = None
        for piece in disposition.split(";"):
            piece = piece.strip()
            if piece.startswith("name="):
                name = piece[5:].strip('"')
            elif piece.startswith("filename="):
                filename = piece[9:].strip('"')
        if name:
            fields[name] = (filename, content)
    return fields


class Handler(BaseHTTPRequestHandler):
    server_version = "DmarcRawdogger/1.0"

    def log_message(self, fmt, *args):
        pass  # keep the console quiet

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            self._send_html(PAGE_HEAD + UPLOAD_FORM + PAGE_TAIL)
        else:
            self.send_error(404, "Not found")

    def do_POST(self):
        path = urlparse(self.path).path
        if path != "/upload":
            self.send_error(404, "Not found")
            return

        content_type = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in content_type or "boundary=" not in content_type:
            self._send_html(render_error_page("Expected a multipart form upload"), status=400)
            return

        length = int(self.headers.get("Content-Length", 0))
        if length <= 0 or length > MAX_UPLOAD_BYTES:
            self._send_html(render_error_page("File missing or too large (limit 20 MB)"), status=400)
            return

        body = self.rfile.read(length)
        boundary = content_type.split("boundary=", 1)[1].strip().strip('"').encode("latin-1")
        fields = parse_multipart(body, boundary)

        upload = fields.get("report")
        if not upload or not upload[0]:
            self._send_html(render_error_page("No file was uploaded"), status=400)
            return

        filename, data = upload
        suffix = os.path.splitext(filename)[1] or ".xml"
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
                tmp.write(data)
                tmp_path = tmp.name
            report = core.load_report(tmp_path)
            self._send_html(render_report_html(report))
        except Exception as exc:
            self._send_html(render_error_page(str(exc)), status=400)
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.remove(tmp_path)

    def _send_html(self, content: str, status: int = 200):
        payload = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def main():
    parser = argparse.ArgumentParser(description="Local browser UI for DMARC Rawdogger")
    parser.add_argument("-p", "--port", type=int, default=8787)
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1, local only)")
    parser.add_argument("--no-browser", action="store_true", help="Don't auto-open a browser tab")
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    url = f"http://{args.host}:{args.port}/"
    print(f"DMARC Rawdogger running at {url}  (Ctrl+C to stop)")

    if not args.no_browser:
        webbrowser.open(url)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping.")
        server.shutdown()


if __name__ == "__main__":
    main()
