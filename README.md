# DMARC Rawdogger

A small, dependency-free Python tool that turns raw DMARC aggregate reports
into a human-readable summary — as a CLI or as a local browser dashboard.

It accepts the report in whatever form it actually shows up in:

- **Mail file** (`.eml`, `.msg`) — the DMARC attachment (`.xml`, `.gz`, or
  `.zip`) is located and extracted automatically.
- **Raw report file** — `.gz`, `.zip`, or plain `.xml`.
- **CSV export** — a flat `.csv` of DMARC records.

## Requirements

- Python 3.8+ (standard library only, no extra packages to install)

## Browser UI

`dmarc_web.py` runs a small local web server with a drag-and-drop-style upload
form and a visual report: KPI tiles, a pass/fail breakdown bar, a top-source-IP
chart, the published policy, and the full record table.

```
python dmarc_web.py
```

This opens `http://127.0.0.1:8787/` in your default browser. Upload a report
file there to see the dashboard. The server only binds to your local machine
(`127.0.0.1`) — it's not reachable from the network — and uploaded files are
processed in memory/a temp file and deleted immediately after rendering,
nothing is persisted.

Options:

```
python dmarc_web.py --port 9000       # use a different port
python dmarc_web.py --no-browser      # don't auto-open a browser tab
```

## Command line

```
python dmarc_rawdogger.py <input-file> [-o output.txt]
```

- `<input-file>` — path to a `.eml`, `.gz`, `.zip`, `.xml`, or `.csv` DMARC report.
- `-o, --output` — optional path to write the report to instead of printing to stdout.

### Example

```
python dmarc_rawdogger.py "domeneshop.no!ligaard.net!1776297600!1776383999.xml.gz"
```

This prints the report metadata (reporting organization, contact, report ID,
date range), the published DMARC policy, pass/fail totals, and a per-record
breakdown showing source IP, message count, disposition, and SPF/DKIM
alignment results.

## CSV format

If you're feeding it a CSV export instead of the native XML, column names are
matched flexibly (case-insensitive) against:

`source_ip`, `count`, `disposition`, `dkim_aligned`, `spf_aligned`,
`header_from`, `dkim_domain`, `dkim_selector`, `dkim_result`, `spf_domain`,
`spf_result`
