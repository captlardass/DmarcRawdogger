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

### SPF cross-check

As soon as a report is analyzed, it automatically does a **live DNS lookup**
of the report's top-level (policy) domain's current SPF TXT record and
compares it against what the report recorded for each source IP checked
against that domain — no extra click needed.

For each source IP it shows the result the report saw at delivery time next
to what the *current* published record would produce today, and flags any
drift — e.g. a source that used to pass but would now fail (often means a
legitimate sender got dropped from the record), or one that used to fail but
would now pass. It also flags general SPF hygiene problems: more than 10
DNS-lookup mechanisms (RFC 7208's hard cap — beyond it receivers treat the
record as broken), a missing or catch-all (`+all`) `all` mechanism, or
multiple SPF records published for the same domain (invalid — causes every
check to fail).

Any source IPs that were SPF-checked against a *different* domain in the
report (typically a subdomain, e.g. `bounce.example.com`) are cross-checked
too, but kept out of the way behind a collapsed **"Show subdomains"** toggle
under the main table, so the top-level result stays the headline.

Below that, a "Check SPF now" box lets you re-run the check against any other
domain on demand (handy right after editing a record, to confirm the fix).

This does a real outbound DNS query (UDP port 53, no external packages —
it's a small built-in DNS client) to `1.1.1.1` / `8.8.8.8`, so it needs
unfiltered outbound DNS access. If your network blocks that, the panel will
say so instead of hanging. Since SPF records are public DNS data, no
credentials or private information are involved.

This is a best-effort evaluator for diagnosing drift, not an RFC-7208-exact
implementation — SPF macros (`exists:`, `%{i}`) and the deprecated `ptr`
mechanism are skipped rather than evaluated.

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
