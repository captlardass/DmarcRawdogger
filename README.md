# DMARC Rawdogger

A small, dependency-free Python tool that turns raw DMARC aggregate reports
into a human-readable summary.

It accepts the report in whatever form it actually shows up in:

- **Mail file** (`.eml`, `.msg`) — the DMARC attachment (`.xml`, `.gz`, or
  `.zip`) is located and extracted automatically.
- **Raw report file** — `.gz`, `.zip`, or plain `.xml`.
- **CSV export** — a flat `.csv` of DMARC records.

## Requirements

- Python 3.8+ (standard library only, no extra packages to install)

## Usage

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
