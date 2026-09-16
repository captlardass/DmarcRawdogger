#!/usr/bin/env python3
"""Parse DMARC aggregate reports (mail file, .gz, .zip, .xml, or .csv) into a human-readable summary."""

import argparse
import csv
import email
import gzip
import io
import sys
import zipfile
from email.message import Message
from xml.etree import ElementTree as ET


def sniff_xml_bytes(data: bytes) -> bytes:
    """Given raw bytes that might be gzip, zip, or plain XML, return the XML bytes."""
    if data[:2] == b"\x1f\x8b":
        return gzip.decompress(data)
    if data[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = [n for n in zf.namelist() if n.lower().endswith(".xml")]
            if not names:
                raise ValueError("Zip archive contains no .xml file")
            return zf.read(names[0])
    return data


def extract_from_eml(path: str) -> bytes:
    with open(path, "rb") as f:
        msg: Message = email.message_from_binary_file(f)

    for part in msg.walk():
        filename = part.get_filename()
        if not filename:
            continue
        lower = filename.lower()
        if lower.endswith((".xml", ".gz", ".zip")):
            payload = part.get_payload(decode=True)
            if payload:
                return sniff_xml_bytes(payload)

    raise ValueError("No DMARC report attachment (.xml/.gz/.zip) found in mail file")


def load_report_xml(path: str) -> bytes:
    lower = path.lower()
    if lower.endswith((".eml", ".msg", ".mail", ".txt")):
        return extract_from_eml(path)

    with open(path, "rb") as f:
        data = f.read()
    return sniff_xml_bytes(data)


def parse_xml_report(xml_bytes: bytes) -> dict:
    root = ET.fromstring(xml_bytes)

    meta = root.find("report_metadata")
    policy = root.find("policy_published")

    def text(el, tag, default=""):
        if el is None:
            return default
        found = el.find(tag)
        return found.text if found is not None and found.text else default

    report = {
        "org_name": text(meta, "org_name"),
        "email": text(meta, "email"),
        "report_id": text(meta, "report_id"),
        "date_begin": text(meta, "date_range/begin"),
        "date_end": text(meta, "date_range/end"),
        "policy_domain": text(policy, "domain"),
        "policy_p": text(policy, "p"),
        "policy_sp": text(policy, "sp"),
        "policy_pct": text(policy, "pct"),
        "policy_adkim": text(policy, "adkim"),
        "policy_aspf": text(policy, "aspf"),
        "records": [],
    }

    for record in root.findall("record"):
        row = record.find("row")
        policy_eval = row.find("policy_evaluated") if row is not None else None
        identifiers = record.find("identifiers")
        auth_results = record.find("auth_results")

        dkim_results = []
        spf_results = []
        if auth_results is not None:
            for dkim in auth_results.findall("dkim"):
                dkim_results.append({
                    "domain": text(dkim, "domain"),
                    "selector": text(dkim, "selector"),
                    "result": text(dkim, "result"),
                })
            for spf in auth_results.findall("spf"):
                spf_results.append({
                    "domain": text(spf, "domain"),
                    "result": text(spf, "result"),
                })

        report["records"].append({
            "source_ip": text(row, "source_ip"),
            "count": text(row, "count", "0"),
            "disposition": text(policy_eval, "disposition"),
            "dkim_aligned": text(policy_eval, "dkim"),
            "spf_aligned": text(policy_eval, "spf"),
            "header_from": text(identifiers, "header_from"),
            "dkim_results": dkim_results,
            "spf_results": spf_results,
        })

    return report


def parse_csv_report(path: str) -> dict:
    """Best-effort parser for a flat CSV export of DMARC records."""
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    if not rows:
        raise ValueError("CSV file has no data rows")

    def get(row, *names, default=""):
        for name in names:
            for key in row:
                if key.strip().lower() == name:
                    return row[key]
        return default

    report = {
        "org_name": "",
        "email": "",
        "report_id": "",
        "date_begin": "",
        "date_end": "",
        "policy_domain": "",
        "policy_p": "",
        "policy_sp": "",
        "policy_pct": "",
        "policy_adkim": "",
        "policy_aspf": "",
        "records": [],
    }

    for row in rows:
        dkim_domain = get(row, "dkim_domain", "dkim domain")
        dkim_result = get(row, "dkim_result", "dkim")
        spf_domain = get(row, "spf_domain", "spf domain")
        spf_result = get(row, "spf_result", "spf")

        report["records"].append({
            "source_ip": get(row, "source_ip", "ip", "source ip"),
            "count": get(row, "count", "message_count", default="0"),
            "disposition": get(row, "disposition"),
            "dkim_aligned": get(row, "dkim_aligned", "dkim_align", "dkim"),
            "spf_aligned": get(row, "spf_aligned", "spf_align", "spf"),
            "header_from": get(row, "header_from", "from_domain", "header from"),
            "dkim_results": [{"domain": dkim_domain, "selector": get(row, "dkim_selector"), "result": dkim_result}] if dkim_result else [],
            "spf_results": [{"domain": spf_domain, "result": spf_result}] if spf_result else [],
        })

    return report


def load_report(path: str) -> dict:
    if path.lower().endswith(".csv"):
        return parse_csv_report(path)
    xml_bytes = load_report_xml(path)
    return parse_xml_report(xml_bytes)


def fmt_timestamp(ts: str) -> str:
    if not ts or not ts.isdigit():
        return ts or "-"
    from datetime import datetime, timezone
    return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def render(report: dict) -> str:
    lines = []
    lines.append("=" * 60)
    lines.append("DMARC AGGREGATE REPORT SUMMARY")
    lines.append("=" * 60)
    lines.append(f"Reporting org : {report['org_name'] or '-'}")
    lines.append(f"Contact       : {report['email'] or '-'}")
    lines.append(f"Report ID     : {report['report_id'] or '-'}")
    lines.append(f"Date range    : {fmt_timestamp(report['date_begin'])}  ->  {fmt_timestamp(report['date_end'])}")
    lines.append("")
    lines.append(f"Policy domain : {report['policy_domain'] or '-'}")
    lines.append(
        f"Policy        : p={report['policy_p'] or '-'}  sp={report['policy_sp'] or '-'}  "
        f"pct={report['policy_pct'] or '-'}  adkim={report['policy_adkim'] or '-'}  aspf={report['policy_aspf'] or '-'}"
    )
    lines.append("")

    records = report["records"]
    total_msgs = sum(int(r["count"] or 0) for r in records)
    pass_msgs = sum(
        int(r["count"] or 0) for r in records
        if r["dkim_aligned"] == "pass" or r["spf_aligned"] == "pass"
    )
    fail_msgs = total_msgs - pass_msgs

    lines.append(f"Total messages     : {total_msgs}")
    lines.append(f"Aligned (pass)     : {pass_msgs}")
    lines.append(f"Not aligned (fail) : {fail_msgs}")
    lines.append("")
    lines.append("-" * 60)
    lines.append(f"{len(records)} record(s):")
    lines.append("-" * 60)

    for i, r in enumerate(records, 1):
        lines.append(f"\n[{i}] Source IP     : {r['source_ip'] or '-'}")
        lines.append(f"    Message count : {r['count'] or '0'}")
        lines.append(f"    Header From   : {r['header_from'] or '-'}")
        lines.append(f"    Disposition   : {r['disposition'] or '-'}")
        lines.append(f"    DKIM aligned  : {r['dkim_aligned'] or '-'}")
        lines.append(f"    SPF aligned   : {r['spf_aligned'] or '-'}")

        for dkim in r["dkim_results"]:
            if dkim.get("result"):
                lines.append(
                    f"      -> DKIM check: domain={dkim.get('domain') or '-'} "
                    f"selector={dkim.get('selector') or '-'} result={dkim.get('result')}"
                )
        for spf in r["spf_results"]:
            if spf.get("result"):
                lines.append(f"      -> SPF check : domain={spf.get('domain') or '-'} result={spf.get('result')}")

        overall = "PASS" if (r["dkim_aligned"] == "pass" or r["spf_aligned"] == "pass") else "FAIL"
        lines.append(f"    Overall       : {overall}")

    lines.append("\n" + "=" * 60)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Render a DMARC aggregate report as human-readable text.")
    parser.add_argument("input", help="Path to a .eml mail file, or a .gz/.zip/.xml/.csv DMARC report")
    parser.add_argument("-o", "--output", help="Write output to a file instead of stdout")
    args = parser.parse_args()

    try:
        report = load_report(args.input)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    text = render(report)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        print(f"Written to {args.output}")
    else:
        print(text)


if __name__ == "__main__":
    main()
