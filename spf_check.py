#!/usr/bin/env python3
"""Live SPF record lookup + evaluation, and cross-checking against DMARC report data.

No third-party packages: this ships a tiny raw-UDP DNS client (A/AAAA/MX/TXT)
built on `socket` + `struct`, plus a best-effort SPF (RFC 7208) evaluator.

This is a diagnostic/hygiene helper, not an RFC-7208-compliant MTA implementation:
macros (%{i}, exists:), PTR mechanisms, and dual-cidr ("a/24//64") forms are
skipped rather than evaluated, since they're rare and not needed to answer
"does this source IP align with the current SPF record".
"""

import ipaddress
import re
import socket
import struct
import time

DEFAULT_RESOLVERS = ["1.1.1.1", "8.8.8.8"]
RESOLVER_TIMEOUT = 1.5
MAX_DNS_LOOKUPS = 10  # RFC 7208 4.6.4
CACHE_TTL = 300

QTYPE = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28}
QUALIFIER_RESULT = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}
MECH_RE = re.compile(r"^(?P<mech>[A-Za-z0-9]+)(?::(?P<value>[^/]+))?(?:/(?P<cidr4>\d+))?(?://(?P<cidr6>\d+))?$")

_cache = {}


def _cache_get(key):
    hit = _cache.get(key)
    if hit and time.time() - hit[0] < CACHE_TTL:
        return hit[1]
    return None


def _cache_set(key, value):
    _cache[key] = (time.time(), value)


# ---------------------------------------------------------------------------
# Minimal raw-UDP DNS client
# ---------------------------------------------------------------------------

def _build_query(name: str, qtype: int):
    import random
    tid = random.randint(0, 0xFFFF)
    # ARCOUNT=1 for the EDNS0 OPT record below, so resolvers can reply with
    # answers bigger than the classic 512-byte UDP limit instead of truncating.
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 1)
    qname = b"".join(
        bytes([len(label)]) + label.encode("ascii", errors="ignore")
        for label in name.rstrip(".").split(".") if label
    ) + b"\x00"
    question = qname + struct.pack(">HH", qtype, 1)
    # EDNS0 OPT pseudo-record: root name, TYPE=41, CLASS=UDP payload size (4096),
    # extended-RCODE/flags=0, RDLENGTH=0.
    opt_record = b"\x00" + struct.pack(">HHIH", 41, 4096, 0, 0)
    return tid, header + question + opt_record


def _read_name(data: bytes, offset: int):
    labels = []
    jumped = False
    end_offset = offset
    steps = 0
    while offset < len(data) and steps < 128:
        steps += 1
        length = data[offset]
        if length == 0:
            if not jumped:
                end_offset = offset + 1
            break
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                end_offset = offset + 2
            jumped = True
            offset = pointer
            continue
        offset += 1
        labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
        offset += length
        if not jumped:
            end_offset = offset
    return ".".join(labels), end_offset


def _raw_query(name: str, qtype: int, resolvers, timeout: float):
    tid, packet = _build_query(name, qtype)
    last_err = None
    for resolver in resolvers:
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(packet, (resolver, 53))
            data, _ = sock.recvfrom(8192)
            if len(data) < 12:
                continue
            resp_id, flags, qdcount, ancount, _, _ = struct.unpack(">HHHHHH", data[:12])
            if resp_id != tid:
                continue
            rcode = flags & 0x000F
            offset = 12
            for _ in range(qdcount):
                _, offset = _read_name(data, offset)
                offset += 4
            answers = []
            for _ in range(ancount):
                _, offset = _read_name(data, offset)
                if offset + 10 > len(data):
                    break
                atype, _aclass, _ttl, rdlen = struct.unpack(">HHIH", data[offset:offset + 10])
                offset += 10
                rd_start = offset
                rdata = data[offset:offset + rdlen]
                offset += rdlen
                answers.append((atype, rdata, rd_start))
            return rcode, answers, data
        except (socket.timeout, OSError) as exc:
            last_err = exc
            continue
        finally:
            if sock is not None:
                sock.close()
    raise RuntimeError(f"no response from {resolvers} ({last_err})")


def resolve(name: str, qtype_name: str, resolvers=None, timeout: float = RESOLVER_TIMEOUT):
    """Returns (values, status). status is 'ok' | 'nxdomain' | 'error'."""
    resolvers = resolvers or DEFAULT_RESOLVERS
    cache_key = (name.lower(), qtype_name)
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    qtype = QTYPE[qtype_name]
    try:
        rcode, answers, data = _raw_query(name, qtype, resolvers, timeout)
    except RuntimeError as exc:
        return [], f"error: {exc}"

    if rcode == 3:
        result = ([], "nxdomain")
        _cache_set(cache_key, result)
        return result
    if rcode != 0:
        return [], f"error: dns rcode {rcode}"

    results = []
    cname_target = None
    for atype, rdata, rd_start in answers:
        if atype == qtype:
            if qtype_name == "TXT":
                pos, parts = 0, []
                while pos < len(rdata):
                    ln = rdata[pos]
                    parts.append(rdata[pos + 1:pos + 1 + ln].decode("ascii", errors="replace"))
                    pos += 1 + ln
                results.append("".join(parts))
            elif qtype_name == "A":
                results.append(socket.inet_ntoa(rdata))
            elif qtype_name == "AAAA":
                results.append(socket.inet_ntop(socket.AF_INET6, rdata))
            elif qtype_name == "MX":
                pref = struct.unpack(">H", rdata[:2])[0]
                exchange, _ = _read_name(data, rd_start + 2)
                results.append((pref, exchange))
        elif atype == QTYPE["CNAME"]:
            cname_target, _ = _read_name(data, rd_start)

    if not results and cname_target and cname_target.lower() != name.lower():
        result = resolve(cname_target, qtype_name, resolvers, timeout)
        _cache_set(cache_key, result)
        return result

    result = (results, "ok")
    _cache_set(cache_key, result)
    return result


# ---------------------------------------------------------------------------
# SPF record retrieval + hygiene checks
# ---------------------------------------------------------------------------

def get_spf_records(domain: str, resolvers=None):
    """Returns (list_of_spf_txt_records, error_message_or_None)."""
    txts, status = resolve(domain, "TXT", resolvers)
    if status == "nxdomain":
        return [], None
    if status.startswith("error"):
        return None, f"Could not reach DNS resolvers to look up {domain} ({status}). " \
                      "The network may be blocking outbound DNS (UDP/53)."
    return [t for t in txts if t.lower().startswith("v=spf1")], None


def domain_health(domain: str, resolvers=None):
    """Hygiene report for a domain's published SPF record (lookup count, +all, etc)."""
    records, error = get_spf_records(domain, resolvers)
    out = {"domain": domain, "record": None, "warnings": [], "error": error, "lookup_count": None}
    if error:
        return out
    if not records:
        out["warnings"].append("No SPF (v=spf1) TXT record found for this domain.")
        return out
    if len(records) > 1:
        out["warnings"].append(
            f"{len(records)} SPF records found for this domain - only one is allowed per "
            "RFC 7208; multiple records cause a permanent SPF failure (permerror)."
        )
    record = records[0]
    out["record"] = record
    tokens = record.split()[1:]
    lookup_count = 0
    all_mech = None
    for tok in tokens:
        body = tok[1:] if tok and tok[0] in "+-~?" else tok
        low = body.lower()
        if low == "all":
            all_mech = tok
            continue
        if low.startswith("redirect="):
            lookup_count += 1
            continue
        mech_name = low.split(":", 1)[0].split("/", 1)[0]
        if mech_name in ("include", "a", "mx", "ptr", "exists"):
            lookup_count += 1
    out["lookup_count"] = lookup_count
    if lookup_count > MAX_DNS_LOOKUPS:
        out["warnings"].append(
            f"{lookup_count} DNS-lookup mechanisms in the record - RFC 7208 caps this at "
            f"{MAX_DNS_LOOKUPS}; receivers may treat the whole record as a permerror."
        )
    if not all_mech:
        out["warnings"].append(
            "No 'all' mechanism at the end of the record - unmatched senders fall through as "
            "neutral rather than being explicitly allowed or denied."
        )
    elif all_mech.startswith("+") or all_mech == "all":
        out["warnings"].append(
            "Catch-all is '+all' - this authorizes ANY server to send as this domain and "
            "defeats the purpose of SPF. Use '-all' (or '~all' while testing) instead."
        )
    return out


# ---------------------------------------------------------------------------
# SPF evaluation for a specific (ip, domain) pair
# ---------------------------------------------------------------------------

def _parse_token(body: str):
    m = MECH_RE.match(body)
    if not m:
        return None, None, None, None
    return m.group("mech").lower(), m.group("value"), m.group("cidr4"), m.group("cidr6")


def evaluate_spf(ip: str, domain: str, resolvers=None, _lookups=None, _depth: int = 0):
    """Best-effort SPF evaluation. Returns dict: result, reason, record."""
    if _lookups is None:
        _lookups = [0]
    if _depth > MAX_DNS_LOOKUPS or _lookups[0] > MAX_DNS_LOOKUPS:
        return {"result": "permerror", "reason": "too many DNS-lookup mechanisms (RFC 7208 cap)", "record": None}

    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return {"result": "unknown", "reason": f"'{ip}' is not a valid IP address", "record": None}

    records, error = get_spf_records(domain, resolvers)
    if error:
        return {"result": "unknown", "reason": error, "record": None}
    if not records:
        return {"result": "none", "reason": f"no SPF record published for {domain}", "record": None}
    if len(records) > 1:
        return {"result": "permerror", "reason": f"{len(records)} SPF records published for {domain}", "record": records[0]}

    record = records[0]
    tokens = record.split()[1:]
    redirect_domain = None

    for tok in tokens:
        qualifier = "+"
        body = tok
        if tok and tok[0] in "+-~?":
            qualifier = tok[0]
            body = tok[1:]

        low = body.lower()
        if low == "all":
            return {"result": QUALIFIER_RESULT[qualifier], "reason": "matched 'all'", "record": record}
        if low.startswith("redirect="):
            redirect_domain = body.split("=", 1)[1]
            continue
        if low.startswith("exp="):
            continue

        mech, value, cidr4, cidr6 = _parse_token(body)
        if mech is None:
            continue

        try:
            if mech in ("ip4", "ip6"):
                if not value:
                    continue
                cidr = cidr4 if mech == "ip4" else cidr6
                default_bits = 32 if mech == "ip4" else 128
                network = ipaddress.ip_network(f"{value}/{cidr or default_bits}", strict=False)
                if ip_obj in network:
                    return {"result": QUALIFIER_RESULT[qualifier], "reason": f"matched {tok}", "record": record}

            elif mech == "a":
                _lookups[0] += 1
                target = value or domain
                qtype = "AAAA" if ip_obj.version == 6 else "A"
                addrs, status = resolve(target, qtype, resolvers)
                if status.startswith("error"):
                    continue
                cidr = cidr6 if ip_obj.version == 6 else cidr4
                bits = 128 if ip_obj.version == 6 else 32
                for addr in addrs:
                    if ip_obj in ipaddress.ip_network(f"{addr}/{cidr or bits}", strict=False):
                        return {"result": QUALIFIER_RESULT[qualifier], "reason": f"matched {tok}", "record": record}

            elif mech == "mx":
                _lookups[0] += 1
                target = value or domain
                mxs, status = resolve(target, "MX", resolvers)
                if status.startswith("error"):
                    continue
                qtype = "AAAA" if ip_obj.version == 6 else "A"
                for _pref, exchange in mxs:
                    addrs, a_status = resolve(exchange, qtype, resolvers)
                    if a_status.startswith("error"):
                        continue
                    for addr in addrs:
                        if ip_obj == ipaddress.ip_address(addr):
                            return {"result": QUALIFIER_RESULT[qualifier], "reason": f"matched {tok}", "record": record}

            elif mech == "include":
                if not value:
                    continue
                _lookups[0] += 1
                sub = evaluate_spf(ip, value, resolvers, _lookups, _depth + 1)
                if sub["result"] == "pass":
                    return {"result": QUALIFIER_RESULT[qualifier], "reason": f"matched include:{value}", "record": record}

            # ptr / exists: deprecated or macro-based - not evaluated
        except Exception:
            continue

    if redirect_domain:
        _lookups[0] += 1
        return evaluate_spf(ip, redirect_domain, resolvers, _lookups, _depth + 1)

    return {"result": "neutral", "reason": "no mechanism matched and no trailing 'all'", "record": record}


# ---------------------------------------------------------------------------
# Cross-check against a parsed DMARC report (see dmarc_rawdogger.load_report)
# ---------------------------------------------------------------------------

def cross_check_report(report: dict, domain: str = None, resolvers=None):
    """Compares each (source_ip, spf-checked-domain) pair seen in the report against
    a live SPF evaluation, and reports the health of the policy domain's own record."""
    policy_domain = domain or report.get("policy_domain") or ""
    health = domain_health(policy_domain, resolvers) if policy_domain else None

    pairs = {}  # (ip, spf_domain) -> {count, reported_result}
    for rec in report.get("records", []):
        ip = rec.get("source_ip")
        count = int(rec.get("count") or 0)
        spf_results = rec.get("spf_results") or []
        if not spf_results:
            spf_results = [{"domain": policy_domain, "result": rec.get("spf_aligned") or ""}]
        for spf in spf_results:
            spf_domain = spf.get("domain") or policy_domain
            key = (ip, spf_domain)
            entry = pairs.setdefault(key, {"ip": ip, "domain": spf_domain, "count": 0, "reported_result": spf.get("result") or ""})
            entry["count"] += count

    rows = []
    for (ip, spf_domain) in sorted(pairs, key=lambda k: -pairs[k]["count"]):
        entry = pairs[(ip, spf_domain)]
        if not spf_domain or not ip:
            continue
        live = evaluate_spf(ip, spf_domain, resolvers)
        reported = (entry["reported_result"] or "").lower()
        live_result = live["result"]
        if reported and live_result != "unknown":
            drift = reported != live_result
        else:
            drift = False
        rows.append({
            "ip": ip,
            "domain": spf_domain,
            "count": entry["count"],
            "reported_result": reported or "-",
            "live_result": live_result,
            "live_reason": live["reason"],
            "drift": drift,
        })

    return {"policy_domain": policy_domain, "health": health, "rows": rows}


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python spf_check.py <domain> <ip>")
        raise SystemExit(1)
    d, i = sys.argv[1], sys.argv[2]
    print("Domain health:", domain_health(d))
    print("Evaluation:", evaluate_spf(i, d))
