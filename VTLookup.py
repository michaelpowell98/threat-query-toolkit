#!/usr/bin/env python3
"""
VirusTotal IOC batch query (VT v3 API)

Features
- Prompts for: API key #1, free vs premium, optional free API key #2, input CSV path
- Accepts "any IOC" from the CSV: hashes (md5/sha1/sha256), domains, IPv4, URLs
- Free mode:
    - 15 seconds per request (4 RPM)
    - stops after 500 IOCs per free key (optionally +500 with a second free key)
- Premium mode:
    - no enforced delay
    - processes the full list
- Writes results incrementally AFTER EACH IOC to: <input>_vt_results.csv
- Shows a progress bar and the HTTP status code for each IOC
"""

import base64
import csv
import os
import re
import sys
import time
from datetime import datetime
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    print("Missing dependency: requests. Install with: pip install requests")
    sys.exit(1)

# ----------------------------
# IOC detection helpers
# ----------------------------
HASH_RE = re.compile(r"^(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})$")
IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$"
)
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+\.?$"
)

def looks_like_url(s: str) -> bool:
    s = s.strip()
    if not s:
        return False
    if "://" in s:
        p = urlparse(s)
        return bool(p.scheme and p.netloc)
    # scheme-less URL heuristic: has / and a dot in the host part
    if "/" in s and "." in s.split("/", 1)[0]:
        return True
    return False

def normalize_url(s: str) -> str:
    s = s.strip()
    if "://" not in s:
        s = "http://" + s
    return s

def vt_url_id(url: str) -> str:
    b = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii")
    return b.rstrip("=")

def detect_ioc_type(ioc: str) -> str:
    ioc = ioc.strip()
    if not ioc:
        return "empty"
    if HASH_RE.match(ioc):
        return "hash"
    if IPV4_RE.match(ioc):
        return "ip"
    if looks_like_url(ioc):
        return "url"
    if DOMAIN_RE.match(ioc) and " " not in ioc and "/" not in ioc:
        return "domain"
    return "unknown"


# ----------------------------
# Timer / rate limiting
# ----------------------------
def enforce_rate_limit(last_request_ts: float, seconds_per_request: float, show_countdown: bool = True) -> float:
    """
    Waits so that each request is at least `seconds_per_request` seconds apart.
    Returns the timestamp at which the request is allowed to fire.
    """
    if seconds_per_request <= 0:
        return time.time()

    now = time.time()
    elapsed = now - last_request_ts
    remaining = seconds_per_request - elapsed

    if remaining > 0:
        if show_countdown:
            # Live countdown on one line
            while remaining > 0:
                sys.stdout.write(f"\r[Timer] Waiting {remaining:5.1f}s to respect rate limit... ")
                sys.stdout.flush()
                sleep_chunk = 1.0 if remaining > 1.0 else remaining
                time.sleep(sleep_chunk)
                remaining -= sleep_chunk
            sys.stdout.write("\r" + " " * 60 + "\r")
            sys.stdout.flush()
        else:
            print(f"\n[Timer] Sleeping {remaining:.2f}s to respect API rate limit...")
            time.sleep(remaining)

    return time.time()


# ----------------------------
# VT query logic
# ----------------------------
def vt_get(session: requests.Session, api_key: str, endpoint: str, timeout: int = 30):
    url = f"https://www.virustotal.com/api/v3/{endpoint.lstrip('/')}"
    headers = {"x-apikey": api_key}
    try:
        resp = session.get(url, headers=headers, timeout=timeout)
        return resp, None
    except requests.RequestException as e:
        return None, str(e)

def extract_common_fields(ioc: str, ioc_type: str, resp_json: dict) -> dict:
    out = {
        "ioc": ioc,
        "type": ioc_type,
        "vt_object_id": "",
        "malicious": "",
        "suspicious": "",
        "harmless": "",
        "undetected": "",
        "timeout": "",
        "reputation": "",
        "last_analysis_date_utc": "",
        "vt_link": "",
        "note": "",
    }

    data = resp_json.get("data") if isinstance(resp_json, dict) else None
    if not isinstance(data, dict):
        out["note"] = "Unexpected VT response shape"
        return out

    out["vt_object_id"] = str(data.get("id", ""))

    attrs = data.get("attributes", {})
    if isinstance(attrs, dict):
        stats = attrs.get("last_analysis_stats", {})
        if isinstance(stats, dict):
            out["malicious"] = stats.get("malicious", "")
            out["suspicious"] = stats.get("suspicious", "")
            out["harmless"] = stats.get("harmless", "")
            out["undetected"] = stats.get("undetected", "")
            out["timeout"] = stats.get("timeout", "")

        out["reputation"] = attrs.get("reputation", "")

        lad = attrs.get("last_analysis_date")
        if isinstance(lad, int):
            out["last_analysis_date_utc"] = datetime.utcfromtimestamp(lad).isoformat() + "Z"

    if ioc_type == "hash":
        out["vt_link"] = f"https://www.virustotal.com/gui/file/{ioc}"
    elif ioc_type == "domain":
        out["vt_link"] = f"https://www.virustotal.com/gui/domain/{ioc.rstrip('.')}"
    elif ioc_type == "ip":
        out["vt_link"] = f"https://www.virustotal.com/gui/ip-address/{ioc}"
    elif ioc_type == "url":
        out["vt_link"] = f"https://www.virustotal.com/gui/url/{vt_url_id(normalize_url(ioc))}"

    return out

def query_vt_ioc(session: requests.Session, api_key: str, ioc: str, ioc_type: str):
    """
    Returns: (http_status, result_dict)
    """
    if ioc_type == "hash":
        endpoint = f"files/{ioc}"
    elif ioc_type == "domain":
        endpoint = f"domains/{ioc.rstrip('.')}"
    elif ioc_type == "ip":
        endpoint = f"ip_addresses/{ioc}"
    elif ioc_type == "url":
        endpoint = f"urls/{vt_url_id(normalize_url(ioc))}"
    else:
        return 0, {
            "ioc": ioc,
            "type": ioc_type,
            "vt_object_id": "",
            "malicious": "",
            "suspicious": "",
            "harmless": "",
            "undetected": "",
            "timeout": "",
            "reputation": "",
            "last_analysis_date_utc": "",
            "vt_link": "",
            "note": "Unsupported/unknown IOC type",
        }

    resp, err = vt_get(session, api_key, endpoint)
    if err:
        return 0, {
            "ioc": ioc,
            "type": ioc_type,
            "vt_object_id": "",
            "malicious": "",
            "suspicious": "",
            "harmless": "",
            "undetected": "",
            "timeout": "",
            "reputation": "",
            "last_analysis_date_utc": "",
            "vt_link": "",
            "note": f"Request error: {err}",
        }

    status = resp.status_code
    try:
        payload = resp.json()
    except ValueError:
        payload = {"error": {"message": (resp.text or "")[:500]}}

    if status == 200:
        return status, extract_common_fields(ioc, ioc_type, payload)

    # Still write a row on errors
    msg = ""
    if isinstance(payload, dict):
        if isinstance(payload.get("error"), dict):
            msg = payload["error"].get("message", "") or ""

    if status == 404:
        note = "Not found in VT"
    elif status == 401:
        note = "Unauthorized (bad API key?)"
    elif status == 429:
        note = "Rate limited (429)"
    else:
        note = f"HTTP {status}"

    if msg:
        note = (note + f": {msg}")[:300]

    return status, {
        "ioc": ioc,
        "type": ioc_type,
        "vt_object_id": "",
        "malicious": "",
        "suspicious": "",
        "harmless": "",
        "undetected": "",
        "timeout": "",
        "reputation": "",
        "last_analysis_date_utc": "",
        "vt_link": "",
        "note": note,
    }


# ----------------------------
# CSV helpers
# ----------------------------
def read_iocs_from_csv(path: str):
    """
    Reads ANY non-empty cell from the CSV as a candidate IOC (deduplicated, order-preserving).
    """
    seen = set()
    iocs = []
    with open(path, "r", newline="", encoding="utf-8-sig") as f:
        reader = csv.reader(f)
        for row in reader:
            for cell in row:
                val = (cell or "").strip()
                if not val:
                    continue
                if val in seen:
                    continue
                seen.add(val)
                iocs.append(val)
    return iocs

def make_output_path(input_path: str) -> str:
    base, ext = os.path.splitext(input_path)
    if not ext:
        ext = ".csv"
    return f"{base}_vt_results{ext}"

def append_row(path: str, fieldnames: list, row: dict):
    file_exists = os.path.exists(path)
    with open(path, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        if not file_exists:
            w.writeheader()
        w.writerow(row)
        f.flush()


# ----------------------------
# Progress display
# ----------------------------
def print_progress(i: int, total: int, status: int, ioc: str):
    bar_len = 28
    filled = int(bar_len * i / total) if total else bar_len
    bar = "#" * filled + "-" * (bar_len - filled)
    status_txt = str(status) if status else "ERR"
    msg = f"[{bar}] {i}/{total}  status={status_txt}  ioc={ioc[:60]}"
    sys.stdout.write("\r" + msg + " " * 10)
    sys.stdout.flush()
    if i == total:
        sys.stdout.write("\n")


# ----------------------------
# Main
# ----------------------------
def main():
    print("VirusTotal IOC CSV Query (VT v3)\n")

    api_key1 = input("Enter VirusTotal API key #1: ").strip()
    if not api_key1:
        print("No API key provided. Exiting.")
        sys.exit(1)

    free_answer = input("Is this a FREE API key? (y/n): ").strip().lower()
    is_free = free_answer.startswith("y")

    api_key2 = ""
    if is_free:
        second = input("Do you have a SECOND FREE API key to add another 500 queries? (y/n): ").strip().lower()
        if second.startswith("y"):
            api_key2 = input("Enter VirusTotal API key #2: ").strip()

    csv_path = input("Enter path to input CSV: ").strip().strip('"')
    if not csv_path or not os.path.exists(csv_path):
        print("CSV path not found. Exiting.")
        sys.exit(1)

    # Timer configuration
    seconds_per_request = 15.0 if is_free else 0.0  # free: 4 RPM; premium: no enforced delay
    show_countdown = True

    # Load IOCs
    iocs = read_iocs_from_csv(csv_path)
    if not iocs:
        print("No IOCs found in the CSV. Exiting.")
        sys.exit(1)

    # Cap logic
    if is_free:
        cap_per_key = 500
        capacity = cap_per_key + (cap_per_key if api_key2 else 0)
        to_process = iocs[:capacity]
    else:
        to_process = iocs

    out_path = make_output_path(csv_path)

    fieldnames = [
        "ioc", "type", "vt_object_id",
        "malicious", "suspicious", "harmless", "undetected", "timeout",
        "reputation", "last_analysis_date_utc", "vt_link", "note"
    ]

    print(f"\nInput IOCs found: {len(iocs)}")
    print(f"Will process:      {len(to_process)}")
    print(f"Mode:              {'FREE (15s/query, 500/key)' if is_free else 'PREMIUM (no delay)'}")
    print(f"Output report:     {out_path}\n")

    session = requests.Session()
    last_req_ts = 0.0

    # Plan which key to use for each chunk
    key_plan = []
    if is_free:
        first_count = min(500, len(to_process))
        key_plan.append((api_key1, first_count))
        if api_key2 and len(to_process) > first_count:
            key_plan.append((api_key2, len(to_process) - first_count))
    else:
        key_plan.append((api_key1, len(to_process)))

    idx = 0
    processed = 0
    total = len(to_process)

    for key, count in key_plan:
        for _ in range(count):
            ioc = to_process[idx]
            idx += 1

            ioc_type = detect_ioc_type(ioc)

            # Enforce timing (free tier)
            last_req_ts = enforce_rate_limit(last_req_ts, seconds_per_request, show_countdown=show_countdown)

            status, result = query_vt_ioc(session, key, ioc, ioc_type)

            # If rate-limited, back off and retry once (still write final result row either way)
            if status == 429 and is_free:
                time.sleep(60)
                last_req_ts = time.time()
                status, result = query_vt_ioc(session, key, ioc, ioc_type)

            append_row(out_path, fieldnames, result)

            processed += 1
            print_progress(processed, total, status, ioc)

    print("\nDone.")
    if is_free and len(iocs) > len(to_process):
        print(f"Note: FREE mode capped processing at {len(to_process)} IOC(s) based on key capacity.")


if __name__ == "__main__":
    main()
