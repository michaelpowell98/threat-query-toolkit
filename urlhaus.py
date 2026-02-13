import csv
import json
import os
import time
import requests

API_URL = "https://urlhaus-api.abuse.ch/v1/host/"


def normalize_domain(s):
    s = (s or "").strip()
    if not s:
        return None
    s = s.replace("http://", "").replace("https://", "")
    s = s.split("/")[0]
    s = s.strip(".").lower()
    return s or None


def read_domains(csv_file):
    domains = []
    with open(csv_file, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row:
                continue
            d = normalize_domain(row[0])
            if d and d.lower() not in ("domain", "host", "fqdn"):
                domains.append(d)

    # De-duplicate
    seen = set()
    unique = []
    for d in domains:
        if d not in seen:
            seen.add(d)
            unique.append(d)

    return unique


def urlhaus_lookup(auth_key, host):
    headers = {"Auth-Key": auth_key}
    r = requests.post(API_URL, headers=headers, data={"host": host}, timeout=30)
    return r.status_code, r.json()


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Live-writing URLhaus bulk lookup")
    parser.add_argument("--in", dest="input_csv", required=True)
    parser.add_argument("--out", dest="output_prefix", default="urlhaus_results")
    parser.add_argument("--sleep", dest="sleep_time", type=float, default=0.5)
    args = parser.parse_args()

    auth_key = os.getenv("THREATFOX_AUTH_KEY")
    if not auth_key:
        print("ERROR: THREATFOX_AUTH_KEY not set.")
        return

    hosts = read_domains(args.input_csv)
    if not hosts:
        print("No valid domains found.")
        return

    csv_file = f"{args.output_prefix}.csv"
    json_file = f"{args.output_prefix}.json"

    # Create CSV immediately with header
    fieldnames = [
        "input_host",
        "http_status",
        "query_status",
        "url_count",
        "urlhaus_reference",
        "firstseen",
        "spamhaus_dbl",
        "surbl"
    ]

    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

    print(f"Created {csv_file} — writing live results...", flush=True)

    raw_results = []

    for i, host in enumerate(hosts, start=1):
        print(f"[{i}/{len(hosts)}] Checking {host}...", flush=True)

        try:
            status_code, resp = urlhaus_lookup(auth_key, host)
        except Exception as e:
            print(f"   ERROR: {e}", flush=True)
            continue

        query_status = resp.get("query_status")
        url_count = resp.get("url_count", 0) or 0

        print(f"   HTTP={status_code} query_status={query_status} url_count={url_count}", flush=True)

        if status_code == 200 and query_status == "ok" and int(url_count) > 0:
            print("   MATCH FOUND", flush=True)
        else:
            print("   No match", flush=True)

        row = {
            "input_host": host,
            "http_status": status_code,
            "query_status": query_status,
            "url_count": url_count,
            "urlhaus_reference": resp.get("urlhaus_reference"),
            "firstseen": resp.get("firstseen"),
            "spamhaus_dbl": (resp.get("blacklists") or {}).get("spamhaus_dbl"),
            "surbl": (resp.get("blacklists") or {}).get("surbl")
        }

        # Append row immediately
        with open(csv_file, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writerow(row)
            f.flush()

        raw_results.append({
            "input_host": host,
            "http_status": status_code,
            "response": resp
        })

        time.sleep(args.sleep_time)

    # Write JSON at end
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(raw_results, f, indent=2)

    print(f"\nDone. Final JSON written to {json_file}", flush=True)


if __name__ == "__main__":
    main()
