# threat-query-toolkit
A collection of Python utilities for bulk-checking hashes, domains, and IPs against various threat intelligence platforms (URLhaus, VirusTotal, ThreatFox, etc.) using CSV input.

This README provides a concise overview of the **VTLookup.py** script, designed for security analysts to automate VirusTotal (VT) API v3 queries for batch Indicators of Compromise (IOCs).

---

## VirusTotal IOC Batch Lookup (VTLookup.py)

A robust Python tool for querying VirusTotal v3 APIs. It processes lists of IOCs from a CSV file, handles rate limiting for free-tier users, and generates an incremental report.

### Key Features

* **Multi-Type Support:** Automatically detects and queries Hashes (MD5/SHA1/SHA256), IPv4 addresses, Domains, and URLs.
* **Smart Rate Limiting:** * **Free Mode:** Enforces a 15-second delay (4 RPM) and supports up to two API keys (1,000 queries total).
* **Premium Mode:** No enforced delay for full-speed processing.


* **Incremental Saving:** Writes results to a CSV after **every** IOC, preventing data loss if the script is interrupted.
* **Progress Tracking:** Includes a real-time progress bar, HTTP status codes, and a countdown timer for rate limits.

### Prerequisites

* Python 3.x
* `requests` library

```bash
pip install requests

```

### Usage

1. **Prepare Input:** Create a CSV file containing your IOCs in any column. The script will deduplicate and extract them automatically.
2. **Run the Script:**
```bash
python VTLookup.py

```


3. **Follow Prompts:** Provide your API key(s), specify if they are Free or Premium, and enter the path to your input CSV.

### Output

The script generates a new file named `<original_filename>_vt_results.csv` containing:

* **Detection Stats:** Malicious, Suspicious, Harmless, and Undetected counts.
* **Metadata:** Reputation score, last analysis date (UTC), and a direct VirusTotal GUI link.
* **Status Notes:** Detailed error messages (e.g., "Not found" or "Rate limited").

---

This README provides a clear overview of the **urlhaus.py** script, which automates bulk lookups of domain names against the **URLhaus API** (v1) to identify potential malware distribution sites.

---

## URLhaus Bulk Domain Lookup

A Python-based utility for security researchers to check lists of domains or hosts against the URLhaus database. It identifies hosts associated with malicious URLs and retrieves reputation data from secondary blacklists like Spamhaus and SURBL.

### Key Features

* **Automated Normalization:** Cleans input data by removing protocols (`http://`), paths, and trailing dots to ensure accurate domain lookups.
* **Bulk Processing:** Reads domains from a CSV file, deduplicates them, and performs sequential lookups.
* **Live Reporting:** * **CSV Output:** Appends results row-by-row to a CSV file to prevent data loss.
* **JSON Output:** Generates a full JSON dump of raw API responses at the end of the run for deep analysis.


* **Reputation Context:** Captures specialized fields including `url_count` (number of known malicious URLs on that host), `firstseen` timestamps, and status on the **Spamhaus DBL** and **SURBL** blacklists.

### Prerequisites

* Python 3.x
* `requests` library
* A valid **URLhaus Auth-Key** (managed via environment variable)

```bash
pip install requests

```

### Usage

1. **Set Your API Key:** The script requires an environment variable named `THREATFOX_AUTH_KEY` (used by the script to authenticate with the URLhaus/Abuse.ch API).
```bash
# Linux/macOS
export THREATFOX_AUTH_KEY="your_api_key_here"

# Windows (Command Prompt)
set THREATFOX_AUTH_KEY=your_api_key_here

```


2. **Run the Script:**
```bash
python urlhaus.py --in input_domains.csv --out project_name --sleep 0.5

```


3. **Arguments:**
* `--in`: Path to the input CSV (domains should be in the first column).
* `--out`: Prefix for the output files (defaults to `urlhaus_results`).
* `--sleep`: Delay between requests in seconds (default is 0.5s to respect API rate limits).



### Output Fields

The resulting CSV includes:

* **input_host**: The normalized domain queried.
* **query_status**: "ok" if the host was found in the database.
* **url_count**: The number of malicious URLs associated with this host.
* **urlhaus_reference**: A direct link to the URLhaus host report.
* **spamhaus_dbl / surbl**: Blacklist status for additional reputation context.

---

