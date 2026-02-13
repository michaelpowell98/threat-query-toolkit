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

**Would you like me to add a specific section for troubleshooting common API errors or explain how to format the input CSV more specifically?**
