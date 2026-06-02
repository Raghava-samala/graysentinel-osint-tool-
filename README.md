# graysentinel-osint-tool-
# Advanced IP Reputation Checker

## Description

Advanced IP Reputation Checker is a Python-based cybersecurity tool that performs IP reputation analysis using IPInfo and AbuseIPDB APIs.

The tool supports:

* Single IP scanning
* Bulk IP scanning from a file
* Geolocation lookup
* Reverse DNS resolution
* AbuseIPDB reputation checks
* Color-coded threat classification
* TXT and CSV report generation
* Concurrent scanning support

---

## Features

* IP Address Validation
* Bulk IP Analysis
* Reverse DNS Lookup
* Geolocation Information
* ASN / Organization Lookup
* AbuseIPDB Reputation Analysis
* TXT Report Export
* CSV Report Export
* Duplicate IP Detection
* Multi-threaded Scanning
* Scan Summary Statistics

---

## Installation

Install required packages:

```bash
pip install -r requirements.txt
```

---

## API Configuration

Open `ip_reputation_checker.py` and add your API keys:

```python
IPINFO_TOKEN = "YOUR_IPINFO_TOKEN"
ABUSEIPDB_API_KEY = "YOUR_ABUSEIPDB_API_KEY"
```

---

## Usage

Run the tool:

```bash
python ip_reputation_checker.py
```

---

## Example Input

```text
8.8.8.8
```

---

## Example Output

```text
IP Address     : 8.8.8.8
Organization   : AS15169 Google LLC
Country        : US
Abuse Score    : 0%
Status         : CLEAN
```

---

## Requirements

* Python 3.x
* Internet Connection
* IPInfo API Token
* AbuseIPDB API Key

---

## Author

Raghavaraj
---

## License

For Educational and Portfolio Purposes.
