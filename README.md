# SQL Injection Security Scanner

> **For authorised security testing only.** Only run this tool against systems you own or have explicit written permission to test.

---

## Project Structure

```
security-scanner/
├── app/
│   ├── main.py                  # CLI entry point
│   ├── crawler/
│   │   ├── crawler.py           # BFS web crawler
│   │   └── extractor.py         # HTML form / link / param extractor
│   ├── scanner/
│   │   ├── sql_scanner.py       # Fires payloads, collects results
│   │   ├── payloads.py          # SQLi payload library
│   │   └── detector.py          # Response analysis (error/blind/time/union)
│   ├── analyzer/
│   │   └── input_analyzer.py    # Static pattern analysis on raw strings
│   ├── models/
│   │   └── result.py            # ScanResult / Vulnerability dataclasses
│   └── utils/
│       └── logger.py            # Coloured console logger
├── requirements.txt
└── README.md
```

---

## Installation

```bash
pip install -r requirements.txt
```

---

## Usage

### Mode 1 — Web Scanner (crawl a domain)

Crawls the target domain, discovers all forms and URL parameters, then tests each one for SQL injection.

```bash
python -m app.main web --url https://target.example.com
```

Options:
| Flag | Default | Description |
|------|---------|-------------|
| `--url` | required | Seed URL to start crawling |
| `--max-pages` | 50 | Maximum pages to crawl |
| `--delay` | 0.3 | Seconds between requests |
| `--output` | — | Save JSON report to file |

```bash
# Crawl up to 100 pages, save report
python -m app.main web --url https://target.example.com --max-pages 100 --output report.json
```

---

### Mode 2 — API Security Tester

Tests a single API endpoint by injecting payloads into the provided parameters.

```bash
# Query-string style params
python -m app.main api --url https://api.example.com/users --params "id=1&name=admin"

# JSON-style params
python -m app.main api --url https://api.example.com/login --params '{"username":"admin","password":"test"}' --method POST

# Save results
python -m app.main api --url https://api.example.com/users --params "id=1" --output api_report.json
```

Options:
| Flag | Default | Description |
|------|---------|-------------|
| `--url` | required | API endpoint URL |
| `--params` | required | Parameters as `key=val&key2=val2` or JSON |
| `--method` | GET | HTTP method: GET, POST, PUT, PATCH |
| `--delay` | 0.3 | Seconds between requests |
| `--output` | — | Save JSON report to file |

---

### Mode 3 — Input Analyzer

Statically analyses a string for SQL injection patterns. No HTTP requests are made.

```bash
python -m app.main input --text "admin' OR '1'='1"
python -m app.main input --text "1; DROP TABLE users--"
python -m app.main input --text "' UNION SELECT username, password FROM users--"
```

Options:
| Flag | Default | Description |
|------|---------|-------------|
| `--text` | required | String to analyse |
| `--output` | — | Save JSON findings to file |

---

## Detection Techniques

| Technique | How it works |
|-----------|-------------|
| **Error-based** | Looks for DB error strings in the response body |
| **Boolean-based blind** | Compares response lengths for TRUE vs FALSE conditions |
| **Time-based blind** | Measures response time against a delay threshold |
| **UNION-based** | Detects version strings or numeric markers injected via UNION |
| **Static pattern** | Regex rules matching known SQLi patterns in raw input |

---

## Output (JSON report)

```json
{
  "summary": {
    "target": "https://example.com",
    "scan_type": "web",
    "total_vulnerabilities": 2,
    "severity_breakdown": { "LOW": 0, "MEDIUM": 0, "HIGH": 1, "CRITICAL": 1 },
    "scanned_urls": 12,
    "errors": 0
  },
  "vulnerabilities": [
    {
      "url": "https://example.com/search",
      "parameter": "q",
      "payload": "' OR '1'='1",
      "evidence": "DB error signature found: ...you have an error in your SQL syntax...",
      "severity": "MEDIUM",
      "type": "Error-based SQLi",
      "method": "GET"
    }
  ]
}
```

---

## Disclaimer

This tool is intended for **authorised penetration testing and security research only**.  
Unauthorised use against systems you do not own is illegal and unethical.
