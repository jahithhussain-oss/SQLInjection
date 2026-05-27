# SQL Injection Security Scanner

> **For authorised security testing only.** Only run this tool against systems you own or have explicit written permission to test.

---

## Project Structure

```
security-scanner/
├── app/
│   ├── main.py                  # CLI entry point
│   ├── web/
│   │   ├── app.py               # Flask application factory
│   │   ├── routes.py            # Flask routes (web UI API)
│   │   ├── templates/
│   │   │   └── index.html       # Single-page web UI
│   │   └── static/
│   │       ├── style.css        # Dark-theme stylesheet
│   │       └── app.js           # Frontend logic
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

## Running the Web Application

The web UI is the recommended way to use the scanner. It wraps all three modes in a browser-based dashboard.

### Start the server

```bash
python -m app.web.app
```

Then open **http://127.0.0.1:5000** in your browser.

The server runs on port `5000` by default. You should see:

```
  SQL Injection Scanner — Web UI
  Open http://127.0.0.1:5000 in your browser
```

### Web UI tabs

| Tab | What it does |
|-----|-------------|
| **🌐 Web Scanner** | Enter a domain URL — crawls all pages, discovers forms and URL parameters, tests each one for SQLi. Shows a live log stream and results table. |
| **🔌 API Tester** | Test a single API endpoint. Supports GET/POST/PUT/PATCH, JSON or form-encoded body, and custom request headers (Authorization, Cookie, X-API-Key, etc.). |
| **🔍 Input Analyzer** | Paste any string for instant static analysis — no HTTP requests made. Highlights matched patterns with severity ratings. |
| **📋 Scan History** | Lists all scans from the current session. Click View to re-open any previous scan's full results. |

### API Tester — passing custom headers

The API Tester tab has a **Request Headers** section below the parameters field.

**Quick-add presets** (one click):
- `Authorization` — paste a Bearer token or Basic auth value
- `Cookie` — paste a session cookie string
- `X-API-Key` — API key header
- `Content-Type` — override the content type
- `Accept` — set accepted response format
- `X-Auth-Token` — token-based auth header

**Add any custom header** using the `+ Add Header` button.

Example for a JWT-protected API:
1. Enter the endpoint URL and body parameters
2. Click the **Authorization** preset
3. Type `Bearer eyJhbGci...` in the value field
4. Select method `POST` and format `JSON`
5. Click **▶ Start Scan**

### Saving results

Results are displayed in the browser. To also save a JSON report, use the CLI modes described below.

---

## CLI Usage

The CLI is available for scripting and automation.

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
| `--output` | — | Save JSON findings to file |

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

### WAF / Protection detection

The scanner automatically detects when an endpoint is protected and cannot be scanned:

| Condition | What happens |
|-----------|-------------|
| HTTP 422 with "suspicious behavior" | Scan stops — WAF or captcha protection detected |
| HTTP 401 / 403 | Scan stops — authentication required |
| HTTP 429 | Scan stops — rate limited |
| Individual payload blocked | Payload skipped, scan continues with next payload |

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

## Practice Targets

To test the scanner safely, run a vulnerable application locally:

```bash
# DVWA (Damn Vulnerable Web Application)
docker run --rm -p 80:80 vulnerables/web-dvwa
python -m app.main web --url http://localhost

# Or use the web UI at http://127.0.0.1:5000
```

Other options: [bWAPP](http://www.itsecgames.com/), [WebGoat](https://owasp.org/www-project-webgoat/), [HackTheBox](https://www.hackthebox.com/).

---

## Disclaimer

This tool is intended for **authorised penetration testing and security research only**.  
Unauthorised use against systems you do not own is illegal and unethical.
