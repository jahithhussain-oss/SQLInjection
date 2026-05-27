"""
Flask routes — thin layer that calls the existing scanner/analyzer modules.
"""
import json
import threading
from urllib.parse import parse_qs

from flask import Blueprint, render_template, request, jsonify, Response
import queue

from app.crawler.crawler import Crawler
from app.scanner.sql_scanner import SQLScanner
from app.analyzer.input_analyzer import InputAnalyzer
from app.models.result import ScanResult

bp = Blueprint("main", __name__)

# ── In-memory scan store (keyed by scan_id) ───────────────────────────────────
_scans: dict = {}          # scan_id -> {"status": ..., "result": ..., "logs": [...]}
_scan_lock = threading.Lock()


# ── Pages ─────────────────────────────────────────────────────────────────────

@bp.route("/")
def index():
    return render_template("index.html")


# ── API: Input Analyzer (synchronous — fast) ──────────────────────────────────

@bp.route("/api/analyze-input", methods=["POST"])
def analyze_input():
    data = request.get_json(force=True)
    text = (data.get("text") or "").strip()
    if not text:
        return jsonify({"error": "No input text provided"}), 400

    analyzer = InputAnalyzer()
    result = analyzer.analyze(text)

    findings = [
        {
            "rule": f.rule_name,
            "severity": f.severity,
            "description": f.description,
            "matched": f.matched_text,
            "position": f.position,
        }
        for f in result.findings
    ]

    return jsonify({
        "input": text,
        "is_suspicious": result.is_suspicious,
        "max_severity": result.max_severity,
        "findings": findings,
    })


# ── API: Start a web / API scan (async — runs in background thread) ───────────

@bp.route("/api/scan/start", methods=["POST"])
def start_scan():
    data = request.get_json(force=True)
    scan_type = data.get("scan_type")          # "web" | "api"

    if scan_type not in ("web", "api"):
        return jsonify({"error": "scan_type must be 'web' or 'api'"}), 400

    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "URL is required"}), 400
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    # Build a unique scan id
    import uuid, time
    scan_id = str(uuid.uuid4())[:8]

    with _scan_lock:
        _scans[scan_id] = {
            "status": "running",
            "scan_type": scan_type,
            "url": url,
            "result": None,
            "logs": [],
            "started_at": time.strftime("%H:%M:%S"),
        }

    # Launch background thread
    if scan_type == "web":
        max_pages = int(data.get("max_pages", 30))
        delay = float(data.get("delay", 0.3))
        t = threading.Thread(
            target=_run_web_scan,
            args=(scan_id, url, max_pages, delay),
            daemon=True,
        )
    else:
        params_raw = (data.get("params") or "").strip()
        method = (data.get("method") or "GET").upper()
        delay = float(data.get("delay", 0.3))
        use_json = bool(data.get("use_json", True))
        headers_raw = data.get("headers") or {}   # dict of extra request headers
        t = threading.Thread(
            target=_run_api_scan,
            args=(scan_id, url, params_raw, method, delay, use_json, headers_raw),
            daemon=True,
        )

    t.start()
    return jsonify({"scan_id": scan_id})


@bp.route("/api/scan/status/<scan_id>")
def scan_status(scan_id: str):
    with _scan_lock:
        scan = _scans.get(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    payload = {
        "scan_id": scan_id,
        "status": scan["status"],
        "scan_type": scan["scan_type"],
        "url": scan["url"],
        "started_at": scan["started_at"],
        "logs": scan["logs"][-100:],   # last 100 log lines
        "custom_headers": scan.get("custom_headers", []),
    }

    if scan["result"]:
        r: ScanResult = scan["result"]
        payload["summary"] = r.summary
        payload["vulnerabilities"] = [v.to_dict() for v in r.vulnerabilities]
        payload["errors"] = r.errors

    return jsonify(payload)


@bp.route("/api/scans")
def list_scans():
    with _scan_lock:
        items = [
            {
                "scan_id": sid,
                "status": s["status"],
                "scan_type": s["scan_type"],
                "url": s["url"],
                "started_at": s["started_at"],
                "vuln_count": len(s["result"].vulnerabilities) if s["result"] else 0,
            }
            for sid, s in _scans.items()
        ]
    return jsonify(items[::-1])   # newest first


# ── Background scan workers ───────────────────────────────────────────────────

def _log(scan_id: str, msg: str):
    with _scan_lock:
        if scan_id in _scans:
            _scans[scan_id]["logs"].append(msg)


def _run_web_scan(scan_id: str, url: str, max_pages: int, delay: float):
    try:
        _log(scan_id, f"[INFO] Starting web crawl: {url}")
        crawler = Crawler(max_pages=max_pages, delay=delay)

        # Monkey-patch crawler logger to capture logs
        import app.crawler.crawler as cm
        orig = cm.logger.info
        def patched_info(msg, *a, **kw):
            _log(scan_id, f"[INFO] {msg}")
            orig(msg, *a, **kw)
        cm.logger.info = patched_info

        targets = crawler.crawl(url)
        cm.logger.info = orig   # restore

        _log(scan_id, f"[INFO] Crawl done. {len(targets)} injectable target(s) found.")

        result = ScanResult(target=url, scan_type="web")
        result.scanned_urls = list({t["url"] for t in targets})

        if targets:
            scanner = SQLScanner(delay=delay)
            _patch_scanner_logger(scan_id, scanner)
            scanner.scan(targets, result)

        with _scan_lock:
            _scans[scan_id]["result"] = result
            _scans[scan_id]["status"] = "done"
        _log(scan_id, f"[DONE] {len(result.vulnerabilities)} vulnerability/ies found.")

    except Exception as exc:
        _log(scan_id, f"[ERROR] {exc}")
        with _scan_lock:
            _scans[scan_id]["status"] = "error"


def _run_api_scan(scan_id: str, url: str, params_raw: str, method: str, delay: float, use_json: bool = True, headers_raw: dict = None):
    try:
        # Parse params
        params: dict = {}
        if params_raw:
            try:
                params = json.loads(params_raw)
            except json.JSONDecodeError:
                qs = parse_qs(params_raw)
                params = {k: v[0] for k, v in qs.items()}

        if not params:
            _log(scan_id, "[ERROR] No parameters parsed. Use key=value or JSON.")
            with _scan_lock:
                _scans[scan_id]["status"] = "error"
            return

        # Coerce all values to str — JSON may send null/numbers
        params = {k: str(v) if v is not None else "" for k, v in params.items()}

        # Sanitise extra headers — keys and values must be strings
        extra_headers = {str(k): str(v) for k, v in (headers_raw or {}).items() if k and v is not None}

        if extra_headers:
            _log(scan_id, f"[INFO] Custom headers: {list(extra_headers.keys())}")
            with _scan_lock:
                _scans[scan_id]["custom_headers"] = list(extra_headers.keys())

        _log(scan_id, f"[INFO] Starting API scan: {method} {url} | params: {list(params.keys())}")

        targets = [{"url": url, "method": method, "params": params, "use_json": use_json}]
        result = ScanResult(target=url, scan_type="api")
        result.scanned_urls = [url]

        scanner = SQLScanner(delay=delay, use_json=use_json, extra_headers=extra_headers)
        _patch_scanner_logger(scan_id, scanner)
        scanner.scan(targets, result)

        with _scan_lock:
            _scans[scan_id]["result"] = result
            _scans[scan_id]["status"] = "done"
        _log(scan_id, f"[DONE] {len(result.vulnerabilities)} vulnerability/ies found.")

    except Exception as exc:
        _log(scan_id, f"[ERROR] {exc}")
        with _scan_lock:
            _scans[scan_id]["status"] = "error"


def _patch_scanner_logger(scan_id: str, scanner: SQLScanner):
    """Redirect scanner log output to the in-memory log store."""
    import app.scanner.sql_scanner as sm
    orig_warn = sm.logger.warning
    orig_info = sm.logger.info

    def w(msg, *a, **kw):
        _log(scan_id, f"[WARN] {msg}")
        orig_warn(msg, *a, **kw)

    def i(msg, *a, **kw):
        _log(scan_id, f"[INFO] {msg}")
        orig_info(msg, *a, **kw)

    sm.logger.warning = w
    sm.logger.info = i
