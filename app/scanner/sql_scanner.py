"""
SQL Scanner: fires payloads at discovered form/query parameters and API endpoints.
"""
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

import requests

from app.models.result import ScanResult, Vulnerability, Severity
from app.scanner.payloads import ALL_PAYLOADS, ERROR_BASED, TIME_BASED, BOOLEAN_BASED
from app.scanner.detector import ResponseDetector
from app.utils.logger import get_logger

logger = get_logger("sql-scanner")

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "application/json, text/html, */*",
}
TIMEOUT = 15  # seconds per request

# HTTP status codes that mean the endpoint blocked us — not a scan result
BLOCKED_STATUSES = {401, 403, 422, 429, 503}

# Response body phrases that indicate WAF / bot-protection blocking
BLOCKED_PHRASES = [
    "suspicious behavior",
    "suspicious behaviour",
    "captcha",
    "bot detected",
    "access denied",
    "forbidden",
    "rate limit",
    "too many requests",
    "challenge",
    "cloudflare",
    "please try again later",
]


class SQLScanner:
    """
    Scans a list of (url, params, method) tuples for SQL injection.
    Each tuple represents one injectable surface (form, query string, API param).

    Supports both form-encoded and JSON body APIs.
    Detects and reports WAF / captcha blocking instead of silently failing.
    """

    def __init__(self, delay: float = 0.3, use_json: bool = False, extra_headers: Dict[str, str] = None):
        self.delay = delay
        self.use_json = use_json    # True → send POST body as JSON
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        # Merge caller-supplied headers (e.g. Authorization, X-API-Key, Cookie)
        if extra_headers:
            self.session.headers.update(extra_headers)
        self.detector = ResponseDetector()

    # ── Public entry point ────────────────────────────────────────────────────
    def scan(
        self,
        targets: List[Dict],   # [{"url": ..., "params": {...}, "method": "GET"|"POST"}]
        result: ScanResult,
    ) -> ScanResult:
        for target in targets:
            url = target.get("url", "")
            params = target.get("params", {})
            method = target.get("method", "GET").upper()
            # Honour per-target json flag if set, else fall back to scanner default
            use_json = target.get("use_json", self.use_json)
            logger.info(f"Scanning {method} {url} | params: {list(params.keys())}")
            self._scan_target(url, params, method, use_json, result)
            time.sleep(self.delay)
        return result

    # ── Per-target scanning ───────────────────────────────────────────────────
    def _scan_target(
        self,
        url: str,
        params: Dict[str, str],
        method: str,
        use_json: bool,
        result: ScanResult,
    ) -> None:
        if not params:
            params = self._extract_query_params(url)
            if not params:
                logger.debug(f"No parameters found for {url}, skipping.")
                return

        # ── Baseline request ──────────────────────────────────────────────────
        baseline_resp = self._request(url, params, method, use_json)
        if baseline_resp is None:
            result.errors.append(f"Baseline request failed (network error): {url}")
            return

        # ── Check if endpoint is blocked before we even inject ────────────────
        blocked, reason = self._is_blocked(baseline_resp)
        if blocked:
            msg = (
                f"Endpoint is protected / blocked — cannot scan. "
                f"Reason: {reason} | URL: {url}"
            )
            logger.warning(msg)
            result.errors.append(msg)
            return

        baseline_len = len(baseline_resp.text)
        logger.info(f"Baseline OK — status={baseline_resp.status_code}, len={baseline_len}")

        for param_name in params:
            self._test_parameter(
                url, params, param_name, method, use_json,
                baseline_len, baseline_resp.text, result
            )

    def _test_parameter(
        self,
        url: str,
        params: Dict[str, str],
        param_name: str,
        method: str,
        use_json: bool,
        baseline_len: int,
        baseline_text: str,
        result: ScanResult,
    ) -> None:
        # Coerce to str — param values may be None when the API sends no default
        original_value = str(params[param_name]) if params[param_name] is not None else ""

        for payload in ALL_PAYLOADS:
            injected_params = dict(params)
            injected_params[param_name] = original_value + payload

            start = time.time()
            resp = self._request(url, injected_params, method, use_json)
            elapsed = time.time() - start

            if resp is None:
                continue

            # Skip blocked responses — WAF ate the payload, not the DB
            if self._is_blocked(resp)[0]:
                logger.debug(f"Payload blocked by WAF/protection on param '{param_name}': {payload[:40]}")
                time.sleep(self.delay)
                continue

            resp_text = resp.text

            # 1. Error-based
            found, evidence = self.detector.detect_error_based(resp_text)
            if found:
                self._record(result, url, param_name, payload, evidence, method, "Error-based SQLi")
                break

            # 2. Time-based
            if payload in TIME_BASED:
                found, evidence = self.detector.detect_time_based(elapsed)
                if found:
                    self._record(result, url, param_name, payload, evidence, method, "Time-based Blind SQLi")
                    break

            # 3. UNION-based
            found, evidence = self.detector.detect_union_based(resp_text, payload)
            if found:
                self._record(result, url, param_name, payload, evidence, method, "UNION-based SQLi")
                break

            time.sleep(self.delay)

        # 4. Boolean-based blind
        self._test_boolean_blind(url, params, param_name, method, use_json, baseline_len, result)

    def _test_boolean_blind(
        self,
        url: str,
        params: Dict[str, str],
        param_name: str,
        method: str,
        use_json: bool,
        baseline_len: int,
        result: ScanResult,
    ) -> None:
        # Coerce to str — same None-safety as _test_parameter
        original = str(params[param_name]) if params[param_name] is not None else ""

        true_params = dict(params)
        true_params[param_name] = original + "' AND '1'='1"
        false_params = dict(params)
        false_params[param_name] = original + "' AND '1'='2"

        true_resp  = self._request(url, true_params,  method, use_json)
        false_resp = self._request(url, false_params, method, use_json)

        if true_resp and false_resp:
            # Don't evaluate if either response was blocked
            if self._is_blocked(true_resp)[0] or self._is_blocked(false_resp)[0]:
                return
            found, evidence = self.detector.detect_boolean_blind(
                baseline_len, len(true_resp.text), len(false_resp.text)
            )
            if found:
                self._record(
                    result, url, param_name,
                    "' AND '1'='1 / ' AND '1'='2",
                    evidence, method, "Boolean-based Blind SQLi"
                )

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _request(
        self,
        url: str,
        params: Dict,
        method: str,
        use_json: bool = False,
    ) -> Optional[requests.Response]:
        try:
            if method in ("POST", "PUT", "PATCH"):
                if use_json:
                    return self.session.request(
                        method, url, json=params, timeout=TIMEOUT, allow_redirects=True
                    )
                else:
                    return self.session.request(
                        method, url, data=params, timeout=TIMEOUT, allow_redirects=True
                    )
            else:
                return self.session.get(url, params=params, timeout=TIMEOUT, allow_redirects=True)
        except requests.exceptions.Timeout:
            logger.warning(f"Timeout on {url}")
        except requests.exceptions.RequestException as exc:
            logger.debug(f"Request error on {url}: {exc}")
        return None

    @staticmethod
    def _is_blocked(resp: requests.Response) -> Tuple[bool, str]:
        """Returns (True, reason) if the response looks like a WAF/captcha block."""
        if resp.status_code in BLOCKED_STATUSES:
            body_lower = resp.text.lower()
            for phrase in BLOCKED_PHRASES:
                if phrase in body_lower:
                    return True, f"HTTP {resp.status_code} — '{phrase}' in response body"
            # 422 with no SQLi-related content is almost always a validation/WAF block
            if resp.status_code == 422:
                return True, f"HTTP 422 Unprocessable Entity — likely input validation or WAF"
            if resp.status_code in (401, 403):
                return True, f"HTTP {resp.status_code} — authentication/authorisation required"
            if resp.status_code == 429:
                return True, f"HTTP 429 — rate limited"
        return False, ""

    @staticmethod
    def _extract_query_params(url: str) -> Dict[str, str]:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        return {k: v[0] for k, v in qs.items()}

    @staticmethod
    def _record(
        result: ScanResult,
        url: str,
        param: str,
        payload: str,
        evidence: str,
        method: str,
        vuln_type: str,
    ) -> None:
        severity = ResponseDetector.classify_severity(vuln_type, evidence)
        vuln = Vulnerability(
            url=url,
            parameter=param,
            payload=payload,
            evidence=evidence,
            severity=severity,
            vuln_type=vuln_type,
            method=method,
        )
        result.vulnerabilities.append(vuln)
        logger.warning(
            f"[{severity.value}] {vuln_type} found | param='{param}' | url={url}"
        )
