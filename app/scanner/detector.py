"""
Detector: analyses HTTP responses to decide whether a payload triggered SQLi.
"""
import re
import time
from typing import Optional, Tuple

from app.scanner.payloads import (
    SQL_ERROR_SIGNATURES,
    BLIND_DIFFERENCE_THRESHOLD,
    TIME_DELAY_THRESHOLD,
)
from app.models.result import Severity


class ResponseDetector:
    """Analyses a pair of HTTP responses (baseline vs injected) for SQLi evidence."""

    # ── Error-based detection ─────────────────────────────────────────────────
    @staticmethod
    def detect_error_based(response_text: str) -> Tuple[bool, str]:
        """
        Returns (is_vulnerable, evidence_snippet).
        Searches for known DB error strings in the response body.
        """
        lower = response_text.lower()
        for sig in SQL_ERROR_SIGNATURES:
            if re.search(sig, lower):
                # Extract a short snippet around the match for the report
                match = re.search(sig, lower)
                start = max(0, match.start() - 40)
                end = min(len(response_text), match.end() + 40)
                snippet = response_text[start:end].strip()
                return True, f"DB error signature '{sig}' found: ...{snippet}..."
        return False, ""

    # ── Boolean-based blind detection ─────────────────────────────────────────
    @staticmethod
    def detect_boolean_blind(
        baseline_len: int,
        true_len: int,
        false_len: int,
    ) -> Tuple[bool, str]:
        """
        Compares response lengths for TRUE vs FALSE conditions.
        A significant difference between true/false (but not baseline) suggests blind SQLi.
        """
        if baseline_len == 0:
            return False, ""

        true_diff = abs(true_len - baseline_len) / baseline_len
        false_diff = abs(false_len - baseline_len) / baseline_len
        tf_diff = abs(true_len - false_len)

        if (
            true_diff > BLIND_DIFFERENCE_THRESHOLD
            and false_diff > BLIND_DIFFERENCE_THRESHOLD
            and tf_diff > 50  # at least 50 chars difference
        ):
            return True, (
                f"Boolean blind: baseline={baseline_len}, "
                f"true_cond={true_len}, false_cond={false_len}"
            )
        return False, ""

    # ── Time-based blind detection ────────────────────────────────────────────
    @staticmethod
    def detect_time_based(elapsed: float) -> Tuple[bool, str]:
        """
        If the response took longer than the threshold, flag as time-based blind SQLi.
        """
        if elapsed >= TIME_DELAY_THRESHOLD:
            return True, f"Time-based blind: response took {elapsed:.2f}s (threshold {TIME_DELAY_THRESHOLD}s)"
        return False, ""

    # ── UNION-based detection ─────────────────────────────────────────────────
    @staticmethod
    def detect_union_based(response_text: str, payload: str) -> Tuple[bool, str]:
        """
        Looks for numeric markers or DB function output that UNION payloads inject.
        """
        if "UNION" not in payload.upper():
            return False, ""

        # Common markers we inject
        markers = ["@@version", "user()", "database()", "1,2,3", "NULL"]
        lower = response_text.lower()

        # Check if version strings appear (e.g. "5.7.38-mysql")
        version_pattern = r"\d+\.\d+\.\d+"
        if re.search(version_pattern, response_text) and "UNION" in payload.upper():
            return True, "UNION-based: version string pattern detected in response"

        return False, ""

    # ── Severity classifier ───────────────────────────────────────────────────
    @staticmethod
    def classify_severity(vuln_type: str, evidence: str) -> Severity:
        if "time-based" in evidence.lower():
            return Severity.HIGH
        if "boolean blind" in evidence.lower():
            return Severity.HIGH
        if "union" in evidence.lower():
            return Severity.CRITICAL
        if any(kw in evidence.lower() for kw in ["drop", "insert", "delete", "update"]):
            return Severity.CRITICAL
        return Severity.MEDIUM
