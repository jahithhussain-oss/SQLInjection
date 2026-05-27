from dataclasses import dataclass, field
from typing import List, Optional
from enum import Enum


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Vulnerability:
    url: str
    parameter: str
    payload: str
    evidence: str
    severity: Severity
    vuln_type: str = "SQL Injection"
    method: str = "GET"

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "evidence": self.evidence,
            "severity": self.severity.value,
            "type": self.vuln_type,
            "method": self.method,
        }


@dataclass
class ScanResult:
    target: str
    scan_type: str                          # "web", "api", "input"
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    scanned_urls: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def is_vulnerable(self) -> bool:
        return len(self.vulnerabilities) > 0

    @property
    def summary(self) -> dict:
        counts = {s.value: 0 for s in Severity}
        for v in self.vulnerabilities:
            counts[v.severity.value] += 1
        return {
            "target": self.target,
            "scan_type": self.scan_type,
            "total_vulnerabilities": len(self.vulnerabilities),
            "severity_breakdown": counts,
            "scanned_urls": len(self.scanned_urls),
            "errors": len(self.errors),
        }
