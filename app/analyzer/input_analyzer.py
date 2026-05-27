"""
Input Analyzer: detects SQL injection patterns in raw user-supplied strings.
No HTTP requests are made — this is purely static / pattern-based analysis.
"""
import re
from dataclasses import dataclass, field
from typing import List

from app.utils.logger import get_logger

logger = get_logger("input-analyzer")


# ── Pattern definitions ───────────────────────────────────────────────────────

@dataclass
class PatternRule:
    name: str
    pattern: str
    severity: str       # LOW | MEDIUM | HIGH | CRITICAL
    description: str


RULES: List[PatternRule] = [
    PatternRule(
        name="Classic OR bypass",
        pattern=r"(\bor\b|\bOR\b)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?",
        severity="HIGH",
        description="Classic OR 1=1 authentication bypass pattern",
    ),
    PatternRule(
        name="Comment terminator",
        pattern=r"(--|#|/\*)",
        severity="MEDIUM",
        description="SQL comment sequence that can truncate queries",
    ),
    PatternRule(
        name="Quote injection",
        pattern=r"['\"`]",
        severity="LOW",
        description="Unescaped quote character — potential string terminator",
    ),
    PatternRule(
        name="UNION SELECT",
        pattern=r"\bUNION\b.{0,20}\bSELECT\b",
        severity="CRITICAL",
        description="UNION SELECT — data extraction attempt",
    ),
    PatternRule(
        name="Stacked query",
        pattern=r";\s*(DROP|INSERT|UPDATE|DELETE|CREATE|ALTER|EXEC|EXECUTE)\b",
        severity="CRITICAL",
        description="Stacked query with destructive/execution statement",
    ),
    PatternRule(
        name="Sleep / delay function",
        pattern=r"\b(SLEEP|WAITFOR\s+DELAY|pg_sleep|BENCHMARK)\s*\(",
        severity="HIGH",
        description="Time-delay function — time-based blind SQLi attempt",
    ),
    PatternRule(
        name="Information schema probe",
        pattern=r"\binformation_schema\b",
        severity="HIGH",
        description="Attempt to query information_schema for table/column enumeration",
    ),
    PatternRule(
        name="System table probe",
        pattern=r"\b(sysobjects|syscolumns|sys\.tables|sys\.columns|pg_tables|sqlite_master)\b",
        severity="HIGH",
        description="Access to system/catalog tables",
    ),
    PatternRule(
        name="Hex / char encoding",
        pattern=r"(0x[0-9a-fA-F]{4,}|CHAR\s*\(\s*\d+)",
        severity="MEDIUM",
        description="Hex or CHAR() encoding — possible obfuscation",
    ),
    PatternRule(
        name="Boolean tautology",
        pattern=r"['\"]?\s*(AND|OR)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?",
        severity="MEDIUM",
        description="Boolean tautology / contradiction pattern",
    ),
    PatternRule(
        name="Batch / exec",
        pattern=r"\b(EXEC|EXECUTE|xp_cmdshell|sp_executesql)\b",
        severity="CRITICAL",
        description="Stored procedure or OS command execution attempt",
    ),
    PatternRule(
        name="LOAD FILE / INTO OUTFILE",
        pattern=r"\b(LOAD_FILE|INTO\s+OUTFILE|INTO\s+DUMPFILE)\b",
        severity="CRITICAL",
        description="File read/write via SQL — severe privilege escalation",
    ),
]


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class InputFinding:
    rule_name: str
    severity: str
    description: str
    matched_text: str
    position: int


@dataclass
class InputAnalysisResult:
    input_text: str
    findings: List[InputFinding] = field(default_factory=list)

    @property
    def is_suspicious(self) -> bool:
        return len(self.findings) > 0

    @property
    def max_severity(self) -> str:
        order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        if not self.findings:
            return "NONE"
        return max(self.findings, key=lambda f: order.index(f.severity)).severity

    def summary(self) -> str:
        if not self.is_suspicious:
            return "✅  Input appears clean — no SQL injection patterns detected."
        lines = [
            f"⚠️  {len(self.findings)} pattern(s) detected | Max severity: {self.max_severity}",
            "",
        ]
        for f in self.findings:
            lines.append(f"  [{f.severity}] {f.rule_name}")
            lines.append(f"    → {f.description}")
            lines.append(f"    → Matched: '{f.matched_text}' at position {f.position}")
            lines.append("")
        return "\n".join(lines)


# ── Analyzer class ────────────────────────────────────────────────────────────

class InputAnalyzer:
    """Statically analyses a string for SQL injection indicators."""

    def analyze(self, user_input: str) -> InputAnalysisResult:
        result = InputAnalysisResult(input_text=user_input)

        for rule in RULES:
            for match in re.finditer(rule.pattern, user_input, re.IGNORECASE):
                finding = InputFinding(
                    rule_name=rule.name,
                    severity=rule.severity,
                    description=rule.description,
                    matched_text=match.group(0),
                    position=match.start(),
                )
                result.findings.append(finding)
                logger.debug(f"Pattern '{rule.name}' matched at pos {match.start()}")

        if result.is_suspicious:
            logger.warning(
                f"Input analysis: {len(result.findings)} finding(s), "
                f"max severity={result.max_severity}"
            )
        else:
            logger.info("Input analysis: no suspicious patterns found.")

        return result
