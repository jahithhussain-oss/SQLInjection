"""
SQL Injection Security Scanner
================================
Three modes:
  1. web   — crawl a domain and test all discovered forms/params
  2. api   — test a single API endpoint with provided parameters
  3. input — statically analyse a user-supplied string for SQLi patterns

Usage examples:
  python -m app.main web   --url https://example.com
  python -m app.main api   --url https://api.example.com/users --params "id=1&name=admin" --method GET
  python -m app.main input --text "admin' OR '1'='1"
"""

import argparse
import json
import sys
from urllib.parse import parse_qs

import colorama
from colorama import Fore, Style

from app.crawler.crawler import Crawler
from app.scanner.sql_scanner import SQLScanner
from app.analyzer.input_analyzer import InputAnalyzer
from app.models.result import ScanResult
from app.utils.logger import get_logger

colorama.init(autoreset=True)
logger = get_logger("main")


# ── Pretty-print helpers ──────────────────────────────────────────────────────

SEVERITY_COLOR = {
    "LOW":      Fore.CYAN,
    "MEDIUM":   Fore.YELLOW,
    "HIGH":     Fore.RED,
    "CRITICAL": Fore.RED + Style.BRIGHT,
}


def print_banner() -> None:
    banner = f"""
{Fore.CYAN}{Style.BRIGHT}
 ███████╗ ██████╗ ██╗      ██╗    ███████╗ ██████╗ █████╗ ███╗  ██╗███╗  ██╗███████╗██████╗
 ██╔════╝██╔═══██╗██║      ██║    ██╔════╝██╔════╝██╔══██╗████╗ ██║████╗ ██║██╔════╝██╔══██╗
 ███████╗██║   ██║██║      ██║    ███████╗██║     ███████║██╔██╗██║██╔██╗██║█████╗  ██████╔╝
 ╚════██║██║▄▄ ██║██║      ██║    ╚════██║██║     ██╔══██║██║╚████║██║╚████║██╔══╝  ██╔══██╗
 ███████║╚██████╔╝███████╗ ██║    ███████║╚██████╗██║  ██║██║ ╚███║██║ ╚███║███████╗██║  ██║
 ╚══════╝ ╚══▀▀═╝ ╚══════╝ ╚═╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚══╝╚═╝  ╚══╝╚══════╝╚═╝  ╚═╝
{Style.RESET_ALL}
  {Fore.WHITE}SQL Injection Security Scanner  |  For authorised testing only{Style.RESET_ALL}
"""
    print(banner)


def print_scan_results(result: ScanResult) -> None:
    summary = result.summary
    print(f"\n{'='*60}")
    print(f"{Fore.CYAN}{Style.BRIGHT}SCAN SUMMARY{Style.RESET_ALL}")
    print(f"{'='*60}")
    print(f"  Target      : {summary['target']}")
    print(f"  Scan type   : {summary['scan_type']}")
    print(f"  URLs scanned: {summary['scanned_urls']}")
    print(f"  Errors      : {summary['errors']}")
    print(f"  Vulnerabilities found: {summary['total_vulnerabilities']}")

    for sev, count in summary["severity_breakdown"].items():
        if count:
            color = SEVERITY_COLOR.get(sev, "")
            print(f"    {color}[{sev}]{Style.RESET_ALL} {count}")

    if result.vulnerabilities:
        print(f"\n{Fore.RED}{Style.BRIGHT}VULNERABILITIES{Style.RESET_ALL}")
        print("-" * 60)
        for i, v in enumerate(result.vulnerabilities, 1):
            color = SEVERITY_COLOR.get(v.severity.value, "")
            print(f"\n  #{i} {color}[{v.severity.value}]{Style.RESET_ALL} {v.vuln_type}")
            print(f"     URL      : {v.url}")
            print(f"     Method   : {v.method}")
            print(f"     Parameter: {v.parameter}")
            print(f"     Payload  : {v.payload}")
            print(f"     Evidence : {v.evidence}")
    else:
        print(f"\n{Fore.GREEN}No SQL injection vulnerabilities detected.{Style.RESET_ALL}")

    print(f"\n{'='*60}\n")


# ── Mode handlers ─────────────────────────────────────────────────────────────

def run_web_scan(args: argparse.Namespace) -> None:
    """Crawl a domain and test all discovered surfaces."""
    url = args.url
    logger.info(f"[WEB SCAN] Target: {url}")

    crawler = Crawler(max_pages=args.max_pages, delay=args.delay)
    targets = crawler.crawl(url)

    result = ScanResult(target=url, scan_type="web")
    result.scanned_urls = [t["url"] for t in targets]

    if not targets:
        logger.warning("No injectable targets found during crawl.")
    else:
        scanner = SQLScanner(delay=args.delay)
        scanner.scan(targets, result)

    print_scan_results(result)

    if args.output:
        _save_json(result, args.output)


def run_api_scan(args: argparse.Namespace) -> None:
    """Test a single API endpoint."""
    url = args.url
    method = args.method.upper()
    logger.info(f"[API SCAN] {method} {url}")

    # Parse params: "id=1&name=admin" or JSON string
    params: dict = {}
    if args.params:
        try:
            params = json.loads(args.params)
        except json.JSONDecodeError:
            qs = parse_qs(args.params)
            params = {k: v[0] for k, v in qs.items()}

    if not params:
        logger.error("No parameters provided. Use --params 'key=value&key2=value2'")
        sys.exit(1)

    targets = [{"url": url, "method": method, "params": params}]
    result = ScanResult(target=url, scan_type="api")
    result.scanned_urls = [url]

    scanner = SQLScanner(delay=args.delay)
    scanner.scan(targets, result)

    print_scan_results(result)

    if args.output:
        _save_json(result, args.output)


def run_input_analysis(args: argparse.Namespace) -> None:
    """Statically analyse a user-supplied string."""
    text = args.text
    logger.info(f"[INPUT ANALYSIS] Analysing: {text!r}")

    analyzer = InputAnalyzer()
    analysis = analyzer.analyze(text)

    print(f"\n{'='*60}")
    print(f"{Fore.CYAN}{Style.BRIGHT}INPUT ANALYSIS RESULT{Style.RESET_ALL}")
    print(f"{'='*60}")
    print(f"  Input: {text!r}")
    print()
    print(analysis.summary())
    print(f"{'='*60}\n")

    if args.output:
        data = {
            "input": text,
            "is_suspicious": analysis.is_suspicious,
            "max_severity": analysis.max_severity,
            "findings": [
                {
                    "rule": f.rule_name,
                    "severity": f.severity,
                    "description": f.description,
                    "matched": f.matched_text,
                    "position": f.position,
                }
                for f in analysis.findings
            ],
        }
        _save_json_raw(data, args.output)


# ── JSON export ───────────────────────────────────────────────────────────────

def _save_json(result: ScanResult, path: str) -> None:
    data = {
        "summary": result.summary,
        "vulnerabilities": [v.to_dict() for v in result.vulnerabilities],
        "errors": result.errors,
    }
    _save_json_raw(data, path)


def _save_json_raw(data: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    logger.info(f"Results saved to {path}")


# ── CLI ───────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sql-scanner",
        description="SQL Injection Security Scanner",
    )
    parser.add_argument(
        "--output", "-o",
        metavar="FILE",
        help="Save results to a JSON file",
    )

    sub = parser.add_subparsers(dest="mode", required=True)

    # ── web ──────────────────────────────────────────────────────────────────
    web_p = sub.add_parser("web", help="Crawl a web application and test for SQLi")
    web_p.add_argument("--url", required=True, help="Seed URL (e.g. https://example.com)")
    web_p.add_argument("--max-pages", type=int, default=50, help="Max pages to crawl (default: 50)")
    web_p.add_argument("--delay", type=float, default=0.3, help="Delay between requests in seconds")

    # ── api ──────────────────────────────────────────────────────────────────
    api_p = sub.add_parser("api", help="Test a single API endpoint for SQLi")
    api_p.add_argument("--url", required=True, help="API endpoint URL")
    api_p.add_argument(
        "--params", required=True,
        help="Parameters as query string (id=1&name=foo) or JSON ({\"id\":\"1\"})"
    )
    api_p.add_argument("--method", default="GET", choices=["GET", "POST", "PUT", "PATCH"],
                       help="HTTP method (default: GET)")
    api_p.add_argument("--delay", type=float, default=0.3, help="Delay between requests in seconds")

    # ── input ─────────────────────────────────────────────────────────────────
    inp_p = sub.add_parser("input", help="Analyse a string for SQL injection patterns")
    inp_p.add_argument("--text", required=True, help="User input string to analyse")

    return parser


def main() -> None:
    print_banner()
    parser = build_parser()
    args = parser.parse_args()

    if args.mode == "web":
        run_web_scan(args)
    elif args.mode == "api":
        run_api_scan(args)
    elif args.mode == "input":
        run_input_analysis(args)


if __name__ == "__main__":
    main()
