"""
Extractor: pulls forms, links, and injectable parameters from HTML pages.
"""
from typing import Dict, List, Tuple
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from app.utils.logger import get_logger

logger = get_logger("extractor")


class Extractor:
    """Parses HTML and extracts all forms and links with their parameters."""

    # ── Forms ─────────────────────────────────────────────────────────────────
    @staticmethod
    def extract_forms(html: str, base_url: str) -> List[Dict]:
        """
        Returns a list of dicts:
          {
            "url":    absolute action URL,
            "method": "GET" | "POST",
            "params": { field_name: default_value, ... }
          }
        """
        soup = BeautifulSoup(html, "lxml")
        forms = []

        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "get").upper()
            action_url = urljoin(base_url, action) if action else base_url

            params: Dict[str, str] = {}
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if not name:
                    continue
                value = inp.get("value", "test")
                # For select, grab first option value
                if inp.name == "select":
                    first_opt = inp.find("option")
                    value = first_opt.get("value", "1") if first_opt else "1"
                params[name] = value or "test"

            if params:
                forms.append({"url": action_url, "method": method, "params": params})
                logger.debug(f"Form found: {method} {action_url} | fields: {list(params.keys())}")

        return forms

    # ── Links ─────────────────────────────────────────────────────────────────
    @staticmethod
    def extract_links(html: str, base_url: str) -> List[str]:
        """Returns all absolute in-scope href links found on the page."""
        soup = BeautifulSoup(html, "lxml")
        base_domain = urlparse(base_url).netloc
        links: List[str] = []

        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()
            if href.startswith(("#", "mailto:", "javascript:", "tel:")):
                continue
            absolute = urljoin(base_url, href)
            if urlparse(absolute).netloc == base_domain:
                links.append(absolute)

        return list(set(links))

    # ── Query-string parameters ───────────────────────────────────────────────
    @staticmethod
    def extract_url_params(url: str) -> Dict[str, str]:
        """Parses query-string parameters from a URL."""
        from urllib.parse import parse_qs
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        return {k: v[0] for k, v in qs.items()}

    # ── API-style JSON body ───────────────────────────────────────────────────
    @staticmethod
    def flatten_json(obj, prefix: str = "") -> Dict[str, str]:
        """
        Flattens a nested JSON object into dot-notation keys.
        e.g. {"user": {"id": 1}} -> {"user.id": "1"}
        """
        items: Dict[str, str] = {}
        if isinstance(obj, dict):
            for k, v in obj.items():
                full_key = f"{prefix}.{k}" if prefix else k
                items.update(Extractor.flatten_json(v, full_key))
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                full_key = f"{prefix}[{i}]"
                items.update(Extractor.flatten_json(v, full_key))
        else:
            items[prefix] = str(obj)
        return items
