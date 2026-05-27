"""
Crawler: BFS web crawler that discovers pages and injectable surfaces.
"""
from collections import deque
from typing import Dict, List, Set
from urllib.parse import urlparse

import requests

from app.crawler.extractor import Extractor
from app.utils.logger import get_logger

logger = get_logger("crawler")

HEADERS = {
    "User-Agent": "SQLi-Scanner/1.0 (security research)",
    "Accept": "text/html,application/xhtml+xml,*/*",
}
TIMEOUT = 10


class Crawler:
    """
    Crawls a web application starting from a seed URL.
    Collects all forms and URL parameters as injectable targets.
    """

    def __init__(self, max_pages: int = 50, delay: float = 0.3):
        self.max_pages = max_pages
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        self.extractor = Extractor()

    def crawl(self, seed_url: str) -> List[Dict]:
        """
        BFS crawl from seed_url.
        Returns a list of injectable targets:
          [{"url": ..., "method": ..., "params": {...}}, ...]
        """
        base_domain = urlparse(seed_url).netloc
        visited: Set[str] = set()
        queue: deque = deque([seed_url])
        targets: List[Dict] = []

        logger.info(f"Starting crawl: {seed_url} (max_pages={self.max_pages})")

        while queue and len(visited) < self.max_pages:
            url = queue.popleft()
            # Normalise: strip fragment
            url = url.split("#")[0]
            if url in visited:
                continue
            visited.add(url)

            logger.info(f"Crawling [{len(visited)}/{self.max_pages}]: {url}")
            html = self._fetch(url)
            if html is None:
                continue

            # ── Collect forms ─────────────────────────────────────────────
            forms = self.extractor.extract_forms(html, url)
            targets.extend(forms)

            # ── Collect URL params on this page ───────────────────────────
            url_params = self.extractor.extract_url_params(url)
            if url_params:
                targets.append({"url": url, "method": "GET", "params": url_params})

            # ── Discover new links ────────────────────────────────────────
            links = self.extractor.extract_links(html, url)
            for link in links:
                if urlparse(link).netloc == base_domain and link not in visited:
                    queue.append(link)

        logger.info(
            f"Crawl complete. Pages visited: {len(visited)} | "
            f"Injectable targets found: {len(targets)}"
        )
        return targets

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _fetch(self, url: str) -> str | None:
        import time
        try:
            resp = self.session.get(url, timeout=TIMEOUT, allow_redirects=True)
            resp.raise_for_status()
            time.sleep(self.delay)
            return resp.text
        except requests.exceptions.HTTPError as e:
            logger.warning(f"HTTP {e.response.status_code} on {url}")
        except requests.exceptions.RequestException as e:
            logger.debug(f"Fetch error on {url}: {e}")
        return None
