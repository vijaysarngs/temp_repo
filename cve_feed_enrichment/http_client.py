"""Small JSON-over-HTTP client with retries, per-source rate limits and a disk cache.

Standard library only, so this tool needs nothing beyond Python itself.
"""
import json
import re
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

USER_AGENT = "cve-feed-enrichment/1.0 (+CVE lookup; standard library urllib)"


class NotFound(Exception):
    """The source has no record for this key (HTTP 404)."""


class FetchError(Exception):
    """The source could not be reached or kept failing after retries."""


class RateLimiter:
    """Allow at most one request per `interval` seconds, shared across threads."""

    def __init__(self, interval):
        self.interval = interval
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self):
        with self._lock:
            delay = self._next - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            self._next = max(time.monotonic(), self._next) + self.interval


def fetch_json(url, headers=None, limiter=None, retries=4, timeout=30):
    """GET a URL and parse JSON. Retries on 429/5xx and network errors; 404 raises NotFound."""
    request_headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    request_headers.update(headers or {})
    last_error = None
    for attempt in range(retries + 1):
        if limiter:
            limiter.wait()
        try:
            request = urllib.request.Request(url, headers=request_headers)
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            if error.code == 404:
                raise NotFound(url) from None
            last_error = f"HTTP {error.code}"
            # NVD answers 403 when the rate limit is exceeded; treat it like 429.
            if error.code not in (403, 429, 500, 502, 503, 504):
                break
            retry_after = error.headers.get("Retry-After") if error.headers else None
            pause = float(retry_after) if retry_after and retry_after.isdigit() else 2 ** attempt * 3
        except (urllib.error.URLError, TimeoutError, ConnectionError, json.JSONDecodeError) as error:
            last_error = f"{type(error).__name__}: {getattr(error, 'reason', error)}"
            pause = 2 ** attempt * 2
        if attempt < retries:
            time.sleep(min(pause, 60))
    raise FetchError(f"{last_error} for {url}")


class Cache:
    """One JSON file per source and key; a missing record is cached too."""

    def __init__(self, root, max_age_days=7, refresh=False):
        self.root = Path(root)
        self.max_age = max_age_days * 86400
        self.refresh = refresh

    def _path(self, source, key):
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", key)
        return self.root / source / f"{safe}.json"

    def get(self, source, key, max_age=None):
        """Return {"found": bool, "data": ...} or None when absent, stale or refreshing."""
        if self.refresh:
            return None
        path = self._path(source, key)
        try:
            if time.time() - path.stat().st_mtime > (self.max_age if max_age is None else max_age):
                return None
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def put(self, source, key, data, found=True):
        path = self._path(source, key)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps({"found": found, "data": data}), encoding="utf-8")
        temporary.replace(path)
