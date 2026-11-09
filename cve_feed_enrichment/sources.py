"""Fetch CVE data from public sources by CVE ID.

- CVE.org (CVE Services API): the official CVE record (CNA plus CISA/ADP additions).
- NVD API 2.0: CPE product/version ranges, CVSS, CWE, CISA KEV fields.
- OSV.dev: package names and fixed versions (Maven, PyPI, npm, Go, distributions...).
- Red Hat Security Data API: RHEL package fixes and states (relevant to Rocky/RHEL hosts).
- FIRST EPSS: probability of exploitation in the next 30 days.
- CISA KEV catalog: CVEs known to be exploited in the wild.
"""
from concurrent.futures import ThreadPoolExecutor

from .http_client import FetchError, NotFound, RateLimiter, fetch_json

ALL_SOURCES = ("cve_org", "nvd", "osv", "redhat", "epss", "kev")
DAY = 86400
# OSV alias prefixes worth following for package data (GitHub, PyPI, Go, Rust...).
OSV_ALIAS_PREFIXES = ("GHSA-", "PYSEC-", "GO-", "RUSTSEC-", "GSD-", "OSV-")
MAX_OSV_ALIASES = 6

URLS = {
    "cve_org": "https://cveawg.mitre.org/api/cve/{cve}",
    "nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}",
    "osv": "https://api.osv.dev/v1/vulns/{cve}",
    "redhat": "https://access.redhat.com/hydra/rest/securitydata/cve/{cve}.json",
    "epss": "https://api.first.org/data/v1/epss?cve={cves}",
    "kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
}


class Sources:
    def __init__(self, cache, nvd_api_key=None, enabled=ALL_SOURCES):
        self.cache = cache
        self.enabled = set(enabled)
        self.nvd_api_key = nvd_api_key
        # NVD: 5 requests / 30 s without a key, 50 / 30 s with one.
        self.limiters = {
            "nvd": RateLimiter(0.7 if nvd_api_key else 6.5),
            "cve_org": RateLimiter(0.1),
            "osv": RateLimiter(0.05),
            "redhat": RateLimiter(0.2),
            "epss": RateLimiter(1.0),
            "kev": RateLimiter(1.0),
        }
        self._kev = None

    def _cached(self, source, key, url, headers=None, max_age=None):
        hit = self.cache.get(source, key, max_age)
        if hit is not None:
            return hit["data"] if hit.get("found") else None
        try:
            data = fetch_json(url, headers=headers, limiter=self.limiters[source])
        except NotFound:
            self.cache.put(source, key, None, found=False)
            return None
        self.cache.put(source, key, data)
        return data

    def cve_org(self, cve):
        return self._cached("cve_org", cve, URLS["cve_org"].format(cve=cve))

    def nvd(self, cve):
        headers = {"apiKey": self.nvd_api_key} if self.nvd_api_key else None
        data = self._cached("nvd", cve, URLS["nvd"].format(cve=cve), headers)
        vulnerabilities = (data or {}).get("vulnerabilities") or []
        return vulnerabilities[0].get("cve") if vulnerabilities else None

    def osv(self, cve):
        """The OSV record for the CVE plus its package advisories (GHSA, PYSEC...)."""
        record = self._cached("osv", cve, URLS["osv"].format(cve=cve))
        if not record:
            return []
        records = [record]
        aliases = [alias for alias in record.get("aliases") or []
                   if alias.startswith(OSV_ALIAS_PREFIXES)][:MAX_OSV_ALIASES]
        for alias in aliases:
            try:
                alias_record = self._cached("osv", alias, URLS["osv"].format(cve=alias))
            except FetchError:
                continue
            if alias_record:
                records.append(alias_record)
        return records

    def redhat(self, cve):
        return self._cached("redhat", cve, URLS["redhat"].format(cve=cve))

    def epss(self, cves):
        """EPSS for many CVEs: cached per CVE for a day, fetched 50 at a time."""
        result, missing = {}, []
        for cve in cves:
            hit = self.cache.get("epss", cve, DAY)
            if hit is not None:
                result[cve] = hit["data"] if hit.get("found") else None
            else:
                missing.append(cve)
        for start in range(0, len(missing), 50):
            batch = missing[start:start + 50]
            data = fetch_json(URLS["epss"].format(cves=",".join(batch)), limiter=self.limiters["epss"])
            rows = {row.get("cve"): row for row in data.get("data") or []}
            for cve in batch:
                row = rows.get(cve)
                self.cache.put("epss", cve, row, found=row is not None)
                result[cve] = row
        return result

    def kev(self):
        """CISA Known Exploited Vulnerabilities catalog as {cve: entry}, cached for a day."""
        if self._kev is None:
            catalog = self._cached("kev", "catalog", URLS["kev"], max_age=DAY) or {}
            self._kev = {item.get("cveID"): item for item in catalog.get("vulnerabilities") or []}
        return self._kev

    def per_cve(self, cve):
        """Fetch every enabled per-CVE source in parallel. Returns (data, errors)."""
        calls = {name: getattr(self, name) for name in ("cve_org", "nvd", "osv", "redhat")
                 if name in self.enabled}
        data, errors = {}, {}
        with ThreadPoolExecutor(max_workers=len(calls) or 1) as pool:
            futures = {name: pool.submit(call, cve) for name, call in calls.items()}
            for name, future in futures.items():
                try:
                    data[name] = future.result()
                except FetchError as error:
                    data[name], errors[name] = None, str(error)
        return data, errors
