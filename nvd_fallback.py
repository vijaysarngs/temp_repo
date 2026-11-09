"""NVD fallback for enrichment rows the scanner text could not fully classify.

When a CVE has no usable description, or classification leaves its product or component
empty, the CVE is looked up in the NVD API 2.0. NVD gives:
- the description (used as source text for classification, quoted as evidence);
- vulnerable CPE products and version ranges ("< 9.0.99" gives fixed version 9.0.99);
- CVSS, CWE and CISA KEV fields.

Product and component are only taken from what NVD states:
- Oracle's fixed description wording ("Vulnerability in the SQL*Plus component of Oracle
  Database Server", "... product of Oracle MySQL (component: Server: Replication)",
  "vulnerability in Oracle Java SE ... via vectors related to Serialization");
- otherwise the most-listed vulnerable CPE product (cpe:2.3:a:apache:tomcat -> Apache Tomcat).
The application name is the organisation's own label and never comes from NVD.

Settings: NVD_API_KEY (environment or the repository .env; 50 requests / 30 s instead of 5),
AEGIS_NVD_FALLBACK=off disables the lookup. Responses are cached in .cache/nvd for 2 days.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CACHE_DIR = ROOT / ".cache" / "nvd"
CACHE_SECONDS = 2 * 86400
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")
OFF = ("off", "false", "0", "no")

# Oracle's description formats (CNA text copied by NVD).
ORACLE_PRODUCT_OF = re.compile(
    r"Vulnerability in the (?P<inner>.+?) product of (?P<product>Oracle [^()]+?)\s*"
    r"\((?:sub)?component:\s*(?P<component>[^)]+?)\s*\)", re.I)
ORACLE_COMPONENT_OF = re.compile(
    r"Vulnerability in the (?P<component>.+?) component of (?P<product>Oracle [^.(]+?)"
    r"\s*(?:\((?:sub)?component:\s*(?P<sub>[^)]+?)\s*\))?[.,]", re.I)
ORACLE_OLD = re.compile(r"\bvulnerability in (?P<product>Oracle [A-Z][\w ]*?[A-Za-z])\s+(?:\d|before|and)", re.I)
ORACLE_VECTORS = re.compile(r"\bvectors related to (?P<component>[A-Z][\w/ -]{1,60}?)(?:[.,;]|\s+(?:and|which)\b|$)")

SPECIAL_WORDS = {
    "openssl": "OpenSSL", "openssh": "OpenSSH", "mysql": "MySQL", "jdk": "JDK", "jre": "JRE",
    "http": "HTTP", "sql": "SQL", "ibm": "IBM", "aix": "AIX", "php": "PHP", "xml": "XML",
    "postgresql": "PostgreSQL", "sqlite": "SQLite", "jboss": "JBoss", "weblogic": "WebLogic",
    "peoplesoft": "PeopleSoft", "virtualbox": "VirtualBox", "graalvm": "GraalVM",
    "openjdk": "OpenJDK", "javascript": "JavaScript", "ssl": "SSL", "tls": "TLS", "ldap": "LDAP",
    "dns": "DNS", "ssh": "SSH", "api": "API", "vm": "VM", "os": "OS", "redhat": "Red Hat",
    "libxml2": "libxml2", "glibc": "glibc", "curl": "curl", "libcurl": "libcurl", "e-business": "E-Business",
    "jd": "JD", "pl/sql": "PL/SQL", "ui": "UI", "tibco": "TIBCO", "vmware": "VMware",
}

_lock = threading.Lock()
_next_request = 0.0


def enabled() -> bool:
    return os.environ.get("AEGIS_NVD_FALLBACK", "on").strip().casefold() not in OFF


def api_key() -> str | None:
    """NVD_API_KEY from the environment, else the repository .env (never logged)."""
    if not os.environ.get("NVD_API_KEY"):
        try:
            from dotenv import load_dotenv
            load_dotenv(ROOT / ".env", override=False)
        except Exception:  # noqa: BLE001 - python-dotenv missing: environment only
            pass
    return (os.environ.get("NVD_API_KEY") or "").strip() or None


def _wait(interval: float) -> None:
    global _next_request
    with _lock:
        delay = _next_request - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        _next_request = max(time.monotonic(), _next_request) + interval


def fetch(cve: str, retries: int = 3) -> tuple[dict | None, str | None]:
    """The NVD record for one CVE: (record or None, error or None). Cached on disk."""
    cve = cve.strip().upper()
    if not CVE_ID.match(cve):
        return None, "not a CVE ID"
    cache = CACHE_DIR / f"{cve}.json"
    try:
        if time.time() - cache.stat().st_mtime < CACHE_SECONDS:
            saved = json.loads(cache.read_text(encoding="utf-8"))
            return saved.get("cve"), None
    except (OSError, ValueError):
        pass
    key = api_key()
    headers = {"User-Agent": "aegis-enrichment/1.0", "Accept": "application/json"}
    if key:
        headers["apiKey"] = key
    error = None
    for attempt in range(retries + 1):
        _wait(0.7 if key else 6.5)
        try:
            request = urllib.request.Request(NVD_URL.format(cve=cve), headers=headers)
            with urllib.request.urlopen(request, timeout=30) as response:
                data = json.loads(response.read().decode("utf-8"))
            items = data.get("vulnerabilities") or []
            record = items[0].get("cve") if items else None
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            cache.write_text(json.dumps({"cve": record}), encoding="utf-8")
            return record, None
        except urllib.error.HTTPError as exc:
            error = f"NVD HTTP {exc.code}"
            if exc.code not in (403, 429, 500, 502, 503, 504):
                break
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            error = f"NVD unavailable: {type(exc).__name__}"
        if attempt < retries:
            time.sleep(min(30, 3 * 2 ** attempt))
    return None, error


def pretty_name(vendor: str, product: str) -> str:
    def words(text: str) -> list[str]:
        return [SPECIAL_WORDS.get(word.casefold(), word.capitalize() if word.islower() else word)
                for word in text.replace("_", " ").split()]
    name = " ".join(words(product))
    vendor_name = " ".join(words(vendor))
    if not vendor or vendor in ("*", "-") or product.casefold().startswith(vendor.casefold()):
        return name
    return f"{vendor_name} {name}"


def _named_in(name: str, criteria: str, text: str) -> bool:
    """True when the description names this CPE product ("Apache Tomcat", or "tomcat")."""
    lowered = text.casefold()
    product = criteria.split(":")[4].replace("_", " ").casefold() if criteria.count(":") >= 4 else ""
    return bool(text) and (name.casefold() in lowered or (
        len(product) >= 4 and re.search(r"(?<![\w-])" + re.escape(product) + r"(?![\w-])", lowered)))


def _english(entries) -> str:
    return next((" ".join(str(entry.get("value", "")).split()) for entry in entries or []
                 if str(entry.get("lang", "")).startswith("en")), "")


def facts(record: dict | None) -> dict:
    """Plain fields from one NVD CVE record."""
    out = {"description": "", "status": "", "products": [], "product": "", "product_quote": "",
           "product_source": "", "component": "", "component_quote": "", "affected": [],
           "fixed": [], "cvss": "", "cwe": [], "kev": ""}
    if not record:
        return out
    # Some NVD descriptions carry vendor HTML ("<span class=font-red>...</span>"); a product
    # name must not include it.
    # Only the tags are removed: their text stays ("Tomcat <b>before</b> 9.0.99" keeps "before").
    out["description"] = re.sub(r"<[^>]+>", " ", _english(record.get("descriptions")))
    out["description"] = " ".join(out["description"].split())
    out["status"] = record.get("vulnStatus", "")
    cpes, counts = {}, Counter()
    for configuration in record.get("configurations") or []:
        for node in configuration.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                parts = str(match.get("criteria", "")).split(":")
                if not match.get("vulnerable") or len(parts) < 7:
                    continue
                part, vendor, product, version = parts[2], parts[3], parts[4], parts[5]
                name = pretty_name(vendor, product)
                cpes.setdefault(name, (part, match["criteria"]))
                counts[name] += 1
                low = match.get("versionStartIncluding") or match.get("versionStartExcluding")
                high = match.get("versionEndExcluding") or match.get("versionEndIncluding")
                if high or low:
                    bound = ("< " + match["versionEndExcluding"] if match.get("versionEndExcluding")
                             else "<= " + match["versionEndIncluding"] if match.get("versionEndIncluding") else "")
                    start = (">= " + match["versionStartIncluding"] if match.get("versionStartIncluding")
                             else "> " + match["versionStartExcluding"] if match.get("versionStartExcluding") else "")
                    out["affected"].append(f"{name}: {', '.join(x for x in (start, bound) if x)}")
                    if match.get("versionEndExcluding"):
                        out["fixed"].append(f"{name}: {match['versionEndExcluding']}")
                elif version not in ("*", "-"):
                    out["affected"].append(f"{name}: {version}" + ("" if parts[6] in ("*", "-") else f" {parts[6]}"))
    # Applications first, then operating systems, then hardware; most-listed first.
    ranked = sorted(counts, key=lambda name: ("aoh".find(cpes[name][0]) % 3, -counts[name]))
    out["products"] = ranked
    out["affected"] = list(dict.fromkeys(out["affected"]))[:25]
    out["fixed"] = list(dict.fromkeys(out["fixed"]))[:25]

    text = out["description"]
    match = ORACLE_PRODUCT_OF.search(text)
    if match:
        out.update(product=match["product"].strip(), component=match["component"].strip(),
                   product_quote=match.group(0), component_quote=match.group(0),
                   product_source="NVD description")
    else:
        match = ORACLE_COMPONENT_OF.search(text)
        if match:
            component = (match["sub"] or match["component"]).strip()
            out.update(product=match["product"].strip(), component=component,
                       product_quote=match.group(0), component_quote=match.group(0),
                       product_source="NVD description")
        else:
            old = ORACLE_OLD.search(text)
            vectors = ORACLE_VECTORS.search(text)
            if old:
                out.update(product=old["product"].strip(), product_quote=old.group(0).strip(),
                           product_source="NVD description")
            if vectors and "Oracle" in text:
                out.update(component=vectors["component"].strip(), component_quote=vectors.group(0).strip())
    if not out["product"] and ranked:
        # A CPE product is used only when it is the only one, or the description names it:
        # a protocol flaw (CVE-2004-0230, TCP) lists dozens of unrelated products.
        named = [name for name in ranked if _named_in(name, cpes[name][1], text)]
        choice = named[0] if named else ranked[0] if len(ranked) == 1 else None
        if choice:
            out.update(product=choice, product_quote=cpes[choice][1], product_source="NVD CPE")

    metrics = record.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        rows = metrics.get(key) or []
        row = next((r for r in rows if r.get("type") == "Primary"), rows[0] if rows else None)
        if row:
            data = row.get("cvssData") or {}
            severity = data.get("baseSeverity") or row.get("baseSeverity") or ""
            out["cvss"] = f"{data.get('baseScore')} {severity} (CVSS {data.get('version', '')}, {data.get('vectorString', '')})".strip()
            break
    out["cwe"] = list(dict.fromkeys(
        item.get("value") for weakness in record.get("weaknesses") or []
        for item in weakness.get("description") or []
        if str(item.get("value", "")).startswith("CWE-")))
    if record.get("cisaExploitAdd"):
        out["kev"] = f"CISA KEV since {record['cisaExploitAdd']}: {record.get('cisaRequiredAction', '')}".strip()
    return out
