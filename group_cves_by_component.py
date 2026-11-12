"""Group enriched CVE rows by their classified product and component."""

import csv
import sys
from functools import lru_cache
from pathlib import Path

from cve_component_enrichment import COMPONENT_COLUMNS, component_identifier
from product_names import unify_products


LIST_COLUMNS = {
    "Application", "Description", "CVE IDs", "Operating System",
    "Technical Details", "Evidence", "Affected Symbol", "Source Path",
    "Component Kind", "Classification Status", "Classification Reason",
    "Source Rows", "Hostname", "Hosts", "Host OS",
    "NVD Description", "CVSS", "CWE", "Affected Versions (NVD)", "Fixed Versions (NVD)",
    "Known Exploited",
}


def _values(value):
    return [item.strip() for item in str(value or "").split(" | ") if item.strip()]


# Labels that mean "no component was identified"; such CVEs are never combined.
UNSPECIFIED_COMPONENTS = {"", "unspecified", "unspecified component"}


def is_unspecified_component(component):
    return str(component or "").strip().casefold() in UNSPECIFIED_COMPONENTS


def is_os_finding(scanner_type) -> bool:
    """The scanner's Type column says the finding is in the operating system."""
    return str(scanner_type or "").strip().casefold() in ("os", "operating system")


def host_os_entries(row):
    """"server => OS" for each server of one source row. Grouping merges the OS names of
    many rows, so this is the last point where each server's OS is known. A row naming
    several OS names cannot say which server runs which, so it adds nothing."""
    existing = _values(row.get("Host OS", ""))
    if existing:
        return existing
    systems = _values(row.get("Operating System", ""))
    if len(systems) != 1:
        return []
    servers = _values(row.get("Hostname", "")) or [
        entry.split(":", 1)[1].strip() if entry.upper().startswith("CVE-") and ":" in entry else entry
        for entry in _values(row.get("Hosts", ""))]
    return [f"{server} => {systems[0]}" for server in dict.fromkeys(servers)]


_EVIDENCE_ROOT = str(Path(__file__).resolve().parent / "aegis-cve-evidence")


def os_group_key(os_names) -> str:
    """The operating system a row belongs to (os_catalog.group_key): AIX 7.2 and 7.2.5
    share a key, AIX and Red Hat do not."""
    return _os_group_key(tuple(os_names or ()))


@lru_cache(maxsize=4096)
def _os_group_key(os_names: tuple) -> str:
    # A file has few distinct OS names; the catalogue lookup is the same for each repeat.
    if _EVIDENCE_ROOT not in sys.path:
        sys.path.insert(0, _EVIDENCE_ROOT)
    import os_catalog
    return os_catalog.group_key(list(os_names))


def group_by_product_and_component(rows):
    """Combine CVEs only when their product, component and operating system match.

    The same CVE on AIX and on Linux gives two rows (each OS has its own fix and
    compatibility rules), even though the CVE then appears twice. A CVE with no identified
    component stays on its own row (its contexts are still merged) with its own Component
    ID, so remediation treats each one separately.
    """
    groups = {}
    # One spelling per product across the file ("PCRE2"/"Pcre2", "Openbsd OpenSSH"/"OpenBSD
    # OpenSSH"), so one product is one group with one route and one set of rules.
    names = unify_products(str(row.get("Product", "")).strip() for row in rows)
    for row in rows:
        product = names[str(row.get("Product", "")).strip()]
        if product != str(row.get("Product", "")).strip():
            row = {**row, "Product": product}
        component = str(row.get("Component", "")).strip()
        scanner_type = str(row.get("Scanner Type", "")).strip()
        if is_os_finding(scanner_type):
            # An OS finding is fixed by the OS update as a whole: no component.
            component = ""
            row = {**row, "Component": ""}
        identity = component
        if is_unspecified_component(component):
            identity = f"{component} [{' | '.join(_values(row.get('CVE IDs', '')))}]"
        os_key = os_group_key(_values(row.get("Operating System", "")))
        if os_key:
            identity = f"{identity} [{os_key}]"
        if is_os_finding(scanner_type):
            # OS and App findings of one product are fixed by different routes. App rows keep
            # their earlier Component IDs.
            identity = f"{identity} [os]"
        key = (product, identity)
        group = groups.setdefault(key, {
            column: [] if column in LIST_COLUMNS else str(row.get(column, "")).strip()
            for column in COMPONENT_COLUMNS
        })
        group["Component ID"] = component_identifier(product, identity)
        for column in LIST_COLUMNS - {"Host OS"}:
            group[column].extend(_values(row.get(column, "")))
        group["Host OS"].extend(host_os_entries(row))

    output = []
    for group in groups.values():
        output.append({
            column: " | ".join(dict.fromkeys(value)) if isinstance(value, list) else value
            for column, value in group.items()
        })
    return sorted(output, key=lambda row: (
        row["Product"].casefold(), row["Component"].casefold(), row["CVE IDs"]
    ))


def write_grouped_csv(path, rows):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=COMPONENT_COLUMNS)
        writer.writeheader()
        writer.writerows(group_by_product_and_component(rows))
    return path
