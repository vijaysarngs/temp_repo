"""Read CVE IDs from a CSV, look each one up in the public sources, write one row per CVE."""
import csv
import json
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from .extract import cve_org_fields, cwe_ids, nvd_fields, osv_fields, redhat_fields, unique
from .http_client import FetchError

CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
SEPARATOR = " | "
# The CVSS shown in the summary columns: NVD's own score first, then the CNA's, then others.
CVSS_SOURCE_ORDER = ("NVD", "CNA")
CVSS_VERSION_ORDER = ("3.1", "3.0", "4.0", "3.x", "2.0")

COLUMNS = [
    "CVE ID", "Input Rows", "CVE State", "Title", "Description", "Description Source",
    "Vendors", "Products", "CPE Products", "CPE Operating Systems",
    "Components", "Component Evidence", "Packages",
    "Affected Versions", "Fixed Versions",
    "CWE", "CVSS Score", "CVSS Severity", "CVSS Version", "CVSS Vector", "CVSS Source",
    "Red Hat Severity", "Red Hat Fixed Packages (RHEL)", "Red Hat Package States (RHEL)",
    "Red Hat Statement", "Mitigation",
    "Known Exploited (CISA KEV)", "KEV Date Added", "KEV Due Date", "KEV Required Action",
    "KEV Ransomware Use", "EPSS Score", "EPSS Percentile", "SSVC (CISA)",
    "Published", "Last Modified", "Assigner", "NVD Status", "OSV IDs", "References",
    "Sources With Data", "Sources Without Record", "Source Errors",
]


def read_cves(path, column=None):
    """Return {cve: [input row numbers]} in first-seen order.

    Uses `column` when given, else a header containing 'cve', else every cell.
    """
    with open(path, encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        headers = reader.fieldnames or []
        if column and column not in headers:
            raise ValueError(f"Column '{column}' not found. Columns: {', '.join(headers)}")
        candidates = [column] if column else [h for h in headers if "cve" in h.casefold()]
        rows = list(reader)
    found = {}

    def scan(names):
        for number, row in enumerate(rows, 2):
            for name in names:
                for cve in CVE_PATTERN.findall(str(row.get(name) or "")):
                    found.setdefault(cve.upper(), []).append(number)

    scan(candidates)
    if not found and not column:
        scan(headers)  # no CVE column: look in every cell
    return {cve: unique(numbers) for cve, numbers in found.items()}


def best_cvss(scores):
    def rank(score):
        source = score.get("source", "")
        source_rank = CVSS_SOURCE_ORDER.index(source) if source in CVSS_SOURCE_ORDER else len(CVSS_SOURCE_ORDER)
        version = score.get("version", "")
        version_rank = CVSS_VERSION_ORDER.index(version) if version in CVSS_VERSION_ORDER else 9
        return (source_rank, version_rank)
    usable = [score for score in scores if score.get("score") is not None]
    return min(usable, key=rank) if usable else {}




def combine(cve, rows, data, errors, epss, kev):
    """Merge every source's fields into one output row (plus a detailed record for JSON)."""
    org = cve_org_fields(data.get("cve_org"))
    nvd = nvd_fields(data.get("nvd"))
    osv = osv_fields(data.get("osv"))
    redhat = redhat_fields(data.get("redhat"))

    for label, text in (("CVE.org", org["description"]), ("NVD", nvd["description"]),
                        ("OSV", osv["details"] or osv["summary"]), ("Red Hat", redhat["details"])):
        if text:
            description, description_source = text, label
            break
    else:
        description, description_source = "", ""

    components = unique(org["components"] + osv["components"])
    evidence = unique(org["component_evidence"] + osv["component_evidence"])
    cvss = best_cvss(org["cvss"] + nvd["cvss"] + redhat["cvss"])
    kev_entry = kev.get(cve) or {}
    nvd_kev = nvd["kev"]
    epss_row = epss.get(cve) or {}

    with_data = [name for name, value in (("CVE.org", data.get("cve_org")), ("NVD", data.get("nvd")),
                                          ("OSV", data.get("osv")), ("Red Hat", data.get("redhat")),
                                          ("EPSS", epss_row), ("CISA KEV", kev_entry)) if value]
    queried = {"cve_org": "CVE.org", "nvd": "NVD", "osv": "OSV", "redhat": "Red Hat"}
    without = [label for key, label in queried.items()
               if key in data and not data.get(key) and key not in errors]

    row = {
        "CVE ID": cve,
        "Input Rows": SEPARATOR.join(map(str, rows)),
        "CVE State": org["state"] or ("NOT_FOUND" if "cve_org" in data and "cve_org" not in errors else ""),
        "Title": org["title"],
        "Description": description,
        "Description Source": description_source,
        "Vendors": SEPARATOR.join(org["vendors"]),
        "Products": SEPARATOR.join(org["products"]),
        "CPE Products": SEPARATOR.join(nvd["products"]),
        "CPE Operating Systems": SEPARATOR.join(nvd["os_products"]),
        "Components": SEPARATOR.join(components),
        "Component Evidence": SEPARATOR.join(evidence),
        "Packages": SEPARATOR.join(unique(org["packages"] + osv["packages"] + redhat["packages"])),
        "Affected Versions": SEPARATOR.join([f"[CVE.org] {v}" for v in org["affected"]]
                                            + [f"[NVD] {v}" for v in nvd["affected"]]
                                            + [f"[OSV] {v}" for v in osv["affected"]]),
        "Fixed Versions": SEPARATOR.join([f"[CVE.org] {v}" for v in org["fixed"]]
                                         + [f"[NVD] {v}" for v in nvd["fixed"]]
                                         + [f"[OSV] {v}" for v in osv["fixed"]]),
        "CWE": SEPARATOR.join(cwe_ids(org["cwes"] + nvd["cwes"] + re.findall(r"CWE-\d+", redhat["cwe"]))),
        "CVSS Score": cvss.get("score", ""),
        "CVSS Severity": cvss.get("severity", ""),
        "CVSS Version": cvss.get("version", ""),
        "CVSS Vector": cvss.get("vector", ""),
        "CVSS Source": cvss.get("source", ""),
        "Red Hat Severity": redhat["severity"],
        "Red Hat Fixed Packages (RHEL)": SEPARATOR.join(redhat["fixed_packages"]),
        "Red Hat Package States (RHEL)": SEPARATOR.join(redhat["package_states"]),
        "Red Hat Statement": redhat["statement"],
        "Mitigation": redhat["mitigation"],
        "Known Exploited (CISA KEV)": "Yes" if (kev_entry or nvd_kev) else "No",
        "KEV Date Added": kev_entry.get("dateAdded") or nvd_kev.get("dateAdded", ""),
        "KEV Due Date": kev_entry.get("dueDate") or nvd_kev.get("dueDate", ""),
        "KEV Required Action": kev_entry.get("requiredAction") or nvd_kev.get("requiredAction", ""),
        "KEV Ransomware Use": kev_entry.get("knownRansomwareCampaignUse", ""),
        "EPSS Score": epss_row.get("epss", ""),
        "EPSS Percentile": epss_row.get("percentile", ""),
        "SSVC (CISA)": org["ssvc"],
        "Published": org["published"] or nvd["published"],
        "Last Modified": org["updated"] or nvd["updated"],
        "Assigner": org["assigner"],
        "NVD Status": nvd["status"],
        "OSV IDs": SEPARATOR.join(osv["ids"]),
        "References": SEPARATOR.join(unique(org["references"] + nvd["references"])[:10]),
        "Sources With Data": SEPARATOR.join(with_data),
        "Sources Without Record": SEPARATOR.join(without),
        "Source Errors": SEPARATOR.join(f"{name}: {message}" for name, message in errors.items()),
    }
    detail = {"cve": cve, "input_rows": rows, "summary": row,
              "sources": {"cve_org": org, "nvd": nvd, "osv": osv, "redhat": redhat,
                          "epss": epss_row, "kev": kev_entry}}
    return row, detail


def enrich(cves, sources, workers=4, progress=None):
    """Look up every CVE. `cves` is {cve: input rows}. Returns (rows, details)."""
    errors_shared = {}
    epss, kev = {}, {}
    if "epss" in sources.enabled:
        try:
            epss = sources.epss(list(cves))
        except FetchError as error:
            errors_shared["EPSS"] = str(error)
    if "kev" in sources.enabled:
        try:
            kev = sources.kev()
        except FetchError as error:
            errors_shared["CISA KEV"] = str(error)

    def one(item):
        cve, rows = item
        data, errors = sources.per_cve(cve)
        errors.update(errors_shared)
        return combine(cve, rows, data, errors, epss, kev)

    results = []
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        for index, result in enumerate(pool.map(one, cves.items()), 1):
            results.append(result)
            if progress:
                progress(index, len(cves), result[0])
    return [row for row, _ in results], [detail for _, detail in results]


def write_outputs(rows, details, out_dir, stem):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = out_dir / f"{stem}.csv"
    json_path = out_dir / f"{stem}.json"
    with csv_path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    json_path.write_text(json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "cve_count": len(rows), "cves": details}, indent=2), encoding="utf-8")
    return csv_path, json_path


def load_env_value(name, env_file):
    """Read one setting from the environment, else from a .env file (never printed)."""
    if os.environ.get(name):
        return os.environ[name]
    try:
        for line in Path(env_file).read_text(encoding="utf-8").splitlines():
            key, _, value = line.partition("=")
            if key.strip() == name:
                return value.strip().strip('"').strip("'") or None
    except OSError:
        pass
    return None


def print_progress(index, total, row):
    found = row["Sources With Data"] or "no source"
    errors = f"  errors: {row['Source Errors']}" if row["Source Errors"] else ""
    print(f"[{index}/{total}] {row['CVE ID']}: {found}{errors}", file=sys.stderr, flush=True)
