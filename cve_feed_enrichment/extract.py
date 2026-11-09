"""Turn each source's record into plain fields: products, components, versions, scores...

Every function here is pure (record in, dict out) and copies what the source says;
nothing is guessed. A component is only reported when a source names it.
"""
import re

NOT_APPLICABLE = {"", "n/a", "na", "-", "*", "unspecified", "unknown"}
# Oracle and some other vendors put the component in the description: "(component: JSSE)".
DESCRIPTION_COMPONENT = re.compile(r"\(\s*(?:sub)?components?\s*:\s*([^)]+?)\s*\)", re.I)
# Oracle's pre-2017 wording: "... Oracle Java SE ... via vectors related to Serialization."
ORACLE_OLD_COMPONENT = re.compile(r"\bvectors related to ([A-Z][\w/ -]{1,60}?)(?:[.,;]|\s+(?:and|a different|which)\b|$)")
CWE_ID = re.compile(r"^CWE-\d+$", re.I)
REFERENCE_TAGS = {"vendor-advisory", "patch", "release-notes", "mitigation",
                  "Vendor Advisory", "Patch", "Release Notes", "Mitigation"}
CVSS_KEYS = (("cvssV4_0", "4.0"), ("cvssV3_1", "3.1"), ("cvssV3_0", "3.0"), ("cvssV2_0", "2.0"))
NVD_METRIC_KEYS = (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"),
                   ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0"))
MAX_EXACT_VERSIONS = 12


def unique(values):
    return list(dict.fromkeys(value for value in values if value))


def _blank(value):
    return str(value or "").strip().casefold() in NOT_APPLICABLE


def english(entries, key="value"):
    for entry in entries or []:
        if str(entry.get("lang", "")).lower().startswith("en") and entry.get(key):
            return " ".join(str(entry[key]).split())
    return ""


def description_components(text):
    """Components a vendor names in the description in a fixed format (Oracle)."""
    found = []
    for match in DESCRIPTION_COMPONENT.findall(text or ""):
        found.extend(part.strip() for part in match.split(","))
    if not found and "Oracle" in (text or ""):
        found.extend(match.strip() for match in ORACLE_OLD_COMPONENT.findall(text or ""))
    return unique(part for part in found if not _blank(part))


def cwe_ids(values):
    return unique(str(value).strip().upper() for value in values if CWE_ID.match(str(value or "").strip()))


# ---------------------------------------------------------------- CVE.org

def _cve_org_affected(entry, label):
    """Affected and fixed versions from one CVE JSON 5 'affected' entry."""
    affected, fixed = [], []
    for version in entry.get("versions") or []:
        if version.get("versionType") == "git":
            continue  # commit hashes, not release versions
        start = str(version.get("version") or "").strip()
        status = version.get("status")
        less_than = str(version.get("lessThan") or "").strip()
        less_equal = str(version.get("lessThanOrEqual") or "").strip()
        open_start = _blank(start) or start == "0"
        if "*" in less_than or "*" in less_equal:
            less_than = less_equal = ""  # a wildcard bound ("log4j-core*") is not a version
        if status == "affected":
            if less_than and less_than != "*":
                affected.append(f"< {less_than}" if open_start else f"{start} to < {less_than}")
                fixed.append(less_than)
            elif less_equal and less_equal != "*":
                affected.append(f"<= {less_equal}" if open_start else f"{start} to <= {less_equal}")
            elif not _blank(start):
                affected.append(start if version.get("lessThan") is None and version.get("lessThanOrEqual") is None
                                else f"from {start}")
        elif status == "unaffected" and not _blank(start) and start != "0":
            # An 'unaffected' version listed next to affected ones is where the fix landed.
            fixed.append(f"{start} to < {less_than}" if less_than and less_than != "*" else start)
        for change in version.get("changes") or []:
            if change.get("status") == "unaffected" and change.get("at"):
                fixed.append(str(change["at"]))
    prefix = f"{label}: " if label else ""
    return [prefix + item for item in unique(affected)], [prefix + item for item in unique(fixed)]


def _cvss_from_cve_org(metrics, source):
    found = []
    for metric in metrics or []:
        for key, version in CVSS_KEYS:
            data = metric.get(key)
            if data and data.get("baseScore") is not None:
                found.append({"version": version, "score": data.get("baseScore"),
                              "severity": data.get("baseSeverity", ""),
                              "vector": data.get("vectorString", ""), "source": source})
    return found


def cve_org_fields(record):
    out = {"description": "", "title": "", "state": "", "assigner": "", "published": "",
           "updated": "", "vendors": [], "products": [], "components": [], "packages": [],
           "cpes": [], "affected": [], "fixed": [], "cwes": [], "cvss": [], "references": [],
           "ssvc": "", "component_evidence": []}
    if not record:
        return out
    meta = record.get("cveMetadata") or {}
    out.update(state=meta.get("state", ""), assigner=meta.get("assignerShortName", ""),
               published=meta.get("datePublished", ""), updated=meta.get("dateUpdated", ""))
    containers = record.get("containers") or {}
    cna = containers.get("cna") or {}
    adps = containers.get("adp") or []
    out["description"] = english(cna.get("descriptions"))
    out["title"] = cna.get("title", "")
    if meta.get("state") == "REJECTED":
        out["description"] = out["description"] or english(cna.get("rejectedReasons"))

    for container, origin in [(cna, "CNA")] + [(adp, adp.get("title") or "ADP") for adp in adps]:
        for entry in container.get("affected") or []:
            vendor = str(entry.get("vendor") or "").strip()
            product = str(entry.get("product") or "").strip()
            if not _blank(vendor):
                out["vendors"].append(vendor)
            if not _blank(product):
                out["products"].append(product)
            names = [str(item) for item in entry.get("modules") or []]
            names += [str(item) for item in entry.get("programFiles") or []]
            names += [str(item.get("name")) for item in entry.get("programRoutines") or [] if item.get("name")]
            for name in names:
                if not _blank(name):
                    out["components"].append(name)
                    out["component_evidence"].append(f"{name}: CVE record ({origin}) modules/files")
            if entry.get("packageName"):
                out["packages"].append(str(entry["packageName"]))
            out["cpes"].extend(entry.get("cpes") or [])
            affected, fixed = _cve_org_affected(entry, product if not _blank(product) else "")
            out["affected"].extend(affected)
            out["fixed"].extend(fixed)
        for problem in container.get("problemTypes") or []:
            for item in problem.get("descriptions") or []:
                out["cwes"].append(item.get("cweId") or item.get("description", "").split(" ")[0])
        out["cvss"].extend(_cvss_from_cve_org(container.get("metrics"), origin))
        for metric in container.get("metrics") or []:
            other = metric.get("other") or {}
            if other.get("type") == "ssvc":
                options = (other.get("content") or {}).get("options") or []
                out["ssvc"] = "; ".join(f"{k}: {v}" for option in options for k, v in option.items())
        for reference in container.get("references") or []:
            if REFERENCE_TAGS.intersection(reference.get("tags") or []):
                out["references"].append(reference.get("url", ""))

    for name in description_components(out["description"]):
        out["components"].append(name)
        out["component_evidence"].append(f"{name}: named in the CVE description (vendor's fixed wording)")
    out["cwes"] = cwe_ids(out["cwes"])
    for key in ("vendors", "products", "components", "packages", "cpes", "affected", "fixed",
                "references", "component_evidence"):
        out[key] = unique(out[key])
    return out


# ---------------------------------------------------------------- NVD

def cpe_parts(criteria):
    parts = criteria.split(":")
    if len(parts) < 7:
        return None
    return {"part": parts[2], "vendor": parts[3], "product": parts[4],
            "version": parts[5], "update": parts[6]}


def _nvd_range(match):
    low = (f">= {match['versionStartIncluding']}" if match.get("versionStartIncluding")
           else f"> {match['versionStartExcluding']}" if match.get("versionStartExcluding") else "")
    high = (f"< {match['versionEndExcluding']}" if match.get("versionEndExcluding")
            else f"<= {match['versionEndIncluding']}" if match.get("versionEndIncluding") else "")
    return ", ".join(part for part in (low, high) if part)


def nvd_fields(cve):
    out = {"description": "", "status": "", "published": "", "updated": "", "products": [],
           "os_products": [], "cpes": [], "affected": [], "fixed": [], "cwes": [], "cvss": [],
           "references": [], "kev": {}}
    if not cve:
        return out
    out.update(description=english(cve.get("descriptions")), status=cve.get("vulnStatus", ""),
               published=cve.get("published", ""), updated=cve.get("lastModified", ""))
    exact = {}
    for configuration in cve.get("configurations") or []:
        for node in configuration.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                if not match.get("vulnerable"):
                    continue  # platform the product runs on, not the vulnerable product
                parts = cpe_parts(match.get("criteria", ""))
                if not parts:
                    continue
                name = f"{parts['vendor']}:{parts['product']}"
                (out["os_products"] if parts["part"] == "o" else out["products"]).append(name)
                out["cpes"].append(match["criteria"])
                version_range = _nvd_range(match)
                if version_range:
                    out["affected"].append(f"{name}: {version_range}")
                    if match.get("versionEndExcluding"):
                        out["fixed"].append(f"{name}: {match['versionEndExcluding']}")
                elif parts["version"] not in ("*", "-"):
                    version = parts["version"] + ("" if parts["update"] in ("*", "-") else f" {parts['update']}")
                    exact.setdefault(name, []).append(version)
    for name, versions in exact.items():
        versions = unique(versions)
        if len(versions) > MAX_EXACT_VERSIONS:
            out["affected"].append(f"{name}: {len(versions)} listed versions ({versions[0]} ... {versions[-1]})")
        else:
            out["affected"].append(f"{name}: {', '.join(versions)}")
    for weakness in cve.get("weaknesses") or []:
        for item in weakness.get("description") or []:
            if item.get("value") not in ("NVD-CWE-Other", "NVD-CWE-noinfo"):
                out["cwes"].append(item.get("value", ""))
    metrics = cve.get("metrics") or {}
    for key, version in NVD_METRIC_KEYS:
        for metric in metrics.get(key) or []:
            data = metric.get("cvssData") or {}
            out["cvss"].append({"version": version, "score": data.get("baseScore"),
                                "severity": data.get("baseSeverity") or metric.get("baseSeverity", ""),
                                "vector": data.get("vectorString", ""),
                                "source": "NVD" if metric.get("type") == "Primary" else f"NVD ({metric.get('source', '')})"})
    for reference in cve.get("references") or []:
        if REFERENCE_TAGS.intersection(reference.get("tags") or []):
            out["references"].append(reference.get("url", ""))
    if cve.get("cisaExploitAdd"):
        out["kev"] = {"dateAdded": cve.get("cisaExploitAdd"), "dueDate": cve.get("cisaActionDue", ""),
                      "requiredAction": cve.get("cisaRequiredAction", ""),
                      "vulnerabilityName": cve.get("cisaVulnerabilityName", "")}
    out["cwes"] = cwe_ids(out["cwes"])
    for key in ("products", "os_products", "cpes", "affected", "fixed", "references"):
        out[key] = unique(out[key])
    return out


# ---------------------------------------------------------------- OSV

def package_short_name(ecosystem, name):
    if ecosystem == "Maven" and ":" in name:
        return name.split(":", 1)[1]  # group:artifact -> artifact
    return name


def osv_fields(records):
    out = {"ids": [], "summary": "", "details": "", "packages": [], "components": [],
           "affected": [], "fixed": [], "component_evidence": []}
    for record in records or []:
        out["ids"].append(record.get("id", ""))
        out["summary"] = out["summary"] or record.get("summary", "")
        out["details"] = out["details"] or " ".join(str(record.get("details", "")).split())
        for entry in record.get("affected") or []:
            package = entry.get("package") or {}
            ecosystem, name = package.get("ecosystem", ""), package.get("name", "")
            if not name:
                continue
            label = f"{ecosystem}: {name}" if ecosystem else name
            out["packages"].append(label)
            short = package_short_name(ecosystem, name)
            out["components"].append(short)
            out["component_evidence"].append(f"{short}: OSV package {label} ({record.get('id', '')})")
            for version_range in entry.get("ranges") or []:
                if version_range.get("type") == "GIT":
                    continue
                introduced = fixed = last = ""
                for event in version_range.get("events") or []:
                    introduced = event.get("introduced", introduced)
                    fixed = event.get("fixed", fixed)
                    last = event.get("last_affected", last)
                    if fixed or last:
                        start = "" if introduced in ("", "0") else f">= {introduced}, "
                        end = f"< {fixed}" if fixed else f"<= {last}"
                        out["affected"].append(f"{label}: {start}{end}")
                        if fixed:
                            out["fixed"].append(f"{label}: {fixed}")
                        introduced = fixed = last = ""
                if introduced and introduced != "0":
                    out["affected"].append(f"{label}: >= {introduced} (no fix listed)")
    for key in ("ids", "packages", "components", "affected", "fixed", "component_evidence"):
        out[key] = unique(out[key])
    return out


# ---------------------------------------------------------------- Red Hat

RPM_NAME = re.compile(r"^(.+?)-(?:\d+:)?\d[^-]*-[^-]+$")


def rpm_name(package):
    match = RPM_NAME.match(package or "")
    return match.group(1) if match else package


def redhat_fields(record, rhel_only=True):
    out = {"severity": "", "cvss": [], "cwe": "", "statement": "", "mitigation": "",
           "fixed_packages": [], "package_states": [], "packages": [], "details": ""}
    if not record:
        return out
    out["severity"] = record.get("threat_severity", "")
    cvss3 = record.get("cvss3") or {}
    if cvss3.get("cvss3_base_score"):
        out["cvss"].append({"version": "3.x", "score": float(cvss3["cvss3_base_score"]),
                            "severity": out["severity"], "vector": cvss3.get("cvss3_scoring_vector", ""),
                            "source": "Red Hat"})
    out["cwe"] = record.get("cwe", "")
    out["statement"] = " ".join(str(record.get("statement") or "").split())
    mitigation = record.get("mitigation")
    out["mitigation"] = " ".join(str(mitigation.get("value", "") if isinstance(mitigation, dict)
                                     else mitigation or "").split())
    out["details"] = " ".join(" ".join(record.get("details") or []).split())
    for release in record.get("affected_release") or []:
        product = release.get("product_name", "")
        if rhel_only and not product.startswith("Red Hat Enterprise Linux"):
            continue
        package = release.get("package", "")
        out["fixed_packages"].append(f"{product}: {package} ({release.get('advisory', '')})")
        out["packages"].append(rpm_name(package))
    for state in record.get("package_state") or []:
        product = state.get("product_name", "")
        if rhel_only and not product.startswith("Red Hat Enterprise Linux"):
            continue
        out["package_states"].append(f"{product}: {state.get('package_name', '')} - {state.get('fix_state', '')}")
        out["packages"].append(state.get("package_name", ""))
    for key in ("fixed_packages", "package_states", "packages"):
        out[key] = unique(out[key])
    return out
