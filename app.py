import csv
import io
import json
import os
import re
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from threading import Thread
from urllib.parse import urlparse
from uuid import uuid4

from fastapi import Body, FastAPI, File, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

from agent_utils import create_llm_client
from cve_component_enrichment import (
    COMPONENT_COLUMNS,
    build_records,
    classify_cves,
    component_identifier,
    component_rows,
    read_source_file,
    write_csv,
)
from group_cves_by_component import group_by_product_and_component, write_grouped_csv


MAX_UPLOAD_BYTES = 25 * 1024 * 1024
JOBS = {}
PIPELINE_RUNS = {}
COMPATIBILITY_RULE_DRAFTS = {}
UI_DIST = Path(__file__).parent / "ui" / "dist"
DATA_DIR = Path(__file__).parent / "data"
REMEDIATION_RUNNER = (
    Path(__file__).parent / "aegis-cve-evidence" / "remediation" / "run_grouped_remediation.py"
)
REMEDIATION_RUNS_DIR = REMEDIATION_RUNNER.parent / "runs"
REMEDIATION_CONTEXT_DIR = (
    Path(__file__).parent / "aegis-cve-evidence" / "context_gathered" / "test"
)
# Host inventory (YAML) used as the centralized context: the captured Rocky hosts
# (inventory/sterling_rocky8.yaml) and the AIX hosts (inventory/aix/), defined once in
# host_inventory.ACTIVE_INVENTORY. AEGIS_HOST_INVENTORY replaces it (paths separated by ';').
INVENTORY_DIR = Path(__file__).parent / "aegis-cve-evidence" / "context_gathered" / "inventory"
if str(INVENTORY_DIR.parent) not in sys.path:
    sys.path.insert(0, str(INVENTORY_DIR.parent))
from host_inventory import describe_inventory, inventory_paths  # noqa: E402
REMEDIATION_INVENTORY = inventory_paths()
# Save each UI run and its evidence to Oracle (CVE_RUN, CVE_EVIDENCE, CVE_ASSESSMENT).
PERSIST_RUNS = os.getenv("AEGIS_PERSIST_RUNS", "").strip().casefold() in ("1", "true", "yes")
REMEDIATION_PACKAGE_ROOT = str(REMEDIATION_RUNNER.parent.parent)
if REMEDIATION_PACKAGE_ROOT not in sys.path:
    sys.path.insert(0, REMEDIATION_PACKAGE_ROOT)

app = FastAPI(title="Aegis CVE Enrichment API")
if (UI_DIST / "assets").is_dir():
    app.mount("/assets", StaticFiles(directory=UI_DIST / "assets"), name="ui-assets")


def error(message, status=400):
    return JSONResponse({"error": message}, status_code=status)


def generated_run_id():
    return "ui-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-") + uuid4().hex[:8]


def csv_response(rows, columns, filename):
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=columns)
    writer.writeheader()
    writer.writerows(rows)

    return Response(
        content="\ufeff" + stream.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def read_enriched_csv(path):
    """Read an enrichment output while enforcing the grouping input contract."""
    with Path(path).open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        # Older enrichment files did not have Component ID. They remain reusable
        # because the ID can be recreated deterministically from the group key.
        required_columns = [column for column in COMPONENT_COLUMNS if column != "Component ID"]
        missing = [column for column in required_columns if column not in (reader.fieldnames or [])]
        if missing:
            raise ValueError("CSV is not a component enrichment file; missing " + ", ".join(missing))
        rows = []
        for row in reader:
            normalized = {
                column: str(row.get(column, "") or "") for column in COMPONENT_COLUMNS
            }
            normalized["Component ID"] = component_identifier(
                normalized["Product"], normalized["Component"])
            rows.append(normalized)
    if not rows:
        raise ValueError("The saved enrichment CSV has no records.")
    return rows


def reusable_enrichment_files():
    """Return valid saved enrichment outputs, newest first."""
    if not DATA_DIR.exists():
        return []
    candidates = []
    for path in DATA_DIR.glob("*.csv"):
        if path.name == "grouped_by_comp.csv" or path.name.startswith("selected_components_"):
            continue
        try:
            rows = read_enriched_csv(path)
        except (OSError, ValueError, csv.Error):
            continue
        modified = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
        candidates.append({
            "filename": path.name,
            "row_count": len(rows),
            "modified_at": modified.isoformat(),
            "_mtime": path.stat().st_mtime,
        })
    candidates.sort(key=lambda item: item["_mtime"], reverse=True)
    for candidate in candidates:
        candidate.pop("_mtime", None)
    return candidates


def grouped_payload(job_id, enriched_rows, source, source_filename):
    grouped_rows = group_by_product_and_component(enriched_rows)
    job = JOBS[job_id]
    job["enriched_rows"] = enriched_rows
    job["grouped_rows"] = grouped_rows
    grouped_filename = "grouped_by_comp.csv"
    warning = None
    try:
        write_grouped_csv(DATA_DIR / grouped_filename, enriched_rows)
    except PermissionError:
        # Excel commonly locks an open CSV on Windows. Preserve the run instead
        # of failing after enrichment has already completed successfully.
        grouped_filename = f"grouped_by_comp_{job_id}.csv"
        write_grouped_csv(DATA_DIR / grouped_filename, enriched_rows)
        warning = (
            "data/grouped_by_comp.csv is open or locked, so this run was saved as "
            f"data/{grouped_filename}. Close the locked file before the next run."
        )
    job["grouped_filename"] = grouped_filename
    return {
        "run_id": job_id,
        "source": source,
        "source_filename": source_filename,
        "columns": COMPONENT_COLUMNS,
        "rows": enriched_rows,
        "grouped": {
            "columns": COMPONENT_COLUMNS,
            "rows": grouped_rows,
            "filename": grouped_filename,
            "warning": warning,
        },
    }


def execute_selected_pipeline(run_id, selected_path):
    run = PIPELINE_RUNS[run_id]
    run["status"] = "running"
    run["started_at"] = datetime.now(timezone.utc).isoformat()
    try:
        remediation_root = str(REMEDIATION_RUNNER.parent.parent)
        if remediation_root not in sys.path:
            sys.path.insert(0, remediation_root)
        from remediation.run_grouped_remediation import RemediationOptions, run_grouped_remediation

        aggregate = run_grouped_remediation(RemediationOptions(
            input_csv=Path(selected_path),
            latest_per_component=True,
            continue_on_error=True,
            run_id=run_id,
            upload_id=run.get("job_id"),
            # Oracle CVE_RUN / CVE_EVIDENCE / CVE_ASSESSMENT rows, only when enabled.
            persist_context=PERSIST_RUNS,
            # Centralized context: every item's host facts come from the observed host
            # inventory. Per-CVE context files are no longer used.
            allow_dummy=True,
            inventory=REMEDIATION_INVENTORY,
            progress_callback=lambda progress: run.update({"workflow_progress": progress}),
        ))
        if aggregate["status"] not in ("completed", "completed_with_errors"):
            raise RuntimeError(f"Pipeline ended with status {aggregate['status']}")
        combined = REMEDIATION_RUNS_DIR / f"grouped_remediation_{run_id}.json"
        summary = combined.parent / run_id / "run_summary.json"
        if not combined.is_file():
            raise RuntimeError(f"Pipeline did not create its aggregate: {combined}")
        run.update({
            "status": "completed",
            "pipeline_status": aggregate["status"],
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "return_code": 0,
            "combined_output": str(combined.resolve()) if combined.exists() else None,
            "summary_output": str(summary.resolve()) if summary.exists() else None,
            "message": ("Pipeline completed with one or more assessment errors."
                        if aggregate["status"] == "completed_with_errors"
                        else "Pipeline completed; some CVEs reached the model budget."
                        if any((entry.get("remediation_result") or {}).get("assessment_limited")
                               for entry in aggregate.get("results", []))
                        else "Pipeline completed."),
        })
    except Exception as exc:
        run.update({
            "status": "failed",
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "message": f"{type(exc).__name__}: {exc}",
        })


def saved_pipeline_run(run_id):
    """Recover run status from durable remediation artifacts after an API restart."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", run_id):
        return None
    combined = REMEDIATION_RUNS_DIR / f"grouped_remediation_{run_id}.json"
    if not combined.is_file():
        return None
    try:
        aggregate = json.loads(combined.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return None
    raw_status = str(aggregate.get("status", ""))
    if raw_status in ("completed", "completed_with_errors"):
        status = "completed"
    elif raw_status.startswith("failed"):
        status = "failed"
    else:
        status = "running"
    summary = REMEDIATION_RUNS_DIR / run_id / "run_summary.json"
    progress_path = REMEDIATION_RUNS_DIR / run_id / "workflow_progress.json"
    try:
        workflow_progress = json.loads(progress_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        workflow_progress = None
    selected = aggregate.get("selection", {}).get("selected_cves")
    return {
        "run_id": run_id,
        "status": status,
        "pipeline_status": raw_status,
        "selected_count": selected,
        "workflow_progress": workflow_progress,
        "started_at": aggregate.get("started_at"),
        "completed_at": aggregate.get("completed_at"),
        "combined_output": str(combined.resolve()),
        "summary_output": str(summary.resolve()) if summary.exists() else None,
        "message": (aggregate.get("error") or
                    ("Pipeline completed with one or more assessment errors."
                     if raw_status == "completed_with_errors" else
                     "Pipeline completed; some CVEs reached the model budget."
                     if status == "completed" and any(
                            (entry.get("remediation_result") or {}).get("assessment_limited")
                            for entry in aggregate.get("results", [])) else
                     "Pipeline completed." if status == "completed" else
                     f"Pipeline is {raw_status.replace('_', ' ') or 'running'}.")),
    }


def pipeline_run(run_id):
    live = PIPELINE_RUNS.get(run_id)
    if live and live.get("status") in ("queued", "running"):
        return live
    saved = saved_pipeline_run(run_id)
    return {**live, **saved} if live and saved else saved or live


def saved_run_aggregate(run_id):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", run_id):
        return None
    combined = REMEDIATION_RUNS_DIR / f"grouped_remediation_{run_id}.json"
    if not combined.is_file():
        return None
    try:
        value = json.loads(combined.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def unique_lookup_sources(sources):
    """Show each internet lookup page once, preferring its validated entry."""
    unique = {}
    for source in sources:
        url = str(source.get("url") or "").strip()
        if not url:
            continue
        current = unique.get(url)
        if current is None or (bool(source.get("validated")), bool(source.get("fetched"))) > (
                bool(current.get("validated")), bool(current.get("fetched"))):
            unique[url] = source
    return list(unique.values())


def source_fix_groups(records):
    """Expose OS source fixes even when applicability is not yet established."""
    grouped = {"upstream": {}, "downstream": {}}
    for record in records:
        source = str(record.get("source") or "").strip()
        if source.casefold() in {"ibm", "rocky linux"}:
            role = "upstream"
        elif source and source.casefold() != "internet lookup":
            role = "downstream"
        else:
            continue
        version = str(record.get("fixed_version") or "").strip()
        patch = (str(record.get("advisory") or "").strip()
                 if record.get("evidence_kind") == "interim_fix" else "")
        if not version and not patch:
            continue
        identifier = version or patch
        key = (source, record.get("url"), record.get("product"),
               record.get("component"), identifier)
        entry = grouped[role].get(key)
        if entry is None:
            entry = {"source": source, "url": record.get("url"),
                     "product": record.get("product"), "component": record.get("component"),
                     "identifier": identifier, "identifier_kind": "Fixed version" if version else "Interim fix",
                     "releases": [], "evidence_ids": []}
            grouped[role][key] = entry
        release = str(record.get("release") or "").strip()
        if release and release not in entry["releases"]:
            entry["releases"].append(release)
        entry["evidence_ids"].append(record["evidence_id"])
    if not grouped["upstream"]:
        return None
    return {role: list(entries.values()) for role, entries in grouped.items()}


def _publisher(record):
    """The publisher a fix record speaks for: its source, or the site an Internet lookup read."""
    source = str(record.get("source") or "").strip()
    if source.casefold() == "internet lookup":
        host = re.sub(r"^www\.", "", (urlparse(str(record.get("url") or "")).hostname or "").casefold())
        if host == "ibm.com" or host.endswith(".ibm.com"):
            return "IBM"                                   # an IBM bulletin read by the lookup
        return host or "Internet lookup"
    return re.sub(r"\s+releases$", "", source)            # "OpenSSL releases" -> "OpenSSL"


def _upstream_boundary_options(records, product, installed_version):
    """Expose a CNA version boundary as a component option, not a package fix."""
    if str(product or "").casefold() != "libxml2":
        return []
    installed_match = re.match(r"\d+(?:\.\d+)+", str(installed_version or ""))
    if not installed_match:
        return []
    installed = tuple(map(int, installed_match.group().split(".")))
    options = []
    for record in records:
        if record.get("evidence_kind") != "cve_record" or "libxml2" not in str(record.get("product") or "").casefold():
            continue
        for match in re.finditer(r"(?:before|<)\s*(\d+(?:\.\d+)+)", str(record.get("affected_versions") or ""), re.I):
            version = match.group(1)
            if tuple(map(int, version.split("."))) <= installed or any(x["identifier"] == version for x in options):
                continue
            options.append({"identifier": version, "identifier_kind": "Upstream fixed boundary",
                            "source": record.get("source"), "product": product,
                            "component": None, "url": record.get("url"), "releases": [],
                            "packages": [], "evidence_ids": [record["evidence_id"]],
                            "target_scope": "Component release",
                            "caution": "Version boundary from the CVE record; no AIX Toolbox RPM or application support is established by this record."})
    return options


def fixes_by_source(records, product=None, installed_version=None):
    """Every fix the evidence reports, one group per publisher, IBM first.

    A CVE can have an IBM fix (an AIX fileset SP or interim fix) and a separate fix from
    another publisher (upstream release, distribution package, AIX Toolbox) at the same
    time; both are shown. Statuses, statements and mitigations carry no fix and are left out.
    """
    groups = {}
    for record in records:
        kind = record.get("evidence_kind")
        version = str(record.get("fixed_version") or "").strip()
        advisory = str(record.get("advisory") or "").strip()
        if kind == "package_candidate" and version:
            identifier, label = version, "Toolbox RPM candidate"
        elif kind == "interim_fix" and advisory:
            identifier, label = advisory, "Interim fix"
        elif kind == "fixed_package":
            identifier, label = advisory or version, "Package update"
        elif kind in ("latest_release", "latest_cumulative_candidate") and version:
            identifier, label = version, "Newest release on branch"
        elif version:
            identifier, label = version, "Fixed version"
        else:
            continue
        publisher = _publisher(record)
        group = groups.setdefault(publisher, {"source": publisher, "is_ibm": publisher.casefold() == "ibm",
                                              "fixes": {}})
        key = (identifier, label, record.get("product"))
        fix = group["fixes"].get(key)
        if fix is None:
            fix = group["fixes"][key] = {
                "identifier": identifier, "identifier_kind": label, "source": record.get("source"),
                "product": record.get("product"), "component": record.get("component"),
                "url": record.get("url"), "releases": [], "packages": [], "evidence_ids": [],
                "target_scope": ("AIX base fileset" if publisher.casefold() == "ibm"
                                 and kind in ("service_pack_or_fix_pack", "interim_fix")
                                 else "AIX Toolbox RPM" if kind == "package_candidate"
                                 else "Package" if kind == "fixed_package" else "Component release"),
                "caution": record.get("notes") if kind == "package_candidate" else None}
        release = str(record.get("release") or "").strip()
        if release and release not in fix["releases"]:
            fix["releases"].append(release)
        if kind == "fixed_package" and version and version != identifier:
            fix["packages"].extend(p for p in re.split(r";\s*", version) if p and p not in fix["packages"])
        fix["evidence_ids"].append(record["evidence_id"])
    boundaries = _upstream_boundary_options(records, product, installed_version)
    if boundaries:
        group = groups.setdefault("CVE record", {"source": "CVE record", "is_ibm": False, "fixes": {}})
        for option in boundaries:
            group["fixes"][(option["identifier"], "Upstream fixed boundary", product)] = option
    ordered = sorted(groups.values(), key=lambda group: not group["is_ibm"])
    return [{**group, "fixes": list(group["fixes"].values())} for group in ordered]


def fix_major(version):
    """Release branch of a version: '9.0.119' -> '9', '8u503' / '1.8.0_501' -> '8', else None."""
    text = str(version or "").strip()
    java = re.fullmatch(r"(\d+)u\d+(?:-b\d+)?", text) or re.match(r"1\.(\d+)\.\d+[_.]", text)
    if java:
        return java.group(1)
    plain = re.fullmatch(r"(\d+)(?:\.\d+)+[a-z]*", text)
    return plain.group(1) if plain else None


def primary_source_fix(records, product, component, installed_version, runtime, operating_systems,
                       package_lineage=None):
    """Pick one evidence-backed lead, without claiming it is installable."""
    target = str(product or component or "").casefold()
    host = " ".join([str(runtime or ""), *(operating_systems or [])]).casefold()
    version = str(installed_version or "")
    aix_level = None
    if "aix" in host:
        match = re.search(r"\b7\.[23](?:\.\d+)?", version + " " + host)
        aix_level = match.group(0) if match else None
    installed_branch = re.match(r"(\d+)\.(\d+)", version)
    installed_major = fix_major(version.split("-", 1)[0])   # "1.1.1k-17.el8_10" -> "1.1.1k"
    host_os_major = re.search(r"\b(?:rocky|red\s*hat|rhel|oracle\s+linux|ubuntu)\b\D{0,30}?(\d+)", host)

    def rank(record):
        name = str(record.get("product") or "").casefold()
        release = str(record.get("release") or "").casefold()
        source = str(record.get("source") or "").casefold()
        url = str(record.get("url") or "").casefold()
        score = 0
        if target and (target in name or name in target and len(name) > 3):
            score += 100
        if component and str(component).casefold() in name:
            score += 30
        if aix_level and "aix" in name and aix_level in release:
            score += 65
        elif aix_level and "aix" in name and aix_level[:3] in release:
            score += 25
        if "aix" in host and ("vios" in name or "vios" in release):
            score -= 100
        if source == "internet lookup" and target and target in name:
            score += 15
        if "aix" in host and (any(domain in url for domain in (
                "debian.org", "ubuntu.com", "redhat.com", "rockylinux.org"))
                or release in {"sid", "forky", "unstable"}):
            score -= 150
        if "aix" in host and any(domain in url for domain in (
                "openssh.org", "openssl-library.org", "openssl.org", "postgresql.org")):
            score += 45
        if record.get("fixed_version"):
            score += 5
        # Prefer a fix on the installed release branch (Tomcat 9.0.x for 9.0.100,
        # Java 17 for 17.0.2; "8u503" is Java branch 8).
        fix = str(record.get("fixed_version") or "")
        major = fix_major(fix)
        if installed_major and major:
            if major == installed_major:
                parts = fix.split(".")
                score += 20 + (20 if installed_branch and len(parts) > 1
                               and parts[1] == installed_branch.group(2) else 0)
            else:
                score -= 20
        # A distribution package for another OS major release does not fit this host.
        if host_os_major and source in {"rocky linux", "red hat", "oracle linux", "ubuntu"}:
            release_major = re.search(r"(?<![\d.])(\d{1,2})(?!\d)", release)
            if release_major and release_major.group(1) != host_os_major.group(1):
                score -= 120
        # The advisory's first fixed release outranks a later "newest release" row.
        if record.get("evidence_kind") != "latest_release":
            score += 2
        return score

    candidates = [record for record in records
                   if record.get("evidence_kind") != "package_candidate" and (record.get("fixed_version") or
                   (record.get("evidence_kind") == "interim_fix" and record.get("advisory")))]
    if "aix toolbox" in str(package_lineage or "").casefold():
        candidates = [record for record in candidates if not (
            str(record.get("source") or "").casefold() == "ibm"
            and str(record.get("product") or "").casefold() in {"ibm aix", "powervm vios"})]
    if not candidates:
        return None
    best = max(candidates, key=rank)
    if not installed_branch:
        # Without an installed version, equally ranked fixes on different release
        # branches (Tomcat 9.0 / 10.1 / 11.0) cannot be told apart; show none.
        top = rank(best)
        branches = {".".join(str(c.get("fixed_version")).split(".")[:2]) for c in candidates
                    if rank(c) == top
                    and re.fullmatch(r"\d+(?:\.\d+)+[a-z]*", str(c.get("fixed_version") or ""))}
        if len(branches) > 1:
            return None
    identifier = best.get("fixed_version") or best.get("advisory")
    return {
        "identifier": identifier,
        "identifier_kind": "Fixed version" if best.get("fixed_version") else "Interim fix",
        "source": best.get("source"), "url": best.get("url"),
        "product": best.get("product"), "component": best.get("component"),
        "release": best.get("release"), "evidence_id": best.get("evidence_id"),
        "compatibility": "unverified",
        # A fix for another release branch is only a lead for this installation.
        "match_scope": ("source_only" if installed_major and fix_major(str(identifier or ""))
                        and fix_major(str(identifier)) != installed_major
                        else "component" if target and target in str(best.get("product") or "").casefold()
                        else "host" if aix_level and aix_level[:3] in str(best.get("release") or "")
                        else "source_only"),
    }


_COMPATIBILITY_PROVIDER = None


def saved_run_compatibility(item):
    """Compatibility check for a run saved before the compatibility agent existed.

    Deterministic and offline (inventory + saved result only); returns None on any error
    so result pages never fail because of it."""
    global _COMPATIBILITY_PROVIDER
    result = item.get("remediation_result") or {}
    if not result.get("decision"):
        return None
    try:
        from compatibility import assess_compatibility, provider_from_env
        _COMPATIBILITY_PROVIDER = _COMPATIBILITY_PROVIDER or provider_from_env(REMEDIATION_INVENTORY)
        compatibility = assess_compatibility(result, item.get("context") or {},
                                             provider=_COMPATIBILITY_PROVIDER,
                                             evidence=item.get("mcp_evidence"))
        return {**compatibility, "computed_after_run": True}
    except Exception:  # noqa: BLE001 - optional enrichment of a saved result
        return None


def public_remediation_results(aggregate):
    results = []
    verdict_counts = {}
    for item in aggregate.get("results", []):
        item_error = item.get("error")
        persistence_error = item.get("persistence_error")
        # Backward compatibility for runs created before persistence failures were
        # stored separately from remediation-agent failures.
        persistence_marker = "CVE_CONTEXT persistence failed:"
        if item_error and persistence_marker in item_error:
            assessment_part, _, persistence_part = item_error.partition(persistence_marker)
            persistence_error = persistence_error or persistence_marker + persistence_part
            item_error = assessment_part.rstrip("; ") or None
        reasoning = item.get("reasoning") or {}
        if not reasoning:
            reasoning = (item.get("remediation_result") or {}).get("decision") or {}
        legacy_budget_limit = bool(re.search(
            r"Per-CVE (?:remediation|model) input-(?:byte|token) budget exhausted",
            str(item_error or ""), re.I))
        legacy_output_limit = bool(re.search(
            r"Incomplete or blocked model output: (?:max_tokens|length)|"
            r"Per-CVE remediation (?:output-token budget exhausted|model output was truncated twice)",
            str(item_error or ""), re.I))
        if legacy_budget_limit or legacy_output_limit:
            item_error = None
        verdict = ("ASSESSMENT_LIMITED" if legacy_budget_limit or legacy_output_limit else
                   reasoning.get("verdict") or ("FAILED" if item_error else "UNKNOWN"))
        verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
        from remediation.run_grouped_remediation import cited_evidence_ids
        cited_ids = cited_evidence_ids(reasoning)
        evidence_payload = item.get("mcp_evidence") or {}
        evidence_sources = {}
        evidence_records = []
        raw_records = evidence_payload.get("evidence", [])
        from remediation.remedition_agent import _assessment_records
        relevant_ids = {index for index, _record in _assessment_records(
            raw_records, item.get("context") or {})}
        for index, record in enumerate(raw_records, 1):
            evidence_id = f"EV-{index:03d}"
            if index not in relevant_ids and evidence_id not in cited_ids:
                continue
            evidence_sources[evidence_id] = {
                "source": record.get("source"),
                "url": record.get("url"),
                "product": record.get("product"),
                "release": record.get("release"),
            }
            evidence_records.append({
                "evidence_id": evidence_id,
                "cited": evidence_id in cited_ids,
                "source": record.get("source"),
                "url": record.get("url"),
                "product": record.get("product"),
                "component": record.get("component"),
                "release": record.get("release"),
                "affected_versions": record.get("affected_versions"),
                "fixed_version": record.get("fixed_version"),
                "advisory": record.get("advisory"),
                "remediation": record.get("remediation"),
                "vendor_stance": record.get("vendor_stance"),
                "verbatim_excerpt": record.get("verbatim_excerpt"),
                "notes": record.get("notes"),
                "evidence_kind": record.get("evidence_kind"),
            })
        lookup_sources = unique_lookup_sources(
            (evidence_payload.get("internet_lookup") or {}).get("sources", []))
        response = (item.get("context") or {}).get("response", {})
        request_context = (item.get("context") or {}).get("request", {})
        response_components = response.get("components") or []
        component_name = (
            item.get("component_name")
            or next(iter(request_context.get("component_names") or []), None)
            or next((component.get("name") for component in response_components
                     if component.get("name")), None)
        )
        component_context = next((
            component for component in response_components
            if str(component.get("name", "")).casefold() == str(component_name or "").casefold()
        ), response_components[0] if response_components else {})
        application = response.get("application") or {}
        application_names = application.get("names") or (
            [application["name"]] if application.get("name") else [])
        compatibility = item.get("compatibility") or saved_run_compatibility(item)
        results.append({
            "run_id": aggregate.get("run_id"),
            "cve": item.get("cve"),
            "product": item.get("product_group"),
            "component_id": item.get("component_id") or request_context.get("component_id"),
            "component": component_name,
            "components": request_context.get("component_names") or (
                [component_name] if component_name else []),
            "component_version": component_context.get("installed_version"),
            "component_path": (component_context.get("executable_path")
                               or component_context.get("component_path")),
            "package_lineage": component_context.get("package_lineage"),
            "runtime": component_context.get("runtime"),
            "verification_method": component_context.get("verification_method"),
            "applications": application_names,
            "application_version": application.get("version"),
            "application_install_path": application.get("install_path"),
            "operating_systems": (response.get("server") or {}).get("os_names", []),
            "test_context": bool(request_context.get("is_dummy") or response.get("is_dummy")),
            "context_missing": bool(item.get("context_missing")),
            "status": ("assessment_saved"
                       if not item_error and item.get("status") == "failed" and persistence_error
                       else item.get("status")),
            "error": item_error,
            "persistence_status": item.get("persistence_status") or (
                "failed" if persistence_error else
                "saved" if item.get("database_context_id") is not None else "not_attempted"),
            "persistence_error": persistence_error,
            "verdict": verdict,
            "applicability": reasoning.get("applicability"),
            "assessment_summary": (
                f"The automated assessment reached this CVE's configured model "
                f"{'output' if legacy_output_limit else 'input'} limit. "
                "Collected source evidence remains available, but no remediation was validated."
                if legacy_budget_limit or legacy_output_limit else reasoning.get("assessment_summary")),
            "assessment_limited": bool(legacy_budget_limit or legacy_output_limit or reasoning.get("assessment_limited") or
                                       (item.get("remediation_result") or {}).get("assessment_limited")),
            "assessment_limit_reason": (reasoning.get("assessment_limit_reason") or
                                        (item.get("remediation_result") or {}).get("assessment_limit_reason") or
                                        ("output_tokens" if legacy_output_limit else
                                         "input_tokens" if "input-token" in str(item.get("error") or "")
                                         else "input_bytes" if legacy_budget_limit else None)),
            "validation_failure": (reasoning.get("validation_failure") or
                                   (item.get("remediation_result") or {}).get("validation_failure")),
            "assessment_notes": reasoning.get("assessment_notes", []),
            "supporting_claims": reasoning.get("supporting_claims", []),
            "blocked_on": reasoning.get("blocked_on", []),
            "missing_information": reasoning.get("missing_information", []),
            "conflicts": reasoning.get("conflicts", []),
            "operational_notes": reasoning.get("operational_notes", []),
            "recommended_remediation": reasoning.get("recommended_remediation"),
            "candidate_remediations": reasoning.get("candidate_remediations", []),
            # One entry per installed copy with the fixes the decision gives for it.
            "installation_fixes": (item.get("remediation_result") or {}).get("installation_fixes") or [],
            "validation_note": reasoning.get("validation_note"),
            "assessed_at": reasoning.get("assessed_at"),
            "evidence_sources": evidence_sources,
            "evidence_records": evidence_records,
            "source_fix_groups": source_fix_groups(evidence_records),
            # Every source-reported fix, grouped by publisher (IBM and others side by side).
            "fixes_by_source": fixes_by_source(evidence_records, item.get("product_group"),
                                               component_context.get("installed_version")),
            "primary_source_fix": primary_source_fix(
                evidence_records, item.get("product_group"), component_name,
                component_context.get("installed_version"), component_context.get("runtime"),
                (response.get("server") or {}).get("os_names", []),
                component_context.get("package_lineage")),
            "evidence_route": item.get("evidence_route"),
            "evidence_status": evidence_payload.get("status"),
            "evidence_coverage": evidence_payload.get("coverage"),
            "evidence_searched_sources": evidence_payload.get("searched_sources", []),
            "evidence_notes": evidence_payload.get("notes", []),
            "evidence_errors": evidence_payload.get("source_errors", []),
            "lookup_sources": lookup_sources,
            "compatibility": compatibility,
            "reasoning": reasoning,
        })
    return {
        "run_id": aggregate.get("run_id"),
        "status": aggregate.get("status"),
        "started_at": aggregate.get("started_at"),
        "completed_at": aggregate.get("completed_at"),
        "total": len(results),
        "verdict_counts": verdict_counts,
        "uses_test_context": any(item.get("test_context") for item in results),
        "results": results,
    }


@app.post("/api/upload")
async def upload_csv(file: UploadFile | None = File(default=None)):
    upload = file
    if upload is None or not upload.filename:
        return error("Choose a CSV file to upload.")

    if Path(upload.filename).suffix.lower() != ".csv":
        return error("Only CSV files are accepted by this interface.")

    data = await upload.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        return error("The CSV is larger than the 25 MB upload limit.", 413)
    if not data:
        return error("The uploaded CSV is empty.")

    try:
        decoded = data.decode("utf-8-sig")
        original_count = sum(1 for _ in csv.DictReader(io.StringIO(decoded)))
    except UnicodeDecodeError:
        return error("The CSV must use UTF-8 encoding.")

    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as temporary:
            temporary.write(data)
            temp_path = Path(temporary.name)
        source_rows = read_source_file(temp_path)
        records, skipped_rows = build_records(source_rows)
        if not records:
            raise ValueError("No valid CVE IDs were found in the uploaded CSV.")
    except Exception as exc:
        return error(str(exc))
    finally:
        if temp_path:
            temp_path.unlink(missing_ok=True)

    # This is the single workflow identity used by upload, enrichment, grouping,
    # remediation artifacts, API status, and database persistence.
    run_id = generated_run_id()
    job_id = run_id
    columns = list(source_rows[0].keys())
    # Keep one original source row for each unique CVE record so the UI retains
    # every uploaded column while row selection stays aligned with records.
    deduplicated_rows = [record["observations"][0]["row"] for record in records]
    duplicate_count = sum(
        max(0, len(record["observations"]) - 1) for record in records
    )
    JOBS[job_id] = {
        "run_id": run_id,
        "filename": Path(upload.filename).name,
        "records": records,
        "skipped_rows": skipped_rows,
        "deduplicated_rows": deduplicated_rows,
        "deduplicated_columns": columns,
        "enriched_rows": [],
        "grouped_rows": [],
    }

    saved_enrichments = reusable_enrichment_files()
    return {
        "job_id": job_id,
        "run_id": run_id,
        "filename": JOBS[job_id]["filename"],
        "original_count": original_count,
        "unique_count": len(deduplicated_rows),
        "duplicate_count": duplicate_count,
        "skipped_count": len(skipped_rows),
        "columns": columns,
        "rows": deduplicated_rows,
        "existing_enrichment": (saved_enrichments or [None])[0],
        # Every reusable saved enrichment, newest first, so the UI can offer an older one.
        "enrichment_files": saved_enrichments,
    }


@app.post("/api/enrich")
def enrich_range(payload: dict | None = Body(default=None)):
    payload = payload or {}
    job = JOBS.get(str(payload.get("job_id", "")))
    if not job:
        return error("The upload session was not found. Upload the CSV again.", 404)

    try:
        start = int(payload.get("start", 1))
        count = int(payload.get("count", 0))
    except (TypeError, ValueError):
        return error("Start row and row count must be whole numbers.")

    total = len(job["records"])
    if start < 1 or start > total:
        return error(f"Start row must be between 1 and {total}.")
    if count < 1 or start + count - 1 > total:
        return error(f"Select between 1 and {total - start + 1} rows.")

    selected = job["records"][start - 1 : start - 1 + count]

    try:
        has_eligible_source = any(
            source
            for record in selected
            for source in record["sources"]
            if not source["shared_cve_ids"]
        )
        client = create_llm_client() if has_eligible_source else None
        classifications = classify_cves(client, selected, max_batches=None)
        enriched_rows = component_rows(selected, classifications)
    except Exception as exc:
        return error(f"Enrichment failed: {exc}", 500)

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    write_csv(DATA_DIR / f"{payload.get('job_id')}.csv", enriched_rows, COMPONENT_COLUMNS)
    result = grouped_payload(
        str(payload.get("job_id")), enriched_rows, "new_enrichment",
        f"{payload.get('job_id')}.csv")
    result.update({"start": start, "count": count})
    return result


@app.post("/api/enrich/reuse")
def reuse_enrichment(payload: dict | None = Body(default=None)):
    payload = payload or {}
    job_id = str(payload.get("job_id", ""))
    if job_id not in JOBS:
        return error("The upload session was not found. Upload the CSV again.", 404)

    filename = str(payload.get("filename", ""))
    available = {item["filename"]: item for item in reusable_enrichment_files()}
    if filename not in available or Path(filename).name != filename:
        return error("The selected saved enrichment file is no longer available.", 404)
    try:
        enriched_rows = read_enriched_csv(DATA_DIR / filename)
        result = grouped_payload(job_id, enriched_rows, "saved_enrichment", filename)
    except (OSError, ValueError, csv.Error) as exc:
        return error(f"Could not reuse saved enrichment: {exc}")
    return result


@app.post("/api/pipeline-runs")
def start_selected_pipeline(payload: dict | None = Body(default=None)):
    payload = payload or {}
    job_id = str(payload.get("job_id", ""))
    job = JOBS.get(job_id)
    if not job:
        return error("The upload session was not found. Upload the CSV again.", 404)
    grouped_rows = job.get("grouped_rows") or []
    raw_indices = payload.get("selected_indices")
    if not isinstance(raw_indices, list) or not raw_indices:
        return error("Select at least one grouped component to run.")
    if any(not isinstance(index, int) or isinstance(index, bool) for index in raw_indices):
        return error("Selected component indexes must be whole numbers.")
    indices = list(dict.fromkeys(raw_indices))
    if any(index < 0 or index >= len(grouped_rows) for index in indices):
        return error("One or more selected components are no longer available.")

    selected_rows = [grouped_rows[index] for index in indices]
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    first_run_id = job.get("run_id") or job_id
    active_run = next((run for run in PIPELINE_RUNS.values()
                       if (run.get("job_id") == job_id or run.get("run_id") == first_run_id)
                       and run.get("status") in ("queued", "running")), None)
    if active_run:
        return error(
            "A remediation run is already in progress for this upload.",
            409,
        )
    # Keep the upload ID for the first run; later selections need independent
    # artifact paths so the prior assessment remains reviewable.
    run_id = first_run_id if pipeline_run(first_run_id) is None else generated_run_id()
    while pipeline_run(run_id) is not None:
        run_id = generated_run_id()
    selected_path = DATA_DIR / f"selected_components_{run_id}.csv"
    write_csv(selected_path, selected_rows, COMPONENT_COLUMNS)
    PIPELINE_RUNS[run_id] = {
        "run_id": run_id,
        "job_id": job_id,
        "status": "queued",
        "selected_count": len(selected_rows),
        "selected_components": [
            {"product": row.get("Product", ""), "component": row.get("Component", "")}
            for row in selected_rows
        ],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "selected_input": str(selected_path.resolve()),
        "context_source": describe_inventory([path.resolve() for path in REMEDIATION_INVENTORY]),
    }
    Thread(target=execute_selected_pipeline, args=(run_id, selected_path), daemon=True).start()
    return JSONResponse(PIPELINE_RUNS[run_id], status_code=202)


@app.get("/api/pipeline-runs/{run_id}")
def selected_pipeline_status(run_id):
    run = pipeline_run(run_id)
    if not run:
        return error("Pipeline run was not found.", 404)
    return run


@app.get("/api/pipeline-runs/{run_id}/events")
def selected_pipeline_events(run_id):
    if pipeline_run(run_id) is None:
        return error("Pipeline run was not found.", 404)

    def events():
        previous = None
        while True:
            run = pipeline_run(run_id)
            if run is None:
                yield 'event: error\ndata: {"error":"Pipeline run was removed."}\n\n'
                return
            serialized = json.dumps(run, ensure_ascii=False)
            if serialized != previous:
                yield f"data: {serialized}\n\n"
                previous = serialized
            if run.get("status") in ("completed", "failed"):
                return
            time.sleep(1)

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/api/pipeline-runs/{run_id}/results")
def selected_pipeline_results(run_id):
    aggregate = saved_run_aggregate(run_id)
    if aggregate is None:
        return error("Remediation results were not found.", 404)
    if aggregate.get("status") not in ("completed", "completed_with_errors", "failed"):
        return error("The remediation run is still in progress.", 409)
    return public_remediation_results(aggregate)


def _small_compatibility_client():
    from remediation.remedition_agent import LLMClient, load_config

    config = load_config(REMEDIATION_RUNNER.parent / "agent_configs.json")
    config.update({"max_output_tokens": 600, "max_total_output_tokens": 1200,
                   "max_total_input_bytes": 9_000, "max_total_input_tokens": 4_000})
    client = LLMClient(config)
    client.model_id = os.getenv("AEGIS_COMPAT_RULE_MODEL_ID") or client.model_id
    return client


@app.post("/api/compatibility/rules/draft")
def draft_compatibility_rule(payload: dict | None = Body(default=None)):
    """One bounded model call; the proposal remains inactive until accepted in the UI."""
    payload = payload or {}
    try:
        from compatibility.rule_contributions import draft_rule

        proposal = draft_rule(
            cve=str(payload.get("cve") or ""), product=str(payload.get("product") or ""),
            application=str(payload.get("application") or ""),
            application_version=str(payload.get("application_version") or ""),
            target_version=str(payload.get("target_version") or ""),
            rule_text=str(payload.get("rule_text") or ""),
            source_url=str(payload.get("source_url") or ""),
            client=_small_compatibility_client)
    except Exception as exc:
        return error(f"Could not draft a grounded compatibility rule: {exc}")
    draft_id = uuid4().hex
    COMPATIBILITY_RULE_DRAFTS[draft_id] = proposal
    return {"draft_id": draft_id, "proposal": proposal}


@app.post("/api/compatibility/rules/{draft_id}/apply")
def apply_compatibility_rule(draft_id: str):
    proposal = COMPATIBILITY_RULE_DRAFTS.pop(draft_id, None)
    if proposal is None:
        return error("Rule draft was not found; draft it again.", 404)
    try:
        from compatibility.rule_contributions import save_rule

        saved = save_rule(proposal)
    except Exception as exc:
        COMPATIBILITY_RULE_DRAFTS[draft_id] = proposal
        return error(f"Could not save the compatibility rule: {exc}")
    return {"saved": saved, "proposal": proposal}


@app.post("/api/compatibility/recheck")
def recheck_compatibility(payload: dict | None = Body(default=None)):
    from compatibility import assess_or_request_rules, provider_from_env

    payload = payload or {}
    aggregate = saved_run_aggregate(str(payload.get("run_id") or ""))
    if not aggregate or aggregate.get("status") not in ("completed", "completed_with_errors"):
        return error("Completed run was not found.", 404)
    matching = [item for item in aggregate.get("results") or []
                if item.get("cve") == payload.get("cve")
                and (item.get("component_id") or
                     ((item.get("context") or {}).get("request") or {}).get("component_id"))
                == payload.get("component_id")]
    if len(matching) != 1 or not matching[0].get("remediation_result"):
        return error("Matching CVE assessment was not found.", 404)
    item = matching[0]
    try:
        result = assess_or_request_rules(item["remediation_result"], item.get("context") or {},
                                         provider=provider_from_env(REMEDIATION_INVENTORY),
                                         evidence=item.get("mcp_evidence"),
                                         model_client=_small_compatibility_client)
    except Exception as exc:
        return error(f"Compatibility recheck failed: {exc}")
    return {"compatibility": result}


@app.get("/api/jobs/{job_id}/remediation-results")
def session_remediation_results(job_id):
    """Reload every completed remediation run for the current upload session."""
    if job_id not in JOBS:
        return error("The upload session was not found. Upload the CSV again.", 404)
    runs = sorted((run for run in PIPELINE_RUNS.values()
                   if run.get("job_id") == job_id or run.get("run_id") == job_id),
                  key=lambda run: run.get("created_at") or "")
    results = []
    for run in runs:
        aggregate = saved_run_aggregate(run["run_id"])
        if aggregate and aggregate.get("status") in (
                "completed", "completed_with_errors", "failed"):
            results.append(public_remediation_results(aggregate))
    return {"runs": results}


def saved_fix_key(item):
    context = item.get("context") or {}
    component = (item.get("component_name")
                 or next(iter((context.get("request") or {}).get("component_names") or []), None)
                 or next((entry.get("name") for entry in
                          (context.get("response") or {}).get("components") or []
                          if entry.get("name")), ""))
    return (str(item.get("cve") or "").upper(),
            str(item.get("product_group") or "").strip().casefold(),
            str(component or "").strip().casefold())


def observed_inventory_covers(context):
    """True when the observed host inventory describes this context's application."""
    if not any(path.is_file() or any(path.glob("*.y*ml")) for path in REMEDIATION_INVENTORY):
        return False
    inventory_dir = str(Path(REMEDIATION_PACKAGE_ROOT) / "context_gathered")
    if inventory_dir not in sys.path:
        sys.path.insert(0, inventory_dir)
    import host_inventory
    try:
        hosts = host_inventory.load_hosts(REMEDIATION_INVENTORY)
    except (OSError, ValueError):
        return False
    names = ((context.get("response") or {}).get("application") or {}).get("names") or []
    observed = [host for host in hosts if not host.get("_synthetic")]
    host, _application = host_inventory.find_host({"applications": names}, observed)
    return host is not None


def saved_fix_is_reviewable(item):
    """Only expose prior fixes that still pass the current source checks."""
    result = item.get("remediation_result") or {}
    if not isinstance(result, dict):
        return False
    data = result.get("decision") or {}
    if not isinstance(data, dict):
        return False
    remedy = data.get("recommended_remediation")
    if (item.get("error") or data.get("verdict") != "FIX_AVAILABLE"
            or not isinstance(remedy, dict)):
        return False
    context = item.get("context") or {}
    # A result saved from an earlier synthetic/test context must not resurface once observed
    # inventory covers its application: it describes versions the real host may not have.
    request_context = context.get("request") or {}
    if (request_context.get("context_kind") != "OBSERVED_HOST_INVENTORY"
            and observed_inventory_covers(context)):
        return False
    # An inventory edited after the assessment may have changed the facts it used.
    inventory_file = request_context.get("inventory_file")
    if inventory_file:
        try:
            edited = datetime.fromtimestamp(Path(inventory_file).stat().st_mtime, timezone.utc)
            assessed = datetime.fromisoformat(str(result.get("assessed_at")).replace("Z", "+00:00"))
            if edited > assessed:
                return False
        except (OSError, ValueError, TypeError):
            return False
    target = str(remedy.get("target_version") or "")
    operating_systems = " ".join((context.get("response") or {}).get("server", {}).get("os_names") or [])
    # A Debian package version is not an installable Rocky/AIX remediation.
    if re.search(r"(?:~deb\d|\+deb\d)", target, re.I) and "debian" not in operating_systems.casefold():
        return False
    # Test inventory facts have been corrected over time. Do not display a
    # saved decision for a different installed runtime as if it were current.
    context_file = item.get("context_file")
    if (context.get("request") or {}).get("is_dummy") and context_file:
        fixture_path = Path(context_file).resolve()
        if fixture_path.is_relative_to(REMEDIATION_CONTEXT_DIR.resolve()) and fixture_path.is_file():
            try:
                current = json.loads(fixture_path.read_text(encoding="utf-8"))
                old_components = (context.get("response") or {}).get("components") or []
                new_components = (current.get("response") or {}).get("components") or []
                old_versions = {str(c.get("name") or "").casefold(): c.get("installed_version")
                                for c in old_components}
                new_versions = {str(c.get("name") or "").casefold(): c.get("installed_version")
                                for c in new_components}
                if any(name in new_versions and version != new_versions[name]
                       for name, version in old_versions.items()):
                    return False
            except (OSError, ValueError, TypeError, AttributeError):
                return False
    try:
        from remediation.remedition_agent import Decision, prepare, validate_decision
        decision = Decision.model_validate(data)
        package = prepare(item.get("context"), item.get("mcp_evidence"))
        validate_decision(decision, package)
    except (ValueError, TypeError, KeyError):
        return False
    return True


def row_fix_keys(row):
    """The saved-fix keys (CVE, product, component) a grouped component row stands for."""
    return {(cve.upper(), str(row.get("Product") or "").casefold(),
             str(row.get("Component") or "").casefold())
            for cve in re.findall(r"\bCVE-\d{4}-\d{4,}\b", str(row.get("CVE IDs") or ""), re.I)}


def selected_row_indices(indices, rows):
    """Validated, de-duplicated row indexes, or None when any index is invalid."""
    if (not isinstance(indices, list) or any(
            not isinstance(index, int) or isinstance(index, bool)
            or index < 0 or index >= len(rows) for index in indices)):
        return None
    return list(dict.fromkeys(indices))


# saved_fix_is_reviewable runs the citation validator, so its answer is cached per saved item.
# The key includes the aggregate's modification time and the inventory files' times, so an
# edited run or inventory is checked again; entries also expire after REVIEWABLE_CACHE_SECONDS.
REVIEWABLE_CACHE = {}
REVIEWABLE_CACHE_SECONDS = 300


def inventory_signature():
    signature = []
    for path in REMEDIATION_INVENTORY:
        files = [path] if path.is_file() else sorted(path.glob("*.y*ml")) if path.is_dir() else []
        for file in files:
            try:
                signature.append((str(file), file.stat().st_mtime_ns))
            except OSError:
                signature.append((str(file), None))
    return tuple(signature)


def cached_reviewable(path, position, item, signature):
    try:
        modified = path.stat().st_mtime_ns
    except OSError:
        modified = None
    key = (str(path), modified, position, signature)
    cached = REVIEWABLE_CACHE.get(key)
    now = time.monotonic()
    if cached and now - cached[1] < REVIEWABLE_CACHE_SECONDS:
        return cached[0]
    value = saved_fix_is_reviewable(item)
    if len(REVIEWABLE_CACHE) > 5000:
        REVIEWABLE_CACHE.clear()
    REVIEWABLE_CACHE[key] = (value, now)
    return value


def reviewable_saved_fix_runs(wanted=None, exclude_run_id=""):
    """Saved UI runs holding the newest reviewable FIX_AVAILABLE result per key, newest first.

    wanted: set of (CVE, product, component) keys to keep, or None for every saved fix.
    """
    found = []
    signature = inventory_signature()
    for path in REMEDIATION_RUNS_DIR.glob("grouped_remediation_ui-*.json"):
        aggregate = saved_run_aggregate(path.stem.removeprefix("grouped_remediation_"))
        if (not aggregate or aggregate.get("run_id") == exclude_run_id
                or aggregate.get("status") not in ("completed", "completed_with_errors")):
            continue
        matching = []
        for position, item in enumerate(aggregate.get("results", [])):
            if not isinstance(item, dict):
                continue
            key = saved_fix_key(item)
            if wanted is not None and key not in wanted:
                continue
            if cached_reviewable(path, position, item, signature):
                matching.append({**item, "reasoning": item["remediation_result"]["decision"]})
        if matching:
            found.append({**aggregate, "results": matching})
    found.sort(key=lambda run: run.get("started_at") or "", reverse=True)
    seen = set()
    unique_runs = []
    for run in found:
        unique = []
        for item in run["results"]:
            key = saved_fix_key(item)
            if key not in seen:
                seen.add(key)
                unique.append(item)
        if unique:
            unique_runs.append({**run, "results": unique})
    return unique_runs


@app.post("/api/jobs/{job_id}/previous-fixes")
def previous_saved_fixes(job_id, payload: dict | None = Body(default=None)):
    """Find the latest supported saved fix for each product/component/CVE."""
    job = JOBS.get(job_id)
    if not job:
        return error("The upload session was not found. Upload the CSV again.", 404)
    payload = payload or {}
    rows = job.get("grouped_rows") or []
    wanted = None
    if payload.get("scope") == "selected":
        indices = selected_row_indices(payload.get("selected_indices"), rows)
        if indices is None:
            return error("Selected component indexes are invalid.")
        wanted = {key for index in indices for key in row_fix_keys(rows[index])}
    exclude_run_id = str(payload.get("exclude_run_id") or "")
    unique_runs = reviewable_saved_fix_runs(wanted, exclude_run_id)
    return {"runs": [public_remediation_results(run) for run in unique_runs]}


@app.get("/api/jobs/{job_id}/fix-history")
def grouped_fix_history(job_id):
    """For each grouped component row, the saved runs that already found a reviewable fix.

    Only FIX_AVAILABLE results that still pass the previous-fix checks are listed, so the UI
    offers "view previous fix" exactly for the rows that POST previous-fixes would return.
    """
    job = JOBS.get(job_id)
    if not job:
        return error("The upload session was not found. Upload the CSV again.", 404)
    rows = job.get("grouped_rows") or []
    keys_by_row = {index: row_fix_keys(row) for index, row in enumerate(rows)}
    rows_by_key = {}
    for index, keys in keys_by_row.items():
        for key in keys:
            rows_by_key.setdefault(key, []).append(index)
    fixes_by_row = {}
    if rows_by_key:
        for run in reviewable_saved_fix_runs(set(rows_by_key)):
            for item in run["results"]:
                decision = item["remediation_result"].get("decision") or {}
                remedy = decision.get("recommended_remediation") or {}
                for index in rows_by_key.get(saved_fix_key(item), []):
                    fixes_by_row.setdefault(index, []).append({
                        "cve": str(item.get("cve") or "").upper(),
                        "run_id": run.get("run_id"),
                        "assessed_at": item["remediation_result"].get("assessed_at") or run.get("started_at"),
                        "target": remedy.get("target_version") or remedy.get("patch_id"),
                        "component_id": item.get("component_id"),
                    })
    components = []
    for index in sorted(fixes_by_row):
        row = rows[index]
        fixes = sorted(fixes_by_row[index], key=lambda fix: fix.get("assessed_at") or "", reverse=True)
        components.append({
            "index": index,
            "product": row.get("Product", ""),
            "component": row.get("Component", ""),
            "component_id": row.get("Component ID") or component_identifier(
                row.get("Product", ""), row.get("Component", "")),
            "fixes": fixes,
        })
    return {"components": components}


@app.get("/api/download/{job_id}/{kind}")
def download_csv(job_id, kind):
    job = JOBS.get(job_id)
    if not job:
        return error("The upload session was not found.", 404)

    if kind == "deduplicated":
        return csv_response(
            job["deduplicated_rows"],
            job["deduplicated_columns"],
            "deduplicated_cves.csv",
        )

    if kind == "enriched":
        if not job["enriched_rows"]:
            return error("Run enrichment before downloading this file.")
        return csv_response(
            job["enriched_rows"],
            COMPONENT_COLUMNS,
            "component_cve_map.csv",
        )

    if kind == "grouped":
        if not job.get("grouped_rows"):
            return error("Run or reuse enrichment before downloading this file.")
        return csv_response(
            job["grouped_rows"],
            COMPONENT_COLUMNS,
            "grouped_by_comp.csv",
        )

    return error("Unknown download type.", 404)


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/")
def frontend():
    index_path = UI_DIST / "index.html"
    if index_path.is_file():
        return FileResponse(index_path)
    return {
        "message": "React UI is not built yet. Run npm.cmd install and npm.cmd run build in aegis_engine_prod/ui."
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=int(os.getenv("PORT", "5000")))
