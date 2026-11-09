import csv
import io
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock, Thread
from urllib.parse import urlparse
from uuid import uuid4

from fastapi import Body, FastAPI, File, Form, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

from agent_utils import create_llm_client
from aegis_auth import service as auth_service
from aegis_auth.web import current_session_id, enabled as auth_enabled, install as install_auth
from cve_component_enrichment import (
    add_nvd_descriptions,
    apply_nvd_fallback,
    COMPONENT_COLUMNS,
    OPTIONAL_COMPONENT_COLUMNS,
    build_records,
    classify_cves,
    component_identifier,
    component_rows,
    read_source_file,
    write_csv,
)
from app_state import StateDict, mark_interrupted
from group_cves_by_component import group_by_product_and_component, write_grouped_csv


MAX_UPLOAD_BYTES = 25 * 1024 * 1024
# Uploads, runs and rule drafts live in the database (table CVE_APP_STATE), not in memory.
JOBS = StateDict("JOB")
PIPELINE_RUNS = StateDict("PIPELINE_RUN")
COMPATIBILITY_RULE_DRAFTS = StateDict("RULE_DRAFT")
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
# The evidence engine package (aegis_evidence): Oracle CPU dates and patch levels for display.
EVIDENCE_SRC = str(Path(REMEDIATION_PACKAGE_ROOT) / "src")
if EVIDENCE_SRC not in sys.path:
    sys.path.append(EVIDENCE_SRC)
import os_catalog  # noqa: E402  (aegis-cve-evidence/os_catalog.yaml: every OS-specific fact)

app = FastAPI(title="Aegis CVE Enrichment API")
if (UI_DIST / "assets").is_dir():
    app.mount("/assets", StaticFiles(directory=UI_DIST / "assets"), name="ui-assets")
# Sign-in, sessions and roles in front of every /api route (aegis_auth/web.py).
install_auth(app)


@app.on_event("startup")
def close_interrupted_runs():
    """Runs left queued or running by a previous server process can no longer finish."""
    try:
        mark_interrupted(PIPELINE_RUNS)
        if auth_enabled():
            auth_service.fail_interrupted_runs()          # the admin run list (aegis_runs) too
            auth_service.expire_stale_sessions()
    except Exception as exc:  # noqa: BLE001 - a database problem must not stop the server starting
        print(f"could not close interrupted runs: {type(exc).__name__}: {exc}", file=sys.stderr)


def record_run_event(action, *args, **kwargs):
    """Record a run in aegis_runs (who started it, status); never blocks the pipeline."""
    if not auth_enabled():
        return
    try:
        action(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001 - the run itself does not depend on this record
        print(f"aegis_runs record failed: {type(exc).__name__}: {exc}", file=sys.stderr)


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
        # Older enrichment files did not have Component ID (recreated from the group key)
        # or Hosts (left empty: those rows are matched to servers by application name).
        required_columns = [column for column in COMPONENT_COLUMNS
                            if column not in OPTIONAL_COMPONENT_COLUMNS]
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


# ---------------------------------------------------------------- who may see what
# Every upload (job) and remediation run records the user who started it (owner_id). An
# ADMIN sees everything, including uploads, runs and saved enrichments from before owners were
# recorded. Any other user sees only their own: a job, run or file without an owner is
# admin-only, and someone else's answers "not found" (its existence is not revealed).

def request_user(request) -> dict:
    """The signed-in user; with sign-in disabled (AEGIS_AUTH=off) the local administrator."""
    user = getattr(getattr(request, "state", None), "user", None)
    return user or {"user_id": "local", "user_role": "ADMIN"}


def is_admin(user) -> bool:
    return str((user or {}).get("user_role") or "").upper() == "ADMIN"


def job_owner(job_id):
    return (JOBS.get(str(job_id or "")) or {}).get("owner_id")


def run_owner(run_id):
    """The user who started a run: its own record, else its upload's (the first run shares the upload's ID)."""
    run = PIPELINE_RUNS.get(str(run_id or "")) or {}
    return run.get("owner_id") or job_owner(run.get("job_id") or run_id)


def may_access(request, owner_id) -> bool:
    user = request_user(request)
    return is_admin(user) or (bool(owner_id) and owner_id == user.get("user_id"))


def reusable_enrichment_files(request=None):
    """Return valid saved enrichment outputs, newest first (a non-admin: only their own)."""
    if not DATA_DIR.exists():
        return []
    user = request_user(request)
    candidates = []
    for path in DATA_DIR.glob("*.csv"):
        if path.name == "grouped_by_comp.csv" or path.name.startswith("selected_components_"):
            continue
        # A saved enrichment is named after its upload: the upload's owner may reuse it.
        if not is_admin(user) and job_owner(path.stem) != user.get("user_id"):
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
    record_run_event(auth_service.update_run, run_id, "running")
    try:
        remediation_root = str(REMEDIATION_RUNNER.parent.parent)
        if remediation_root not in sys.path:
            sys.path.insert(0, remediation_root)
        from remediation.run_grouped_remediation import RemediationOptions, run_grouped_remediation

        aggregate = run_grouped_remediation(RemediationOptions(
            input_csv=Path(selected_path),
            # One assessment per selected product (its newest CVE, on one server), not one
            # per component and server: 4 selected rows had made 324 runs.
            latest_per_product=True,
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
        record_run_event(auth_service.update_run, run_id, aggregate["status"], completed=True)
    except Exception as exc:
        run.update({
            "status": "failed",
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "message": f"{type(exc).__name__}: {exc}",
        })
        record_run_event(auth_service.update_run, run_id, "failed", completed=True)


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
    if not isinstance(value, dict):
        return None
    # CVEs re-assessed after their server's script output was pasted (this run only).
    reassessed = load_context_reassessments(run_id)
    if reassessed:
        value["results"] = [{**item, **reassessed.get(answer_item_key(item), {})}
                            for item in value.get("results") or []]
    return value


def context_reassessment_path(run_id):
    return REMEDIATION_RUNS_DIR / str(run_id) / "context_reassessments.json"


def load_context_reassessments(run_id):
    try:
        data = json.loads(context_reassessment_path(run_id).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


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


# Publishers of OS packages / filesets (os_catalog.yaml `distribution`): their fixes are the
# host OS source's own.
_OS_PUBLISHERS = {name.casefold() for name in os_catalog.publisher_names(distribution=True)}


_COMMIT_ID = re.compile(r"\b(?=[0-9a-f]*[a-f])[0-9a-f]{7,40}\b", re.I)


def standard_fixed_version(value):
    """A fixed version shown as a standard release / package version: "1.15 or later" -> "1.15";
    a commit ("commit 63dbf6b... or later") or a bare hash is no version to install -> None."""
    text = str(value or "").strip()
    if not text or re.search(r"\bcommits?\b", text, re.I) or _COMMIT_ID.search(text):
        return None
    return re.sub(r"\s*(?:\+|,?\s*(?:or|and)\s+(?:later|newer|higher|above))\s*$", "", text, flags=re.I) or None


def source_fix_groups(records):
    """Expose OS source fixes even when applicability is not yet established."""
    grouped = {"upstream": {}, "downstream": {}}
    for record in records:
        source = str(record.get("source") or "").strip()
        if source.casefold() in _OS_PUBLISHERS:
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
        version = re.sub(r"^v(?=\d)", "", str(record.get("fixed_version") or "").strip())
        advisory = str(record.get("advisory") or "").strip()
        if kind == "package_candidate" and version:
            identifier, label = version, "Toolbox RPM candidate"
        elif kind == "interim_fix" and advisory:
            identifier, label = advisory, "Interim fix"
        elif kind == "fixed_package":
            identifier, label = advisory or version, "Package update"
        elif kind in ("latest_release", "latest_cumulative_candidate", "latest_after_affected") and version:
            identifier, label = version, "Newest release on branch"
        elif version:
            identifier, label = version, "Fixed version"
        elif (kind in ("vendor_advisory", "also_addressed") and advisory
              and re.match(r"apply\b", str(record.get("remediation") or ""), re.I)):
            # "Apply the product-specific patch in this Oracle Critical Patch Update": the
            # vendor's patch release is the fix even though no product version is named.
            identifier = advisory
            label = "Vendor update page" if re.match(r"https?://", advisory) else "Vendor patch"
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
                "tier": record.get("tier"), "affected": record.get("affected_versions"),
                "evidence_kind": kind,
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
    # The host OS from os_catalog.yaml: its platform, family, lineage and numbered release.
    host_platform = os_catalog.platform(operating_systems or [], generic=False)
    host_family = os_catalog.family(operating_systems or [])
    host_lineage = os_catalog.lineage(operating_systems or [])
    level_family = host_family if host_family and os_catalog.families().get(host_family, {}).get("levels") else None
    os_level = None
    if level_family:
        # A level-numbered OS (AIX 7.2 / 7.2.5): fixes are per technology level.
        match = re.search(r"\b\d+\.\d+(?:\.\d+)?", " ".join(operating_systems or []) + " " + version)
        os_level = match.group(0) if match else None
    installed_branch = re.match(r"(\d+)\.(\d+)", version)
    installed_major = fix_major(version.split("-", 1)[0])   # "1.1.1k-17.el8_10" -> "1.1.1k"
    host_os_major = os_catalog.major(operating_systems or [])
    versioned = {name.casefold() for name in os_catalog.publisher_names(release_has_major=True)}

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
        record_platform = os_catalog.platform(f"{name} {release}", generic=False)
        if os_level and record_platform and record_platform.get("family") == level_family:
            if os_level in release:
                score += 65
            elif os_level[:3] in release:
                score += 25
        # Another OS of the same family (VIOS rows on an AIX host) does not fit this host.
        if (host_platform and record_platform and record_platform["id"] != host_platform["id"]
                and record_platform.get("family") == host_platform.get("family")
                and record_platform.get("lineage") == host_platform.get("lineage")
                and not os_catalog.rebuild_of(operating_systems or [])):
            score -= 100
        if source == "internet lookup" and target and target in name:
            score += 15
        # A page of another OS's publisher (Debian, Ubuntu, Red Hat for an AIX host), or a
        # Debian suite name, describes that OS's packages.
        page_lineage = os_catalog.lineage_of_url(url)
        if host_lineage and ((page_lineage and page_lineage != host_lineage)
                             or (host_lineage != "debian" and release in {"sid", "forky", "unstable"})):
            score -= 150
        # Hosts with no distribution packages of the product (AIX) take the upstream release.
        if level_family and any(domain in url for domain in (
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
        if host_os_major and source in versioned:
            release_major = re.search(r"(?<![\d.])(\d{1,2})(?!\d)", release)
            if release_major and release_major.group(1) != host_os_major:
                score -= 120
        # The advisory's first fixed release outranks a later "newest release" row.
        if record.get("evidence_kind") != "latest_release":
            score += 2
        return score

    candidates = [record for record in records
                   if record.get("evidence_kind") != "package_candidate" and (record.get("fixed_version") or
                   (record.get("evidence_kind") == "interim_fix" and record.get("advisory")))]
    if "aix toolbox" in str(package_lineage or "").casefold():
        # A separately packaged copy: the OS publisher's base fileset fix does not update it.
        host_publishers = {name.casefold() for name in os_catalog.publishers(operating_systems or [])}
        candidates = [record for record in candidates if not (
            str(record.get("source") or "").casefold() in host_publishers
            and os_catalog.family(str(record.get("product") or "")) == host_family)]
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
                        else "host" if os_level and os_level[:3] in str(best.get("release") or "")
                        else "source_only"),
    }


_JAVA_PRODUCT = re.compile(r"java|jdk|jre|openj9|semeru", re.I)
def _distro_families(*texts):
    """Linux distribution lineages a text names (os_catalog.yaml lineages with distribution:
    true): a distribution's fix (package, advisory or package version) applies only to a host
    of that lineage."""
    return os_catalog.lineages_in(*texts, distribution=True)


def _version_after(fix, installed, java=False):
    """True / False when fix is newer than installed; None when they cannot be compared."""
    from compatibility.versions import compare_upstream, java_version
    if java:
        a, b = java_version(fix), java_version(installed)
        if a and b:
            return a > b
    if not re.match(r"\d", str(fix or "")) or not re.search(r"\d", str(installed or "")):
        return None
    try:
        return compare_upstream(str(fix), str(installed).split("-", 1)[0]) > 0
    except Exception:  # noqa: BLE001
        return None


def _fix_branch(identifier, java=False):
    """Release branch of a fix: '9.0.119' -> '9.0', '8u461' -> 'Java 8', an advisory -> itself."""
    from compatibility.versions import branch
    text = str(identifier or "")
    if re.fullmatch(r"\d+u\d+(?:-b\d+)?", text) or re.match(r"1\.\d+\.0[_.]", text):
        return f"Java {fix_major(text)}"         # 8u461 and 1.8.0_501 are both Java 8
    if re.match(r"\d", text):
        return branch(text, 2) or text
    return text


def _ordered(fixes):
    from functools import cmp_to_key
    from compatibility.versions import compare_upstream

    def order(a, b):
        try:
            return compare_upstream(str(a.get("identifier")), str(b.get("identifier")))
        except Exception:  # noqa: BLE001
            return 0
    return sorted(fixes, key=cmp_to_key(order))


_REFERENCE_SOURCES = {"cve record": 2, "github advisory database": 3, "osv": 3, "nvd": 4}
# A beta, release candidate or milestone ("3.15.0b4", "11.0.0-rc.2", "12.1.0.beta3", "9.0.0.M1"):
# listed for its branch, never the headline fix while a stable branch has one.
_PRERELEASE = re.compile(r"(?i)alpha|beta|preview|snapshot|(?:^|[.\-_])rc(?:[.\-_]?\d|$)|\d(?:a|b|rc)\d+$|[.\-]m\d+$")


def _is_prerelease(identifier):
    text = str(identifier or "")
    return bool(re.match(r"\d", text) and _PRERELEASE.search(text))


def _source_rank(fix):
    """How authoritative a fix's source is: the publisher's own adapter, then a publisher page
    the lookup read (tier 1), the CNA's record, GitHub's reviewed advisories, NVD, other pages."""
    source = str(fix.get("source") or "").casefold()
    if source in _REFERENCE_SOURCES:
        return _REFERENCE_SOURCES[source]
    if source == "internet lookup":
        return 1 if fix.get("tier") == 1 else 5
    return 0


def _branch_options(pool, java):
    """One option per release branch: its first fix and the newest release on it."""
    branches = {}
    for fix in pool:
        key = (f"package:{fix.get('source')}" if fix.get("identifier_kind") == "Package update"
               else _fix_branch(fix.get("identifier"), java))
        entry = branches.setdefault(key, {"first": [], "latest": []})
        entry["latest" if fix.get("identifier_kind") == "Newest release on branch" else "first"].append(fix)
    # A newest release found on the major line (Log4j 2.26.1 for the 2.8.2 fix) belongs to the
    # branch of that first fix, not to a branch of its own with no fix in it.
    for key in [k for k, entry in branches.items() if not entry["first"] and not k.startswith("package:")]:
        major = fix_major(branches[key]["latest"][0].get("identifier")) if branches[key]["latest"] else None
        homes = {k: _ordered(entry["first"])[-1] for k, entry in branches.items() if k != key and entry["first"]
                 and not k.startswith("package:") and fix_major(entry["first"][0].get("identifier")) == major}
        newest_first = _ordered(list(homes.values()))[-1] if homes else None
        home = next((k for k, fix in homes.items() if fix is newest_first), None)
        if major and home:
            branches[home]["latest"].extend(branches.pop(key)["latest"])
    options = []
    for key, entry in branches.items():
        first, latest = _ordered(entry["first"]), _ordered(entry["latest"])
        # Sources can disagree on a branch's first fix (a third-party page says 1.17.9, the CVE
        # record 1.17.7; the CNA record 8.9.0, the vendor's advisory 8.9.1): the most
        # authoritative source decides (_source_rank), its earliest fix on the branch.
        if first:
            best = min(_source_rank(fix) for fix in first)
            chosen = next(fix for fix in first if _source_rank(fix) == best)
        else:
            chosen = latest[0]
        newest = latest[-1] if latest else None
        if newest is chosen or (newest is not None and _version_after(
                newest.get("identifier"), chosen.get("identifier"), java) is not True):
            newest = None                    # a "newest release" not later than the first fix
        options.append({
            "branch": None if key.startswith("package:") else key,
            "identifier": chosen.get("identifier"), "identifier_kind": chosen.get("identifier_kind"),
            "source": chosen.get("source"), "url": chosen.get("url"), "product": chosen.get("product"),
            "releases": chosen.get("releases") or [], "evidence_ids": chosen.get("evidence_ids") or [],
            "latest": newest.get("identifier") if newest else None,
            "latest_url": newest.get("url") if newest else None})
    # Newest release line first, pre-release lines (a beta-only 3.15 branch) after the stable ones.
    ordered = list(reversed(_ordered(options)))
    return ([o for o in ordered if not _is_prerelease(o.get("identifier"))]
            + [o for o in ordered if _is_prerelease(o.get("identifier"))])


_PRODUCT_NOISE = {"the", "and", "for", "inc", "corp", "corporation", "project", "software", "foundation", "of",
                  "in", "on", "to", "by", "v", "x", "os", "llc", "co", "ltd", "lts", "cd",
                  # vendor names: "Eclipse OMR" is not "Eclipse OpenJ9", "Google Chrome" not "Google Protobuf"
                  "eclipse", "apple", "adobe", "mozilla", "elastic", "f5", "intel", "dell", "vmware",
                  "red", "hat", "gnu", "gnome", "facebook", "meta", "cisco", "sap", "hp", "hpe", "siemens",
                  "ibm", "apache", "oracle", "microsoft", "google", "server", "edition", "community", "enterprise",
                  "version", "release", "products", "product", "https", "github", "com", "www", "org"}


def _product_words(text):
    return {w for w in re.findall(r"[a-z0-9]+", str(text or "").casefold()) if len(w) >= 2 and w not in _PRODUCT_NOISE}


# Words many products share: a match on these alone ("http" in "Ietf HTTP" and
# "akka-http-core") does not make two products the same.
_TECH_WORDS = {"http", "server", "client", "core", "api", "lib", "library", "common", "java", "framework",
               "sdk", "runtime", "plugin", "module", "engine", "web", "app", "application", "tool", "tools",
               "data", "database", "service", "services", "system", "manager", "open"}


def _clean_name(name):
    """A scanner product name without markup: 'Oracle Database Server<span ...>***...***</span>'."""
    return re.sub(r"\s*<[^>]*>.*$|\s*\*{3}.*$", "", str(name or ""), flags=re.S).strip()


# Oracle's JDK family: OpenJDK, Java SE, JDK/JRE and GraalVM for JDK share release numbers and
# Java SE's CPU fixes ("17.0.4", "8u341") are theirs.
_JDK_FAMILY = re.compile(r"\bopen\s*jdk\b|\bjava\s*se\b|\bjdk\b|\bjre\b|java\s+runtime\s+environment", re.I)


def _same_product(wanted, name):
    """'ibm vios' and 'PowerVM VIOS', 'haxx curl' and 'https://github.com/curl/curl': a shared product word.
    'Oracle Database Server' and 'Oracle Database Enterprise Edition': the same words once vendor
    and edition words are left out. 'Oracle OpenJDK' and 'Oracle Java SE': one JDK family."""
    if not name:
        return False
    if wanted in name or (name in wanted and len(name) > 3):
        return True
    if _JDK_FAMILY.search(wanted) and _JDK_FAMILY.search(name) and not re.search(r"openj9|semeru|ibm", f"{wanted} {name}"):
        return True
    if (_product_words(wanted) & _product_words(name)) - _TECH_WORDS:
        return True
    a, b = _product_words(_product_label(wanted)), _product_words(_product_label(name))
    return bool(a) and a == b


def _product_label(name):
    """'Microsoft .NET Framework 4.8 on Windows Server 2012 R2' -> 'Microsoft .NET Framework 4.8'."""
    text = re.sub(r"\s+(?:installed\s+)?on\s+(?:Windows|Mac|Linux|macOS|x64|ARM).*$", "", _clean_name(name), flags=re.I)
    return re.sub(r"\s*\([^)]*\)|\s*\[\d+\]", "", text).strip() or str(name or "")


def _name_words(name):
    """Product words without a trailing release digit ('log4j2' -> 'log4j'), for grouping names."""
    return {re.sub(r"(?<=[a-z])\d$", "", word) for word in _product_words(name)} - _TECH_WORDS


def _product_groups(fixes, java):
    """Fixes grouped by the product they are for, each with its branch options; the group
    with the most fixes first. Names are one product when the words of one are all in the
    other ('Apache Log4j2' and 'Apache Software Foundation Apache Log4j', 'Safari' and 'Apple
    Safari'), not when they merely share one ('BSAFE Crypto-C Micro Edition' and 'BSAFE Micro
    Edition Suite' are two products). A label with no product word joins the largest group."""
    groups, unnamed = [], []
    for fix in fixes:
        label = _product_label(fix.get("product"))
        words = _name_words(label)
        if not words:
            unnamed.append(fix)
            continue
        group = next((g for g in groups if words <= g["words"] or g["words"] <= words), None)
        if group is None:
            group = {"words": words, "product": label, "fixes": []}
            groups.append(group)
        group["words"] |= words
        group["fixes"].append(fix)
    if unnamed:
        if groups:
            max(groups, key=lambda g: len(g["fixes"]))["fixes"].extend(unnamed)
        else:
            groups.append({"words": set(), "product": _product_label(unnamed[0].get("product")), "fixes": unnamed})
    out = []
    for group in groups:
        if not any(f.get("identifier_kind") != "Newest release on branch" for f in group["fixes"]):
            continue                         # a newest release alone is not a fix
        # Every option is labelled with its group's product name, not the label of whichever
        # source row won the branch (a CNA record may call it just "product").
        out.append({"product": group["product"],
                    "options": [{**option, "product": group["product"]}
                                for option in _branch_options(group["fixes"], java)],
                    "count": len(group["fixes"])})
    out.sort(key=lambda g: -g["count"])
    return out


_BOUND_KINDS = {"cve_record", "last_affected_release", "vendor_affected", "nvd_last_affected"}
_DISTRIBUTION_STATUS = {
    "vendor_fix_deferred": "Fix deferred: no package update yet",
    "vendor_affected": "Affected: no package update yet",
    "vendor_no_fix_planned": "No fix planned for this release",
    "vendor_will_not_fix": "Will not be fixed for this release",
    "vendor_not_affected": "Not affected",
}


def _distribution_status(records, package, operating_systems):
    """The host distribution's own status for this package on this release (Red Hat's 'Fix
    deferred: openssl in Red Hat Enterprise Linux 8' for a Rocky 8 openssl RPM), or None."""
    host_text = " ".join(operating_systems or [])
    families = _distro_families(host_text)
    major = re.search(r"\b(\d{1,2})(?:\.\d+)?\b", host_text)
    if not families or not major or not package:
        return None
    for record in records or []:
        kind = record.get("evidence_kind")
        if kind not in _DISTRIBUTION_STATUS:
            continue
        if not _distro_families(record.get("source")) & families:
            continue
        if str(record.get("component") or "").casefold().strip() != package:
            continue                         # compat-openssl10, mingw-openssl are other packages
        release = re.search(r"\b(\d{1,2})\b", str(record.get("product") or record.get("release") or ""))
        if not release or release.group(1) != major.group(1):
            continue
        return record
    return None


def _supposed_fix(records, groups, wanted, product, java):
    """When no source states the release that fixes the CVE for this product: the newest release
    after the last affected release a source names ('GNU patch <= 2.8.0', NVD 'up to and
    including 1.2.12'), or 'later than <last affected>' when no newer release is known. For a
    protocol (HTTP/2), the fix of each implementation NVD lists. Labelled as supposed, never
    as a stated fix."""
    try:
        from aegis_evidence.latest import last_affected_bounds
    except Exception:  # noqa: BLE001
        return None
    bounds = {}
    for record in records or []:
        kind = record.get("evidence_kind")
        if kind not in _BOUND_KINDS:
            continue
        name = _clean_name(record.get("product")).casefold()
        source = str(record.get("source") or "").casefold()
        if wanted and name and not (_same_product(wanted, name) or source in ("cve record", "nvd", "osv")):
            continue
        for bound in last_affected_bounds(record.get("affected_versions"),
                                          listed=kind in ("cve_record", "nvd_last_affected")):
            key = _fix_branch(bound, java)
            prior = bounds.get(key)
            if prior is None or _version_after(bound, prior[0], java):
                bounds[key] = (bound, record)
    newest = [fix for group in groups or [] for fix in group.get("fixes") or []
              if fix.get("identifier_kind") == "Newest release on branch"]
    options, notes = [], []
    for key, (bound, record) in bounds.items():
        later = [fix for fix in newest if fix_major(fix.get("identifier")) == fix_major(bound)
                 and _version_after(fix.get("identifier"), bound, java) is True]
        pick = _ordered(later)[-1] if later else None
        options.append({"branch": key, "identifier": pick.get("identifier") if pick else f"later than {bound}",
                        "identifier_kind": "Supposed fix", "source": (pick or record).get("source"),
                        "url": (pick or record).get("url"), "product": _product_label(product) or record.get("product"),
                        "releases": [], "evidence_ids": [x for x in ((pick or {}).get("evidence_ids") or [])]
                        + ([record["evidence_id"]] if record.get("evidence_id") else []),
                        "latest": None, "last_affected": bound})
        notes.append(f"{bound} is the last affected {key} release ({record.get('source')})"
                     + (f"; {pick.get('identifier')} is the newest release after it and is expected to include the fix"
                        if pick else "; no later release is known yet, so the fix is the first release after it"))
    if options:
        options = [o for o in reversed(_ordered(options))]
        primary = next((o for o in options if not _is_prerelease(o.get("identifier"))
                        and not str(o.get("identifier")).startswith("later")), options[0])
        return {"origin": "supposed", **{k: v for k, v in primary.items() if k != "branch"},
                "branch": primary.get("branch"), "reliability": "supposed",
                "reliability_notes": ["No source states the release that fixes this CVE: this is the supposed fix "
                                      "from the affected versions; confirm it in the release notes"] + notes,
                "branches": options if len(options) > 1 else [], "products": [], "other_products": []}
    # A protocol or specification: each implementation's own fix.
    implementations = [fix for group in groups or [] for fix in group.get("fixes") or []
                       if fix.get("evidence_kind") == "implementation_fix"]
    if implementations:
        products = _product_groups(implementations, java)[:12]
        primary = products[0]["options"][0]
        return {"origin": "supposed", **{k: v for k, v in primary.items() if k != "branch"},
                "branch": primary.get("branch"), "reliability": "supposed",
                "reliability_notes": [f"{product} is a protocol or specification with no release of its own: "
                                      "apply the fix of the implementation you run (web server, proxy, library)"],
                "branches": [], "products": [{"product": g["product"], "options": g["options"]} for g in products],
                "other_products": []}
    return None


def available_fix(recommended, groups, product, installed_version, package_lineage=None,
                  operating_systems=None, assumed_version=False, records=None):
    """The fix to show for this copy, whatever the verdict, and how reliable the match is.

    The agent's recommended fix when it gave one. Otherwise every fix the sources report,
    one option per release branch (its first fixed version and the newest release on that
    branch), the installed branch first. `reliability`:
      matched           same product, this copy's branch, newer than the installed version
      assumed_version   as matched, but the installed version is assumed (not observed)
      installed_unknown same product; the installed version is unknown, so every branch is listed
      unreliable        no source fix fits this copy cleanly (another product name, another
                        distribution, an upstream release for an OS package...); shown with
                        the reasons so it can be judged, never hidden
    None only when the sources report no fix at all, or an observed installed version
    already includes the CVE's fix.
    """
    if recommended and (recommended.get("target_version") or recommended.get("patch_id")):
        return {"origin": "recommended",
                "identifier": recommended.get("target_version") or recommended.get("patch_id"),
                "identifier_kind": "Package update" if recommended.get("route") == "os_package_update"
                else "Fixed version", "installation": recommended.get("installation"),
                "evidence_ids": [claim.get("evidence_id") for claim in recommended.get("claims") or []
                                 if claim.get("evidence_id")],
                "latest": (recommended.get("latest_release") or {}).get("version"),
                "reliability": "assumed_version" if assumed_version else "recommended"}
    wanted = _clean_name(product).casefold().strip()
    if wanted in ("unidentified", "unspecified", "unspecified component", "unknown", "n/a"):
        wanted = ""                          # no product to compare with: the CVE's own sources speak for it
    java = bool(_JAVA_PRODUCT.search(wanted))
    installed = str(installed_version or "").strip()
    installed_base = installed.split("-", 1)[0]
    # An OS-package copy (Rocky RPM) is fixed by the distribution's package update, not by
    # an upstream release (its version string carries backports: 1.1.1k-17.el8_10).
    lineage = str(package_lineage or "")
    # "Manually installed JDK directory (not an RPM path)" is not an OS package.
    os_package = bool(re.search(r"\brpm\b|os[- ]managed|os package|package manager", lineage, re.I)
                      and not re.search(r"\bnot\s+(?:an?\s+)?rpm\b|not owned by any package|manually installed",
                                        lineage, re.I))
    token = re.split(r"[^a-z0-9]+", wanted)[0] if wanted else ""
    host_families = _distro_families(*(operating_systems or []))
    # The CNA names the product its own way ("Google LLC Protocolbuffers" for "Google
    # Protobuf-java"): when none of its names matches, its fixes are still this CVE's.
    # A distribution's own CNA record (Red Hat Hardened Images 2.15.3-0.1.hum1) is a build of
    # that distribution, not the product's release: it does not speak for the product.
    record_names = {str(fix.get("product") or "").casefold().strip()
                    for group in groups or [] for fix in group.get("fixes") or []
                    if str(fix.get("source") or "").casefold() in ("cve record", "osv")
                    and not _distro_families(fix.get("product"))}
    record_is_own = bool(record_names) and not any(_same_product(wanted, name) for name in record_names)
    strict, loose = [], []                   # loose: (fix, reason it may not fit)
    already_fixed = False                    # an observed installed copy already has a fix
    for group in groups or []:
        for fix in group.get("fixes") or []:
            name = str(fix.get("product") or "").casefold().strip()
            kind = fix.get("identifier_kind")
            identifier = str(fix.get("identifier") or "")
            if not identifier:
                continue
            core = _product_words(_product_label(wanted)) - _TECH_WORDS
            same_product = (not wanted or _same_product(wanted, name)
                            or (record_is_own and str(fix.get("source") or "").casefold() in ("cve record", "osv")
                                and not _distro_families(fix.get("product")))
                            # A CPU row filed under Java SE whose affected cell names JavaFX 2.1.
                            or bool(core and core <= _product_words(fix.get("affected"))))
            families = _distro_families(fix.get("source"), fix.get("url"), identifier, fix.get("product"),
                                        *(fix.get("releases") or []))
            reasons = []
            if families and not families & host_families:
                reasons.append(f"{fix.get('source')} package for another distribution"
                               + (f" (this host: {', '.join(operating_systems)})" if operating_systems else ""))
            elif kind == "Package update":
                packages = [str(package).casefold() for package in fix.get("packages") or []]
                if not os_package:
                    reasons.append("distribution package update; this copy is not recorded as an OS package")
                elif not (token and (any(package.startswith(token) for package in packages) or wanted in name)):
                    reasons.append("package update for another package")
            elif os_package:
                reasons.append("upstream release; this copy is an OS package, so the distribution's update applies")
            if not same_product and kind != "Package update":
                reasons.append(f"reported for {fix.get('product') or 'another product'}, not {product}")
            if installed and re.match(r"\d", identifier) and kind != "Package update":
                other_branch = (fix_major(identifier) and fix_major(installed_base)
                                and fix_major(identifier) != fix_major(installed_base))
                if other_branch:
                    if not assumed_version:
                        reasons.append(f"another release branch than the installed {installed}")
                elif _version_after(identifier, installed, java) is False and not assumed_version:
                    # An assumed version is a guess from the affected range: it cannot show
                    # that the copy already has the fix, so such fixes stay listed.
                    if not reasons:
                        already_fixed = already_fixed or kind != "Newest release on branch"
                    continue                 # the installed copy already has it
            if reasons:
                loose.append((fix, "; ".join(reasons), same_product))
            else:
                strict.append(fix)
    # A third-party page's version on a release line no other source has a fix on (the Xalan
    # 2.7.3 a tracker lists for a JDK CVE) is not this product's fix.
    anchors = {fix_major(fix.get("identifier")) for fix in strict
               if str(fix.get("source") or "").casefold() != "internet lookup"
               and fix.get("identifier_kind") != "Newest release on branch"} - {None}
    if anchors:
        strict = [fix for fix in strict if str(fix.get("source") or "").casefold() != "internet lookup"
                  or fix_major(fix.get("identifier")) in anchors or not fix_major(fix.get("identifier"))]
    # A newest release only says what is current, not that it fixes this CVE: without a first
    # fix from a source there is nothing to show.
    if not any(fix.get("identifier_kind") != "Newest release on branch" for fix in strict):
        strict = [] if not already_fixed else strict
    if not any(fix.get("identifier_kind") != "Newest release on branch" for fix, _, _ in loose):
        loose = []
    if already_fixed and not [fix for fix in strict if fix.get("identifier_kind") != "Newest release on branch"]:
        # Only a newer "newest release" remains while the installed copy already has the
        # CVE's fixed version (17.0.15 vs fix 17.0.10): that is an update, not this CVE's fix.
        return None
    # Fixes the sources list for other products this CVE affects (Firefox ESR next to Firefox,
    # macOS next to Safari): shown apart, never as this component's fix.
    others = _product_groups([fix for fix, _, own in loose if not own], java)
    # An OS-package copy (a Rocky 8 openssl RPM) is fixed only by its distribution's package
    # update. With none published, the distribution's own status for this package and release
    # is the answer ("Fix deferred"); the upstream release (1.1.1zj) cannot be installed over
    # an RPM-owned copy, so it is listed for reference only, never as the fix.
    if os_package and not any(fix.get("identifier_kind") == "Package update" for fix in strict):
        status = _distribution_status(records, token, operating_systems)
        if status is not None:
            upstream = _product_groups([fix for fix, _, own in loose if own], java)
            host = ", ".join(operating_systems or [])
            stance = str(status.get("vendor_stance") or status.get("remediation") or _DISTRIBUTION_STATUS[status["evidence_kind"]])
            where = f"{status.get('component')} in {status.get('product')}"
            notes = [f"{status.get('source')}: {stance}" + ("" if where.casefold() in stance.casefold() else f" ({where})") + "."]
            rebuilt = os_catalog.rebuild_of(operating_systems or [])
            if rebuilt and str(status.get("source")) in (rebuilt.get("publishers") or []):
                notes.append(f"This host runs {host}, a rebuild of {rebuilt['name']}: its package fix follows "
                             f"{status.get('source')}'s, so none is available until {status.get('source')} ships one.")
            if upstream:
                notes.append("The upstream release that fixes the CVE is listed below for reference only: installing it "
                             "would replace the OS-owned package (lost errata, FIPS and crypto-policy integration).")
            return {"origin": "distribution_status", "identifier": _DISTRIBUTION_STATUS[status["evidence_kind"]],
                    "identifier_kind": "Distribution package status", "source": status.get("source"),
                    "product": f"{status.get('product')}: {status.get('component')}", "url": status.get("url"),
                    "evidence_ids": [status["evidence_id"]] if status.get("evidence_id") else [],
                    "status": status["evidence_kind"], "reliability": "no_package_fix", "reliability_notes": notes,
                    "branches": [], "products": [],
                    "reference_fixes": [{"product": g["product"], "options": g["options"]} for g in upstream[:3]],
                    "other_products": [{"product": g["product"], "options": g["options"]} for g in others[:8]]}
    if strict:
        pool = strict
        reliability = ("assumed_version" if assumed_version else "matched" if installed else "installed_unknown")
        notes = []
    elif loose:
        # This product's fixes (another branch, another distribution's build, an upstream
        # release for an OS package) before another product's; each reason is shown.
        # Only fixes for this product: a fix another product's bulletin lists (IBM MQ on a
        # WebSphere CVE) is not a fix for this one, so nothing is shown instead.
        own = [entry for entry in loose if entry[2]]
        if not own:
            return _supposed_fix(records, groups, wanted, product, java)
        chosen = own
        pool = [fix for fix, _, _ in chosen]
        reliability = "unreliable"
        notes = list(dict.fromkeys(reason for _, reason, _ in chosen))
    else:
        return _supposed_fix(records, groups, wanted, product, java)
    # One set of branch options per product: a CVE that affects several products (BSAFE
    # Crypto-C 4.1.5 and Micro Edition Suite 4.5.2) gets a fix for each, not one mixed list.
    groups = _product_groups(pool, java)
    main = next((group for group in groups if wanted and _same_product(wanted, group["product"])), groups[0])
    options = main["options"] + [option for group in groups if group is not main for option in group["options"]]
    installed_branch = _fix_branch(installed_base, java) if installed else None
    primary = next((o for o in main["options"] if installed_branch and o.get("branch") == installed_branch),
                   next((o for o in main["options"] if not _is_prerelease(o.get("identifier"))), main["options"][0]))
    if not installed:
        notes = notes + ["installed version unknown: the fix is listed for every affected release branch"]
    elif assumed_version:
        notes = notes + [f"installed version {installed} is assumed from the CVE's affected versions, "
                         "not observed on the host"]
    return {"origin": "source", **{k: v for k, v in primary.items() if k != "branch"},
            "branch": primary.get("branch"), "reliability": reliability, "reliability_notes": notes,
            "branches": options if len(options) > 1 else [],
            "products": [{"product": group["product"], "options": group["options"]} for group in groups]
            if len(groups) > 1 else [],
            "other_products": [{"product": group["product"], "options": group["options"]} for group in others[:8]]}


_AVAILABLE_FIX_CHECKS = {}


def available_fix_compatibility(item, fix, product):
    """Offline compatibility check of a source-reported available fix (cached per item)."""
    key = (answer_item_key(item), fix.get("identifier"))
    if key not in _AVAILABLE_FIX_CHECKS:
        global _COMPATIBILITY_PROVIDER
        try:
            from compatibility import assess_compatibility, provider_from_env
            _COMPATIBILITY_PROVIDER = _COMPATIBILITY_PROVIDER or provider_from_env(REMEDIATION_INVENTORY)
            checked = assess_compatibility(
                item.get("remediation_result") or {"decision": item.get("reasoning") or {}},
                item.get("context") or {}, provider=_COMPATIBILITY_PROVIDER,
                evidence=item.get("mcp_evidence"),
                proposals=[{"product": fix.get("product") or product, "target_version": fix["identifier"],
                            "route": "component_upgrade"}])
            for evaluation in checked.get("evaluations") or []:
                if evaluation.get("role") == "proposal":
                    evaluation["role"] = "available"
            _AVAILABLE_FIX_CHECKS[key] = {
                **checked, "summary": str(checked.get("summary") or "").replace("Proposed fix", "Available fix"),
                "computed_after_run": True, "for_available_fix": True}
        except Exception:  # noqa: BLE001 - optional enrichment of a saved result
            _AVAILABLE_FIX_CHECKS[key] = None
    return _AVAILABLE_FIX_CHECKS[key]


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


def answer_item_key(item):
    component_id = (item.get("component_id")
                    or ((item.get("context") or {}).get("request") or {}).get("component_id"))
    return f"{str(item.get('cve') or '').upper()}|{component_id or ''}|{item.get('host') or ''}"


def answered_compatibility_path(run_id):
    return REMEDIATION_RUNS_DIR / str(run_id) / "compatibility_answers.json"


def load_answered_compatibility(run_id):
    """Compatibility results re-checked after the user answered questions (run_id/...json)."""
    if not run_id or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", str(run_id)):
        return {}
    try:
        data = json.loads(answered_compatibility_path(run_id).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def without_answered_questions(compatibility):
    """Drop questions answered since this compatibility result was computed."""
    if not isinstance(compatibility, dict) or not compatibility.get("questions"):
        return compatibility
    from compatibility.questions import load_answers

    answers = load_answers()
    return {**compatibility, "questions": [q for q in compatibility["questions"] if q.get("key") not in answers]}


def saved_run_questions(item):
    """Open questions for a result saved before compatibility asked questions (offline re-check;
    the saved status is kept). Empty on any error."""
    global _COMPATIBILITY_PROVIDER
    result = item.get("remediation_result") or {}
    if not result.get("decision"):
        return []
    try:
        from compatibility import assess_or_request_rules, provider_from_env
        _COMPATIBILITY_PROVIDER = _COMPATIBILITY_PROVIDER or provider_from_env(REMEDIATION_INVENTORY)
        return assess_or_request_rules(result, item.get("context") or {}, provider=_COMPATIBILITY_PROVIDER,
                                       evidence=item.get("mcp_evidence")).get("questions") or []
    except Exception:  # noqa: BLE001 - optional enrichment of a saved result
        return []


_CPU_MONTH = re.compile(r"\b(January|April|July|October|Jan|Apr|Jul|Oct)[a-z]*\.?\s+(\d{4})\b", re.I)


def with_patch_versions(remedy, records, installed_version=None, product=None):
    """A fix named after an Oracle Critical Patch Update, with the Oracle Database patch
    level(s) that CPU gives (12.2.0.1.171017 for October 2017). Only the installed branch when
    it is known; every affected dated branch otherwise. Other fixes are returned unchanged."""
    if not isinstance(remedy, dict) or remedy.get("target_version") or not remedy.get("patch_id"):
        return remedy
    named = _CPU_MONTH.search(str(remedy["patch_id"]))
    if not named or "patch update" not in str(remedy["patch_id"]).casefold():
        return remedy
    from aegis_evidence.sources.oracle_cpu import OracleCPU, database_patch_levels

    month = {"jan": 1, "apr": 4, "jul": 7, "oct": 10}[named.group(1)[:3].casefold()]
    levels = {}
    for record in records or []:
        released = OracleCPU.cpu_release_date(str(record.get("url") or ""))
        if not released or (released.month, released.year) != (month, int(named.group(2))):
            continue
        release = str(record.get("release") or "")
        if record.get("evidence_kind") == "cpu_release" and record.get("fixed_version") \
                and release.startswith("Oracle Database "):
            levels[release.removeprefix("Oracle Database ")] = record["fixed_version"]
        # Older runs name only the matrix component ("Java VM"); the card's product says Database.
        for branch, level in database_patch_levels(record.get("url"), f"{record.get('product') or ''} {product or ''}",
                                                   record.get("affected_versions")):
            levels.setdefault(branch, level)
    if not levels:
        return remedy
    installed = str(installed_version or "")
    chosen = {branch: level for branch, level in levels.items() if installed.startswith(branch)} or levels
    return {**remedy, "patch_versions": [{"branch": branch, "version": level} for branch, level in chosen.items()]}


_KNOWLEDGE_CACHE = {"at": -1e9, "data": {}}


def with_applied_rules(compatibility, cve):
    """Add the knowledge rules behind each evaluation (runs saved before `applied_rules` existed)."""
    if not isinstance(compatibility, dict) or not compatibility.get("evaluations"):
        return compatibility
    if all("applied_rules" in e for e in compatibility["evaluations"] if isinstance(e, dict)):
        return compatibility
    try:
        from compatibility.agent import applied_rules, load_knowledge
        from compatibility.versions import normalize_upstream
        if time.monotonic() - _KNOWLEDGE_CACHE["at"] > 60:
            _KNOWLEDGE_CACHE.update(at=time.monotonic(), data=load_knowledge())
        knowledge = _KNOWLEDGE_CACHE["data"]
    except Exception:  # noqa: BLE001 - rules are extra detail; the result stands without them
        return compatibility
    evaluations = []
    for evaluation in compatibility["evaluations"]:
        if isinstance(evaluation, dict) and "applied_rules" not in evaluation:
            key = evaluation.get("product_rules")
            target = evaluation.get("target")
            target = normalize_upstream(target) if target and evaluation.get("scheme") in ("upstream", "java") else None
            evaluation = {**evaluation, "applied_rules": applied_rules(key, knowledge.get(key) or {}, target, cve)}
        evaluations.append(evaluation)
    return {**compatibility, "evaluations": evaluations}


def public_remediation_results(aggregate):
    answered = load_answered_compatibility(aggregate.get("run_id"))
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
                "fixed_version": standard_fixed_version(record.get("fixed_version")),
                "advisory": record.get("advisory"),
                "remediation": record.get("remediation"),
                "vendor_stance": record.get("vendor_stance"),
                "verbatim_excerpt": record.get("verbatim_excerpt"),
                "notes": record.get("notes"),
                "evidence_kind": record.get("evidence_kind"),
                "tier": record.get("tier"),
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
        compatibility = (answered.get(answer_item_key(item)) or item.get("compatibility")
                         or saved_run_compatibility(item))
        if isinstance(compatibility, dict) and "questions" not in compatibility:
            compatibility = {**compatibility, "questions": saved_run_questions(item)}
        compatibility = without_answered_questions(compatibility)
        if (verdict == "NOT_APPLICABLE" and not reasoning.get("recommended_remediation")
                and isinstance(compatibility, dict) and compatibility.get("status") == "AWAITING_RULES"):
            # Saved before a not-affected copy stopped asking for rules (it may name another
            # product's fix): recheck offline.
            compatibility = saved_run_compatibility(item) or compatibility
        fixes_grouped = fixes_by_source(evidence_records, item.get("product_group"),
                                        component_context.get("installed_version"))
        fix_now = available_fix(reasoning.get("recommended_remediation"), fixes_grouped,
                                item.get("product_group"), component_context.get("installed_version"),
                                component_context.get("package_lineage"),
                                (response.get("server") or {}).get("os_names", []),
                                assumed_version=bool(component_context.get("assumed_installed_version")),
                                records=evidence_records)
        # A fix that exists but that the run did not check (no recommended fix: verdict
        # NOT_APPLICABLE / NEEDS_INPUT) is checked against the host now, offline.
        if fix_now and fix_now["origin"] == "source" and not item_error and (
                not isinstance(compatibility, dict) or compatibility.get("status") in ("NOT_EVALUATED", None)):
            compatibility = available_fix_compatibility(item, fix_now, item.get("product_group")) or compatibility
        compatibility = with_applied_rules(compatibility, item.get("cve"))
        results.append({
            "run_id": aggregate.get("run_id"),
            "cve": item.get("cve"),
            "product": item.get("product_group"),
            "component_id": item.get("component_id") or request_context.get("component_id"),
            # The server the scanner found this CVE on (one assessment per server), if named.
            "host": item.get("host"),
            "other_hosts": item.get("other_hosts") or [],
            "component": component_name,
            "components": request_context.get("component_names") or (
                [component_name] if component_name else []),
            "component_version": component_context.get("installed_version"),
            # True when no version was collected and the CVE's affected version is assumed.
            "component_version_assumed": bool(component_context.get("assumed_installed_version")),
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
            "context_source": item.get("context_source") or (response.get("context_source")),
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
            "recommended_remediation": with_patch_versions(reasoning.get("recommended_remediation"), raw_records,
                                                           component_context.get("installed_version"),
                                                           item.get("product_group")),
            "candidate_remediations": [with_patch_versions(remedy, raw_records,
                                                           component_context.get("installed_version"),
                                                           item.get("product_group"))
                                       for remedy in reasoning.get("candidate_remediations") or []],
            # One entry per installed copy with the fixes the decision gives for it.
            "installation_fixes": (item.get("remediation_result") or {}).get("installation_fixes") or [],
            "validation_note": reasoning.get("validation_note"),
            "assessed_at": reasoning.get("assessed_at"),
            "evidence_sources": evidence_sources,
            "evidence_records": evidence_records,
            "source_fix_groups": source_fix_groups(evidence_records),
            # Every source-reported fix, grouped by publisher (IBM and others side by side).
            "fixes_by_source": fixes_grouped,
            # The fix that exists for this copy, shown whatever the verdict or compatibility say.
            "available_fix": fix_now,
            # A distribution's "fix deferred" status is shown in the fix section but is not a fix.
            "fix_available": verdict == "FIX_AVAILABLE" or (fix_now is not None
                                                             and fix_now.get("origin") != "distribution_status"),
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
        # Results with a fix that exists for the installed copy (whatever their verdict).
        "fix_available_count": sum(1 for item in results if item.get("fix_available")),
        "uses_test_context": any(item.get("test_context") for item in results),
        "results": results,
    }


@app.post("/api/upload")
async def upload_csv(request: Request, file: UploadFile | None = File(default=None)):
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
        "owner_id": request_user(request).get("user_id"),
        "owner_email": request_user(request).get("email"),
    }

    saved_enrichments = reusable_enrichment_files(request)
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
def enrich_range(request: Request, payload: dict | None = Body(default=None)):
    payload = payload or {}
    job = JOBS.get(str(payload.get("job_id", "")))
    if not job or not may_access(request, job.get("owner_id")):
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
        # A CVE with no description of its own gets NVD's as source text; afterwards an
        # empty product/component is filled from what NVD states (nvd_fallback.py).
        add_nvd_descriptions(selected)
        has_eligible_source = any(
            source
            for record in selected
            for source in record["sources"]
            if not source["shared_cve_ids"]
        )
        client = create_llm_client() if has_eligible_source else None
        classifications = classify_cves(client, selected, max_batches=None)
        apply_nvd_fallback(selected, classifications)
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


def fill_hosts_from_upload(rows, records):
    """Give reused enrichment rows without servers the servers of the current upload.

    Older saved enrichment files have no Hostname / Hosts columns, so their CVEs could not be
    grouped by server. The uploaded scan names the server of each CVE (records[cve].contexts
    [].hosts); a row that already lists servers keeps them. Returns how many rows were filled.
    """
    by_cve = {}
    for record in (records.values() if isinstance(records, dict) else records or []):
        hosts = [host for context in record.get("contexts") or [] for host in context.get("hosts") or []]
        if hosts:
            by_cve[str(record.get("cve_id") or "").upper()] = list(dict.fromkeys(hosts))
    if not by_cve:
        return 0
    filled = 0
    for row in rows:
        if str(row.get("Hosts") or "").strip() or str(row.get("Hostname") or "").strip():
            continue
        cves = dict.fromkeys(c.upper() for c in re.findall(r"\bCVE-\d{4}-\d{4,}\b", str(row.get("CVE IDs") or ""), re.I))
        pairs = [(cve, host) for cve in cves for host in by_cve.get(cve, [])]
        if not pairs:
            continue
        row["Hostname"] = " | ".join(dict.fromkeys(host for _cve, host in pairs))
        row["Hosts"] = " | ".join(f"{cve}: {host}" for cve, host in pairs)
        filled += 1
    return filled


@app.post("/api/enrich/reuse")
def reuse_enrichment(request: Request, payload: dict | None = Body(default=None)):
    payload = payload or {}
    job_id = str(payload.get("job_id", ""))
    if job_id not in JOBS or not may_access(request, job_owner(job_id)):
        return error("The upload session was not found. Upload the CSV again.", 404)

    filename = str(payload.get("filename", ""))
    available = {item["filename"]: item for item in reusable_enrichment_files(request)}
    if filename not in available or Path(filename).name != filename:
        return error("The selected saved enrichment file is no longer available.", 404)
    try:
        enriched_rows = read_enriched_csv(DATA_DIR / filename)
        filled = fill_hosts_from_upload(enriched_rows, JOBS[job_id].get("records"))
        result = grouped_payload(job_id, enriched_rows, "saved_enrichment", filename)
        if filled:
            result["hosts_filled"] = filled
    except (OSError, ValueError, csv.Error) as exc:
        return error(f"Could not reuse saved enrichment: {exc}")
    return result


@app.post("/api/pipeline-runs")
def start_selected_pipeline(request: Request, payload: dict | None = Body(default=None)):
    payload = payload or {}
    job_id = str(payload.get("job_id", ""))
    job = JOBS.get(job_id)
    if not job or not may_access(request, job.get("owner_id")):
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
    active_run = next((run for run in PIPELINE_RUNS.values(status=("queued", "running"))
                       if run.get("job_id") == job_id or run.get("run_id") == first_run_id), None)
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
        "owner_id": job.get("owner_id") or request_user(request).get("user_id"),
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
    record_run_event(auth_service.record_run, run_id, current_session_id(request), job.get("filename"), "queued")
    Thread(target=execute_selected_pipeline, args=(run_id, selected_path), daemon=True).start()
    return JSONResponse(PIPELINE_RUNS[run_id], status_code=202)


@app.get("/api/pipeline-runs/{run_id}")
def selected_pipeline_status(run_id, request: Request):
    run = pipeline_run(run_id) if may_access(request, run_owner(run_id)) else None
    if not run:
        return error("Pipeline run was not found.", 404)
    return run


@app.get("/api/pipeline-runs/{run_id}/events")
def selected_pipeline_events(run_id, request: Request):
    if not may_access(request, run_owner(run_id)) or pipeline_run(run_id) is None:
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
def selected_pipeline_results(run_id, request: Request):
    aggregate = saved_run_aggregate(run_id) if may_access(request, run_owner(run_id)) else None
    if aggregate is None:
        return error("Remediation results were not found.", 404)
    if aggregate.get("status") not in ("completed", "completed_with_errors", "failed"):
        return error("The remediation run is still in progress.", 409)
    return public_remediation_results(aggregate)


def _small_compatibility_client():
    from remediation.remedition_agent import LLMClient, load_config

    config = load_config(REMEDIATION_RUNNER.parent / "agent_configs.json")
    # 900: a rule with its quote and several versions can exceed 600 output tokens.
    config.update({"max_output_tokens": 900, "max_total_output_tokens": 1800,
                   "max_total_input_bytes": 9_000, "max_total_input_tokens": 4_000})
    client = LLMClient(config)
    client.model_id = os.getenv("AEGIS_COMPAT_RULE_MODEL_ID") or client.model_id
    return client


@app.post("/api/compatibility/rules/draft")
def draft_compatibility_rule(payload: dict | None = Body(default=None)):
    """One bounded model call; the proposal remains inactive until accepted in the UI."""
    payload = payload or {}
    from compatibility.agent import model_drafting_enabled
    if not model_drafting_enabled():
        return error("Drafting rules from a source with a model is turned off (AEGIS_COMPAT_RULE_DRAFTER=off). "
                     "Enter the rule by hand instead.", 409)
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


@app.post("/api/compatibility/rules/manual")
def manual_compatibility_rule(payload: dict | None = Body(default=None)):
    """A rule typed in by the user (no model call): validated, kept as a draft for review, and
    saved to knowledge.yaml by /apply like a drafted one."""
    try:
        from compatibility.rule_contributions import manual_rule

        proposal = manual_rule(payload or {})
    except ValueError as exc:
        return error(str(exc))
    draft_id = uuid4().hex
    COMPATIBILITY_RULE_DRAFTS[draft_id] = proposal
    return {"draft_id": draft_id, "proposal": proposal}


@app.post("/api/compatibility/rules/bulk")
def bulk_compatibility_rules(payload: dict | None = Body(default=None)):
    """Several hand-entered rules at once (the Compatibility rules page; no model call).

    {"rules": [<manual_rule payload>, ...], "save": false} checks every rule and returns its
    proposal or error; with "save": true and no errors, every rule is saved to knowledge.yaml.
    Nothing is saved while any rule has an error.
    """
    from compatibility.rule_contributions import manual_rule, save_rule

    payload = payload or {}
    items = payload.get("rules")
    if not isinstance(items, list) or not items:
        return error("Add at least one rule.")
    if len(items) > 200:
        return error("At most 200 rules at a time.")
    checked = []
    for index, item in enumerate(items):
        try:
            checked.append({"index": index, "proposal": manual_rule(item if isinstance(item, dict) else {})})
        except ValueError as exc:
            checked.append({"index": index, "product": (item or {}).get("product") if isinstance(item, dict) else None,
                            "error": str(exc)})
    errors = sum("error" in entry for entry in checked)
    if not payload.get("save") or errors:
        return {"checked": checked, "errors": errors, "saved": 0}
    try:
        for entry in checked:
            entry["saved"] = save_rule(entry["proposal"])
    except Exception as exc:  # noqa: BLE001 - reported; earlier rules of the batch stay saved
        return error(f"Saving the rules stopped: {type(exc).__name__}: {exc}", 500)
    return {"checked": checked, "errors": 0, "saved": len(checked)}


@app.get("/api/jobs/{job_id}/compatibility-coverage")
def compatibility_coverage(job_id, request: Request):
    """Middleware -> OS -> products of the enriched file, each with its compatibility rule status."""
    job = JOBS.get(job_id)
    if not job or not may_access(request, job.get("owner_id")):
        return error("The upload session was not found. Upload the CSV again.", 404)
    from compatibility.rule_coverage import coverage

    try:
        return coverage(job.get("grouped_rows") or [])
    except (OSError, ValueError) as exc:
        return error(f"The compatibility knowledge could not be read: {exc}", 500)


@app.get("/api/compatibility/config")
def compatibility_config():
    """Which model steps compatibility may use (AEGIS_COMPAT_RULE_DRAFTER, AEGIS_COMPAT_JUDGE)."""
    from compatibility.agent import model_drafting_enabled, model_judge_enabled

    return {"model_drafting": model_drafting_enabled(), "model_judge": model_judge_enabled(),
            "rule_kinds": ["os_support", "requirement", "application_support", "behaviour_change"]}


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
def recheck_compatibility(request: Request, payload: dict | None = Body(default=None)):
    from compatibility import assess_or_request_rules

    payload = payload or {}
    run_id = str(payload.get("run_id") or "")
    aggregate = saved_run_aggregate(run_id) if may_access(request, run_owner(run_id)) else None
    if not aggregate or aggregate.get("status") not in ("completed", "completed_with_errors"):
        return error("Completed run was not found.", 404)
    matching = [item for item in aggregate.get("results") or []
                if item.get("cve") == payload.get("cve")
                and (item.get("component_id") or
                     ((item.get("context") or {}).get("request") or {}).get("component_id"))
                == payload.get("component_id")
                # One assessment per server: the server tells them apart (None for older runs).
                and (item.get("host") or None) == (payload.get("host") or None)]
    if len(matching) != 1 or not matching[0].get("remediation_result"):
        return error("Matching CVE assessment was not found.", 404)
    item = matching[0]
    try:
        # The card's server: the inventory host, or the run-only host from pasted script output.
        result = assess_or_request_rules(item["remediation_result"], item.get("context") or {},
                                         provider=compatibility_provider(run_id, item),
                                         evidence=item.get("mcp_evidence"),
                                         # use_model: false (a hand-entered rule): the rule checks alone.
                                         model_client=(_small_compatibility_client
                                                       if payload.get("use_model", True) else None))
    except Exception as exc:
        return error(f"Compatibility recheck failed: {exc}")
    result = {**result, "rechecked_after_rules": True}
    store_answered_compatibility(run_id, item, result)      # kept: the card shows it after a reload
    return {"compatibility": result}


ANSWER_LOCK = Lock()


def find_run_item(aggregate, cve, component_id, host):
    return [item for item in aggregate.get("results") or []
            if item.get("cve") == cve
            and (item.get("component_id") or
                 ((item.get("context") or {}).get("request") or {}).get("component_id")) == component_id
            and (item.get("host") or None) == (host or None)]


@app.get("/api/pipeline-runs/{run_id}/questions")
def run_questions(run_id, request: Request):
    """Open compatibility questions for a run, also while it is still running."""
    aggregate = saved_run_aggregate(run_id) if may_access(request, run_owner(run_id)) else None
    if aggregate is None:
        return {"items": [], "total": 0}
    answered = load_answered_compatibility(run_id)
    items = []
    for item in aggregate.get("results") or []:
        compatibility = without_answered_questions(answered.get(answer_item_key(item)) or item.get("compatibility"))
        open_questions = (compatibility or {}).get("questions") or []
        if not open_questions:
            continue
        items.append({"cve": item.get("cve"), "host": item.get("host"),
                      "component_id": item.get("component_id")
                      or ((item.get("context") or {}).get("request") or {}).get("component_id"),
                      "product": item.get("product_group"), "component": item.get("component_name"),
                      "compatibility_status": (compatibility or {}).get("status"), "questions": open_questions})
    return {"items": items, "total": sum(len(item["questions"]) for item in items),
            "run_status": aggregate.get("status")}


@app.post("/api/compatibility/answers")
def answer_compatibility_questions(request: Request, payload: dict | None = Body(default=None)):
    """Store the user's answers to one CVE's compatibility questions and re-check it.

    Answers are facts (a server's copy, an application's support list, a contract), saved
    once in compatibility/answers.json and reused by every later compatibility check.
    """
    from compatibility import assess_or_request_rules
    from compatibility.questions import load_answers, save_answers, validate_answer

    payload = payload or {}
    run_id = str(payload.get("run_id") or "")
    aggregate = saved_run_aggregate(run_id) if may_access(request, run_owner(run_id)) else None
    if aggregate is None:
        return error("Run was not found.", 404)
    matching = find_run_item(aggregate, payload.get("cve"), payload.get("component_id"), payload.get("host"))
    if len(matching) != 1 or not matching[0].get("remediation_result"):
        return error("Matching CVE assessment was not found.", 404)
    item = matching[0]
    submitted = payload.get("answers")
    if not isinstance(submitted, list) or not submitted or len(submitted) > 20:
        return error("Send between 1 and 20 answers.")
    provider = compatibility_provider(run_id, item)
    try:
        current = assess_or_request_rules(item["remediation_result"], item.get("context") or {},
                                          provider=provider, evidence=item.get("mcp_evidence"))
    except Exception as exc:  # noqa: BLE001
        return error(f"Compatibility check failed: {exc}")
    # Only questions this CVE actually asks (now or when it was saved) can be answered here.
    known = {q["key"]: q for q in [*((item.get("compatibility") or {}).get("questions") or []),
                                   *(current.get("questions") or [])]}
    updates = {}
    for answer in submitted:
        question = known.get(str((answer or {}).get("key") or ""))
        if question is None:
            return error("An answer does not belong to this CVE's questions.")
        try:
            value = validate_answer(question, answer.get("value"))
        except ValueError as exc:
            return error(str(exc))
        note = " ".join(str(answer.get("note") or "").split())[:300]
        updates[question["key"]] = {"value": value, "note": note, "question": question["question"],
                                    "aspect": question["aspect"], "cve": item.get("cve"), "run_id": run_id}
    answers = save_answers(updates)
    try:
        result = assess_or_request_rules(item["remediation_result"], item.get("context") or {},
                                         provider=provider, evidence=item.get("mcp_evidence"),
                                         model_client=_small_compatibility_client, answers=answers)
    except Exception as exc:  # noqa: BLE001 - the answers are saved either way
        return error(f"Answers saved; the compatibility re-check failed: {exc}", 500)
    result = {**result, "rechecked_after_answers": True}
    store_answered_compatibility(run_id, item, result)
    return {"compatibility": result, "answered": len(updates)}



class RunHostProvider:
    """The host a CVE with no server got from pasted script output: used for this run only."""

    def __init__(self, host, base):
        self.host, self.base, self.source = host, base, "run-session script output"

    def host_for(self, context):
        return self.host

    def host_by_name(self, hostname):
        return self.host

    def __getattr__(self, name):
        return getattr(self.base, name)


def run_session_context_path(run_id, item):
    key = hashlib.sha256(answer_item_key(item).encode()).hexdigest()[:16]
    return REMEDIATION_RUNS_DIR / str(run_id) / f"session_context_{key}.json"


def compatibility_provider(run_id, item):
    """The inventory provider, or the run-only host when this card's CVE had no server."""
    from compatibility import provider_from_env

    base = provider_from_env(REMEDIATION_INVENTORY)
    if item.get("host"):
        return base
    try:
        host = json.loads(run_session_context_path(run_id, item).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return base
    return RunHostProvider(host, base)

def context_with_host(context, host):
    """The CVE's context with the facts the pasted script output gives about its copy and server."""
    from compatibility.agent import _component_for_context

    context = json.loads(json.dumps(context or {}, default=str))
    response = context.setdefault("response", {})
    os_info = host.get("os") or {}
    server = response.setdefault("server", {})
    server["os_names"] = list(dict.fromkeys([*(server.get("os_names") or []),
                                             *[name for name in [os_info.get("name")] if name]]))
    if host.get("hostname") and not server.get("hostnames"):
        server["hostnames"] = [host["hostname"]]
    merged = _component_for_context(context, host)
    keep = ("installed_version", "version_evidence", "executable_path", "component_path", "package_lineage",
            "packages", "ownership", "ownership_evidence", "used_by_application", "runtime", "jars",
            "copy_status", "copy_status_basis", "verification_method", "inventory_component")
    for component, found in zip(response.get("components") or [], merged):
        if found.get("installed_version") and found.get("installed_version") != component.get("installed_version"):
            component.pop("assumed_installed_version", None)
        for key in keep:
            if found.get(key) not in (None, "", []):
                component[key] = found[key]
    response["context_source"] = "pasted script output"
    return context


def reassess_with_context(run_id, item, host, provider):
    """Re-run this CVE's remediation (saved evidence, one model call) and compatibility on the
    context from the pasted script output; kept for this run only."""
    from compatibility import assess_or_request_rules
    from remediation.remedition_agent import LLMClient, load_config, run_agent

    context = context_with_host(item.get("context"), host)
    config = load_config(REMEDIATION_RUNNER.parent / "agent_configs.json")
    remediation = run_agent(context, item.get("mcp_evidence") or {}, LLMClient(config), config)
    compatibility = assess_or_request_rules(remediation, context, provider=provider,
                                            evidence=item.get("mcp_evidence"),
                                            model_client=_small_compatibility_client)
    update = {"context": context, "remediation_result": remediation,
              "reasoning": remediation.get("decision") or {}, "context_missing": False,
              "compatibility": {**compatibility, "rechecked_after_context": True}}
    with ANSWER_LOCK:
        stored = load_context_reassessments(run_id)
        stored[answer_item_key(item)] = update
        path = context_reassessment_path(run_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        pending = path.with_name(path.name + ".tmp")
        pending.write_text(json.dumps(stored, ensure_ascii=False, default=str), encoding="utf-8")
        pending.replace(path)
        # The re-assessment replaces any compatibility re-checked before it.
        answered = load_answered_compatibility(run_id)
        if answered.pop(answer_item_key(item), None) is not None:
            answered_compatibility_path(run_id).write_text(json.dumps(answered, ensure_ascii=False),
                                                           encoding="utf-8")
    return {**item, **update}


def store_answered_compatibility(run_id, item, result):
    """Keep a re-checked compatibility result for one CVE card of a run."""
    with ANSWER_LOCK:
        stored = load_answered_compatibility(run_id)
        stored[answer_item_key(item)] = result
        path = answered_compatibility_path(run_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        pending = path.with_name(path.name + ".tmp")
        pending.write_text(json.dumps(stored, ensure_ascii=False), encoding="utf-8")
        pending.replace(path)


@app.post("/api/compatibility/context")
def compatibility_server_context(request: Request, payload: dict | None = Body(default=None)):
    """Take the output of the collection script for this CVE card's server and re-check the card.

    The card's server is the one the scanner named for the CVE, so the output is stored as that
    server's host context (the same store as /api/context-upload) and the compatibility check is
    rerun against it. Facts the output now answers (installed version, owner, Java runtime,
    dependencies) are no longer asked; the returned compatibility replaces the card's.
    """
    import self_service
    from compatibility import provider_from_env

    payload = payload or {}
    run_id = str(payload.get("run_id") or "")
    aggregate = saved_run_aggregate(run_id) if may_access(request, run_owner(run_id)) else None
    if aggregate is None:
        return error("Run was not found.", 404)
    matching = find_run_item(aggregate, payload.get("cve"), payload.get("component_id"), payload.get("host"))
    if len(matching) != 1 or not matching[0].get("remediation_result"):
        return error("Matching CVE assessment was not found.", 404)
    item = matching[0]
    server = item.get("host") or ""
    text = payload.get("text")
    if not isinstance(text, str) or not text.strip():
        return error("Paste the output of the collection script.")
    application = ((item.get("context") or {}).get("response") or {}).get("application") or {}
    applications = [name for name in application.get("names") or [] if name]
    try:
        if server:
            stored = self_service.save_upload(text, server, applications=applications)
            provider = provider_from_env(REMEDIATION_INVENTORY)
            host = (provider.host_for(item.get("context") or {})
                    or provider.host_by_name(stored.get("hostname") or server))
        else:
            # No server for this CVE: nothing is stored in the inventory or Oracle. The host
            # lives in this run's folder and is used only for this card.
            host, report = self_service.host_from_upload(text, "", applications)
            path = run_session_context_path(run_id, item)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(host, default=str), encoding="utf-8")
            stored = {"server": None, "hostname": host.get("hostname"), "run_only": True,
                      "os": (host.get("os") or {}).get("name") or (host.get("os") or {}).get("kind"),
                      "components": len(host.get("components") or []), "status": report["status"],
                      "warnings": ([] if report["status"] == "complete"
                                   else ["The script did not finish or some output was cut off; the context is partial."])}
            provider = compatibility_provider(run_id, item)
    except ValueError as exc:
        return error(str(exc))
    except Exception as exc:  # noqa: BLE001 - reported to the user, nothing half-saved matters
        return error(f"The output could not be converted: {type(exc).__name__}: {exc}", 500)
    if not host:
        return error("Context stored, but the server it describes could not be matched to this CVE.", 500)
    try:
        updated = reassess_with_context(run_id, item, host, provider)
    except Exception as exc:  # noqa: BLE001 - the context is kept either way
        return error(f"Context kept; re-assessing this CVE with it failed: {type(exc).__name__}: {exc}", 500)
    card = public_remediation_results({"run_id": run_id, "status": aggregate.get("status"),
                                       "results": [updated]})["results"][0]
    return {"compatibility": card.get("compatibility"), "result": card, "context": stored}


@app.get("/api/jobs/{job_id}/remediation-results")
def session_remediation_results(job_id, request: Request):
    """Reload every completed remediation run for the current upload session."""
    if not may_access(request, job_owner(job_id) or run_owner(job_id)):
        return error("The upload session was not found. Upload the CSV again.", 404)
    runs = sorted((run for run in PIPELINE_RUNS.values(job_id=job_id)),
                  key=lambda run: run.get("created_at") or "")
    if not runs and saved_run_aggregate(job_id):
        # The upload itself is gone (it predates the database) but its first run is saved on disk.
        runs = [{"run_id": job_id}]
    if job_id not in JOBS and not runs:
        return error("The upload session was not found. Upload the CSV again.", 404)
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
            str(component or "").strip().casefold(),
            # Server the assessment was for; "" for rows/runs without one.
            str(item.get("host") or "").strip().casefold())


# load_hosts parses every inventory YAML (and may query Oracle); the previous-fix check asks
# once per saved fix, so the hosts are kept while the inventory files are unchanged, for at
# most REVIEWABLE_CACHE_SECONDS (database hosts are not in the file signature).
_OBSERVED_HOSTS = {"key": None, "at": 0.0, "hosts": None}


def observed_hosts():
    """The inventory hosts, or None when they cannot be loaded."""
    inventory_dir = str(Path(REMEDIATION_PACKAGE_ROOT) / "context_gathered")
    if inventory_dir not in sys.path:
        sys.path.insert(0, inventory_dir)
    import host_inventory
    key, now = inventory_signature(), time.monotonic()
    cached = _OBSERVED_HOSTS
    if cached["key"] == key and now - cached["at"] < REVIEWABLE_CACHE_SECONDS:
        return cached["hosts"]
    try:
        hosts = host_inventory.load_hosts(REMEDIATION_INVENTORY)
    except (OSError, ValueError):
        hosts = None
    cached.update(key=key, at=now, hosts=hosts)
    return hosts


def observed_inventory_covers(context):
    """True when the observed host inventory describes this context's application."""
    if not any(path.is_file() or any(path.glob("*.y*ml")) for path in REMEDIATION_INVENTORY):
        return False
    inventory_dir = str(Path(REMEDIATION_PACKAGE_ROOT) / "context_gathered")
    if inventory_dir not in sys.path:
        sys.path.insert(0, inventory_dir)
    import host_inventory
    hosts = observed_hosts()
    if hosts is None:
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
    # A distribution's package version (Debian ~deb12u1, .el8) is not installable on another OS.
    target_lineages = _distro_families(target)
    host_lineage = os_catalog.lineage(operating_systems)
    if target_lineages and host_lineage and host_lineage not in target_lineages:
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
    """The saved-fix keys (CVE, product, component, server) a grouped component row stands for.

    Each server in the row's Hosts column is its own key (the runner names servers the same
    way). The server-less key is always included, so assessments saved before servers were
    recorded still match their component.
    """
    from remediation.run_grouped_remediation import servers_by_cve

    cves = [cve.upper() for cve in dict.fromkeys(
        re.findall(r"\bCVE-\d{4}-\d{4,}\b", str(row.get("CVE IDs") or ""), re.I))]
    servers = servers_by_cve(row.get("Hosts") or "", cves) if row.get("Hosts") else {}
    product = str(row.get("Product") or "").casefold()
    component = str(row.get("Component") or "").casefold()
    return {(cve, product, component, host.strip().casefold())
            for cve in cves for host in ["", *servers.get(cve, [])]}


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


def reviewable_saved_fix_runs(wanted=None, exclude_run_id="", request=None):
    """Saved UI runs holding the newest reviewable FIX_AVAILABLE result per key, newest first.

    wanted: set of (CVE, product, component) keys to keep, or None for every saved fix.
    request: a non-admin sees only fixes from their own runs.
    """
    found = []
    signature = inventory_signature()
    for path in REMEDIATION_RUNS_DIR.glob("grouped_remediation_ui-*.json"):
        if request is not None and not may_access(request, run_owner(path.stem.removeprefix("grouped_remediation_"))):
            continue
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
def previous_saved_fixes(job_id, request: Request, payload: dict | None = Body(default=None)):
    """Find the latest supported saved fix for each product/component/CVE."""
    job = JOBS.get(job_id)
    if not job or not may_access(request, job.get("owner_id")):
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
    unique_runs = reviewable_saved_fix_runs(wanted, exclude_run_id, request)
    return {"runs": [public_remediation_results(run) for run in unique_runs]}


@app.get("/api/jobs/{job_id}/fix-history")
def grouped_fix_history(job_id, request: Request):
    """For each grouped component row, the saved runs that already found a reviewable fix.

    Only FIX_AVAILABLE results that still pass the previous-fix checks are listed, so the UI
    offers "view previous fix" exactly for the rows that POST previous-fixes would return.
    """
    job = JOBS.get(job_id)
    if not job or not may_access(request, job.get("owner_id")):
        return error("The upload session was not found. Upload the CSV again.", 404)
    rows = job.get("grouped_rows") or []
    keys_by_row = {index: row_fix_keys(row) for index, row in enumerate(rows)}
    rows_by_key = {}
    for index, keys in keys_by_row.items():
        for key in keys:
            rows_by_key.setdefault(key, []).append(index)
    fixes_by_row = {}
    if rows_by_key:
        for run in reviewable_saved_fix_runs(set(rows_by_key), request=request):
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
                        "host": item.get("host"),
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
def download_csv(job_id, kind, request: Request):
    job = JOBS.get(job_id)
    if not job or not may_access(request, job.get("owner_id")):
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


# ---------------------------------------------------------------- delivery agent
# One upgrade per product per server, from the results of the runs the UI shows; written as a
# diff folder (before/after versions, changes.diff, manifest) that can be committed to git.

def delivery_results(request, payload):
    """The result cards of the requested runs (only runs this user may see), optionally narrowed
    to the listed items: [{run_id, cve, component_id, host}]."""
    run_ids = [str(run_id) for run_id in (payload.get("run_ids") or []) if str(run_id or "").strip()]
    if not run_ids or len(run_ids) > 50:
        raise ValueError("Choose between 1 and 50 remediation runs.")
    items = payload.get("items")
    wanted = None
    if isinstance(items, list) and items:
        wanted = {(str(i.get("run_id") or ""), str(i.get("cve") or "").upper(), str(i.get("component_id") or ""),
                   str(i.get("host") or "").casefold()) for i in items if isinstance(i, dict)}
    results = []
    for run_id in dict.fromkeys(run_ids):
        if not may_access(request, run_owner(run_id)):
            continue
        aggregate = saved_run_aggregate(run_id)
        if not aggregate:
            continue
        for result in public_remediation_results(aggregate)["results"]:
            key = (str(result.get("run_id") or ""), str(result.get("cve") or "").upper(),
                   str(result.get("component_id") or ""), str(result.get("host") or "").casefold())
            if wanted is None or key in wanted:
                results.append(result)
    return results


def delivery_artifact_folder(request, artifact_id):
    from delivery import agent as delivery_agent

    folder = delivery_agent.find_artifact(artifact_id)
    if folder is None:
        return None, None
    manifest = delivery_agent.read_manifest(folder)
    if not may_access(request, manifest.get("created_by")):
        return None, None
    return folder, manifest


@app.get("/api/delivery/config")
def delivery_config():
    from delivery import agent as delivery_agent

    config = delivery_agent.git_config()
    return {"git_configured": config["configured"], "push_enabled": config["configured"] and config["push"],
            "remote": config["remote"], "path": config["path"],
            "repo_name": Path(config["repo"]).name if config["repo"] else None}


@app.post("/api/delivery/plan")
def delivery_plan(request: Request, payload: dict | None = Body(default=None)):
    """Every server's grouped upgrades for the given runs (nothing is written)."""
    from delivery import agent as delivery_agent

    payload = payload or {}
    try:
        results = delivery_results(request, payload)
        plan = delivery_agent.build_plan(results, str(payload.get("strategy") or "minimum"))
    except ValueError as exc:
        return error(str(exc))
    return {**plan, "result_count": len(results)}


@app.get("/api/jobs/{job_id}/middleware")
def job_middleware(job_id, request: Request):
    """The uploaded file as middleware -> product (with its components) -> CVEs, each CVE with
    its servers and the fix from this upload's runs or, failing that, an earlier saved run.
    Nothing is written and no agent is called."""
    from delivery import agent as delivery_agent

    job = JOBS.get(job_id)
    if not job or not may_access(request, job.get("owner_id")):
        return error("The upload session was not found. Upload the CSV again.", 404)
    rows = job.get("grouped_rows") or []
    if not rows:
        return error("Enrich and group the file first: the middleware view is built from its grouped components.")
    results = []
    for run in sorted(PIPELINE_RUNS.values(job_id=job_id), key=lambda run: run.get("created_at") or ""):
        aggregate = saved_run_aggregate(run["run_id"])
        if aggregate:
            results += [{**result, "_origin": "session"} for result in public_remediation_results(aggregate)["results"]]
    wanted = {key for row in rows for key in row_fix_keys(row)}
    for run in reviewable_saved_fix_runs(wanted, request=request):
        results += [{**result, "_origin": "saved"} for result in public_remediation_results(run)["results"]]
    return {**delivery_agent.middleware_tree(rows, results), "rows": len(rows),
            "source_filename": job.get("source_filename") or job.get("filename")}


@app.post("/api/delivery/artifacts")
def delivery_create_artifact(request: Request, payload: dict | None = Body(default=None)):
    """Write one server's delivery as a diff folder."""
    from delivery import agent as delivery_agent

    payload = payload or {}
    server = str(payload.get("server") or "").strip()
    if not server:
        return error("Choose the server to deliver.")
    strategy = str(payload.get("strategy") or "minimum")
    try:
        plan = delivery_agent.build_plan(delivery_results(request, payload), strategy, server=server)
    except ValueError as exc:
        return error(str(exc))
    if not plan["servers"] or not plan["servers"][0]["products"]:
        return error(f"There is nothing to deliver for {server}: none of its CVEs has a fix in these runs.")
    manifest = delivery_agent.write_artifact(plan["servers"][0], strategy, request_user(request).get("user_id"))
    return {key: manifest[key] for key in ("artifact_id", "server", "strategy", "created_at", "summary", "files", "diff")}


@app.get("/api/delivery/artifacts")
def delivery_list_artifacts(request: Request):
    from delivery import agent as delivery_agent

    return {"artifacts": [entry for entry in delivery_agent.list_artifacts()
                          if may_access(request, entry.get("created_by"))]}


@app.get("/api/delivery/artifacts/{artifact_id}/download")
def delivery_download_artifact(artifact_id, request: Request):
    """The diff folder as a .zip (the same files that are committed to git)."""
    import zipfile

    folder, manifest = delivery_artifact_folder(request, artifact_id)
    if folder is None:
        return error("The delivery artifact was not found.", 404)
    stream = io.BytesIO()
    prefix = f"{folder.parent.name}/{folder.name}"
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(folder.rglob("*")):
            if path.is_file():
                archive.write(path, f"{prefix}/{path.relative_to(folder).as_posix()}")
    return Response(content=stream.getvalue(), media_type="application/zip", headers={
        "Content-Disposition": f'attachment; filename="aegis-delivery-{folder.parent.name}-{artifact_id}.zip"'})


@app.post("/api/delivery/artifacts/{artifact_id}/push")
def delivery_push_artifact(artifact_id, request: Request):
    """Commit the folder on its own branch of the delivery repository; push when enabled."""
    from delivery import agent as delivery_agent

    folder, manifest = delivery_artifact_folder(request, artifact_id)
    if folder is None:
        return error("The delivery artifact was not found.", 404)
    if manifest.get("git"):
        return {"git": manifest["git"], "already": True}
    try:
        return {"git": delivery_agent.commit_artifact(folder)}
    except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
        return error(str(exc), 409 if "not set up" in str(exc) else 500)


def job_servers(rows):
    """Servers named in the grouped rows' Hosts column, merged when they are the same server."""
    from host_inventory import same_server
    from remediation.run_grouped_remediation import servers_by_cve

    servers = []
    for index, row in enumerate(rows):
        if not row.get("Hosts"):
            continue
        cves = [cve.upper() for cve in dict.fromkeys(
            re.findall(r"\bCVE-\d{4}-\d{4,}\b", str(row.get("CVE IDs") or ""), re.I))]
        applications = [name.strip() for name in str(row.get("Application") or "").split(" | ") if name.strip()]
        product = str(row.get("Product") or "").strip() or "Unknown product"
        component = str(row.get("Component") or "").strip()
        if component.casefold() == "unspecified component":
            component = ""
        for cve, names in servers_by_cve(row["Hosts"], cves).items():
            for name in names:
                entry = next((s for s in servers if same_server(s["server"], name)), None)
                if entry is None:
                    entry = {"server": name, "applications": [], "cves": [], "rows": [], "products": {}}
                    servers.append(entry)
                elif len(name) > len(entry["server"]):
                    entry["server"] = name
                entry["applications"] = list(dict.fromkeys(entry["applications"] + applications))
                entry["cves"] = list(dict.fromkeys(entry["cves"] + [cve]))
                entry["rows"] = list(dict.fromkeys(entry["rows"] + [index]))
                # Every enriched CVE on this server, grouped by product (component names listed).
                item = entry["products"].setdefault(product.casefold(), {"product": product, "names": [], "cves": []})
                if component and component not in item["names"]:
                    item["names"].append(component)
                if cve not in item["cves"]:
                    item["cves"].append(cve)
                # The scanner's operating systems for this row (every server of the row runs one).
                entry.setdefault("_os_sets", []).append(
                    {name.strip() for name in str(row.get("Operating System") or "").split(" | ") if name.strip()})
    for entry in servers:
        entry["products"] = list(entry["products"].values())
        # The server's OS per the scanner: the one OS every row naming it shares.
        sets = [names for names in entry.pop("_os_sets", []) if names]
        common = set.intersection(*sets) if sets else set()
        entry["scanner_os"] = next(iter(common)) if len(common) == 1 else None
    return servers


def server_os(job, server):
    """A server's OS: the scanner rows' (job_servers scanner_os), else its collected context."""
    from host_inventory import host_is_server, load_hosts, same_server
    for entry in job_servers((job or {}).get("grouped_rows") or []):
        if same_server(entry["server"], server) and entry.get("scanner_os"):
            return entry["scanner_os"]
    try:
        host = next((h for h in load_hosts(REMEDIATION_INVENTORY)
                     if not h.get("_synthetic") and host_is_server(h, server)), None)
    except (OSError, ValueError):
        host = None
    os_info = (host or {}).get("os") or {}
    return os_info.get("name") or os_info.get("kind")


@app.get("/api/jobs/{job_id}/server-coverage")
def server_coverage(job_id, request: Request):
    """For each server the scanner named: is its context collected (inventory or Oracle)?"""
    job = JOBS.get(job_id)
    if not job or not may_access(request, job.get("owner_id")):
        return error("The upload session was not found. Upload the CSV again.", 404)
    import host_inventory

    servers = job_servers(job.get("grouped_rows") or [])
    try:
        hosts = host_inventory.load_hosts(REMEDIATION_INVENTORY) if servers else []
    except (OSError, ValueError) as exc:
        return error(f"The host inventory could not be read: {exc}", 500)
    for entry in servers:
        host = next((h for h in hosts if not h.get("_synthetic")
                     and host_inventory.host_is_server(h, entry["server"])), None)
        entry["covered"] = host is not None
        entry["source"] = host.get("_file") if host else None
        entry["collected_at"] = host.get("_collected_at") if host else None
        os_info = (host or {}).get("os") or {}
        entry["os"] = os_info.get("release_text") or os_info.get("name") or entry.get("scanner_os")
        entry["context_components"] = len((host or {}).get("components") or [])
        # The collector for its OS (os_catalog.yaml): file name and how to run it.
        import self_service
        os_name = os_info.get("name") or os_info.get("kind") or entry.get("scanner_os")
        entry["script"] = {"filename": self_service.collector_filename(entry["server"], os_name),
                           "run": self_service.collector_run(entry["server"], os_name)}
    return {"servers": servers, "missing": sum(not s["covered"] for s in servers)}


@app.get("/api/context-script")
def context_script(request: Request, server: str = "", os: str = "", job_id: str = ""):
    """The read-only collection script for one server (run by its owner, output uploaded), in
    its OS's collector: the OS given, else the scanner's OS for the server in this job, else
    its collected context; an unknown OS gets the shell script (it identifies the family)."""
    import self_service

    job = JOBS.get(job_id) if job_id else None
    if job and not may_access(request, job.get("owner_id")):
        job = None
    os_name = os[:120] or (server_os(job, server) if server else None)
    try:
        script = self_service.build_collector(server, os_name)
    except ValueError as exc:
        return error(str(exc))
    filename = self_service.collector_filename(server, os_name)
    media = "text/x-shellscript" if filename.endswith(".sh") else "text/plain"
    return Response(content=script, media_type=media,
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@app.post("/api/context-upload")
async def context_upload(request: Request, file: UploadFile | None = File(default=None),
                         server: str = Form(default=""), job_id: str = Form(default=""),
                         applications_text: str = Form(default="", alias="applications"),
                         components: str = Form(default="")):
    """Store the output of the collection script as this server's host context."""
    import self_service

    if file is None or not file.filename:
        return error("Choose the output file of the collection script.")
    data = await file.read(self_service.MAX_UPLOAD_BYTES + 1)
    if len(data) > self_service.MAX_UPLOAD_BYTES:
        return error("The uploaded file is larger than 8 MB.", 413)
    job = (JOBS.get(job_id) or {}) if may_access(request, job_owner(job_id)) else {}
    entry = next((s for s in job_servers(job.get("grouped_rows") or [])
                  if s["server"] == server), None)
    # The context gatherer page sends the server's applications and components itself.
    applications = (entry or {}).get("applications") or [
        name.strip() for name in applications_text.split("|") if name.strip()]
    try:
        result = self_service.save_upload(data.decode("utf-8", errors="replace"), server,
                                          applications=applications)
    except ValueError as exc:
        return error(str(exc))
    except Exception as exc:  # noqa: BLE001 - reported to the user, nothing half-saved matters
        return error(f"The output could not be converted: {type(exc).__name__}: {exc}", 500)
    try:
        wanted = json.loads(components or "[]")
    except ValueError:
        wanted = []
    if wanted:
        result["applied"] = context_applied_to(result, server, wanted)
    return result


def context_applied_to(result, server, wanted):
    """For each component the CSV names on this server: what the uploaded context found for it."""
    import host_inventory
    from compatibility.agent import load_knowledge, product_rules

    try:
        hosts = host_inventory.load_inventory([Path(result["inventory_file"])])
    except Exception:  # noqa: BLE001 - the context is stored; only the summary is skipped
        return []
    host = next((h for h in hosts if host_inventory.host_is_server(h, server)
                 or h.get("hostname") == result.get("hostname")), hosts[0] if hosts else None)
    found = (host or {}).get("components") or []
    knowledge = load_knowledge()
    out = []
    for item in wanted[:500]:
        product = str((item or {}).get("product") or "")
        key, _ = product_rules([product], knowledge)
        hits = [c for c in found
                if (key and product_rules(list(c.get("products") or []) + [c.get("name") or ""], knowledge)[0] == key)
                or host_inventory._matches(c.get("products"), product)]
        out.append({"product": product, "component": (item or {}).get("component"),
                    "cves": (item or {}).get("cves") or [],
                    "found": [{"name": c.get("name"), "installed_version": c.get("installed_version"),
                               "path": c.get("executable_path") or c.get("component_path"),
                               "owner": c.get("ownership")} for c in hits]})
    return out


@app.post("/api/context-gatherer/script")
def context_gatherer_script(payload: dict | None = Body(default=None)):
    """A collection script built by the context script agent for this server's vulnerable components.

    The standard allowlist plus validated read-only probes per component; the plan, coverage and
    token use are logged (context_gathered/script_agent_runs) and returned with the script.
    """
    import script_agent

    payload = payload or {}
    components = payload.get("components")
    if not isinstance(components, list) or not components:
        return error("Send the server's vulnerable components.")
    try:
        result = script_agent.generate_script(
            str(payload.get("server") or ""), components,
            applications=[str(a) for a in payload.get("applications") or []][:20],
            os_hint=str(payload.get("os") or "")[:80])
    except ValueError as exc:
        return error(str(exc))
    except Exception as exc:  # noqa: BLE001 - reported to the user; the standard script still works
        return error(f"The script could not be generated: {type(exc).__name__}: {exc}", 500)
    return {key: result[key] for key in ("server", "script", "filename", "run", "probes", "fallback_probes",
                                         "rejected", "coverage", "tokenomics", "error")}


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
