import csv
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from threading import Thread
from uuid import uuid4

from flask import Flask, Response, jsonify, request, stream_with_context
from werkzeug.exceptions import RequestEntityTooLarge

from agent_utils import create_bedrock_client
from cve_component_enrichment import (
    COMPONENT_COLUMNS,
    build_records,
    classify_cves,
    component_rows,
    read_source_file,
    write_csv,
)
from group_cves_by_component import group_by_product_and_component, write_grouped_csv


MAX_UPLOAD_BYTES = 25 * 1024 * 1024
JOBS = {}
PIPELINE_RUNS = {}
UI_DIST = Path(__file__).parent / "ui" / "dist"
DATA_DIR = Path(__file__).parent / "data"
REMEDIATION_RUNNER = (
    Path(__file__).parent / "aegis-cve-evidence" / "remediation" / "run_grouped_remediation.py"
)
REMEDIATION_RUNS_DIR = REMEDIATION_RUNNER.parent / "runs"
REMEDIATION_CONTEXT_DIR = (
    Path(__file__).parent / "aegis-cve-evidence" / "context_gathered" / "test"
)

app = Flask(
    __name__,
    static_folder=str(UI_DIST) if UI_DIST.exists() else None,
    static_url_path="",
)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES


def error(message, status=400):
    return jsonify({"error": message}), status


def csv_response(rows, columns, filename):
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=columns)
    writer.writeheader()
    writer.writerows(rows)

    return Response(
        "\ufeff" + stream.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def read_enriched_csv(path):
    """Read an enrichment output while enforcing the grouping input contract."""
    with Path(path).open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        missing = [column for column in COMPONENT_COLUMNS if column not in (reader.fieldnames or [])]
        if missing:
            raise ValueError("CSV is not a component enrichment file; missing " + ", ".join(missing))
        rows = [
            {column: str(row.get(column, "") or "") for column in COMPONENT_COLUMNS}
            for row in reader
        ]
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
    command = [
        sys.executable,
        str(REMEDIATION_RUNNER),
        "--input-csv", str(selected_path),
        "--all-cves",
        "--continue-on-error",
        "--run-id", run_id,
        "--context-dir", str(REMEDIATION_CONTEXT_DIR),
        "--allow-dummy",
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=Path(__file__).parent,
            text=True,
            capture_output=True,
            check=False,
        )
        combined = REMEDIATION_RUNS_DIR / f"grouped_remediation_{run_id}.json"
        summary = combined.parent / run_id / "run_summary.json"
        run.update({
            "status": "completed" if completed.returncode == 0 else "failed",
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "return_code": completed.returncode,
            "combined_output": str(combined.resolve()) if combined.exists() else None,
            "summary_output": str(summary.resolve()) if summary.exists() else None,
            "message": ((completed.stderr or completed.stdout or "").strip().splitlines() or
                        ["Pipeline completed."])[-1],
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
    selected = aggregate.get("selection", {}).get("selected_cves")
    return {
        "run_id": run_id,
        "status": status,
        "pipeline_status": raw_status,
        "selected_count": selected,
        "started_at": aggregate.get("started_at"),
        "completed_at": aggregate.get("completed_at"),
        "combined_output": str(combined.resolve()),
        "summary_output": str(summary.resolve()) if summary.exists() else None,
        "message": (aggregate.get("error") or
                    ("Pipeline completed with one or more assessment errors."
                     if raw_status == "completed_with_errors" else
                     "Pipeline completed." if status == "completed" else
                     f"Pipeline is {raw_status.replace('_', ' ') or 'running'}.")),
    }


def pipeline_run(run_id):
    return PIPELINE_RUNS.get(run_id) or saved_pipeline_run(run_id)


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


def public_remediation_results(aggregate):
    results = []
    verdict_counts = {}
    for item in aggregate.get("results", []):
        reasoning = item.get("reasoning") or {}
        if not reasoning:
            reasoning = (item.get("remediation_result") or {}).get("decision") or {}
        verdict = reasoning.get("verdict") or ("FAILED" if item.get("error") else "UNKNOWN")
        verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
        cited_ids = {
            claim.get("evidence_id")
            for claim in reasoning.get("supporting_claims", [])
            if claim.get("evidence_id")
        }
        remedies = [reasoning.get("recommended_remediation"),
                    *reasoning.get("candidate_remediations", [])]
        for remedy in (value for value in remedies if value):
            for support_key in ("fix_support", "applicability_support", "compatibility_support"):
                cited_ids.update(
                    claim.get("evidence_id")
                    for claim in remedy.get(support_key, [])
                    if claim.get("evidence_id"))
        evidence_sources = {}
        for index, record in enumerate((item.get("mcp_evidence") or {}).get("evidence", []), 1):
            evidence_id = f"EV-{index:03d}"
            if evidence_id not in cited_ids:
                continue
            evidence_sources[evidence_id] = {
                "source": record.get("source"),
                "url": record.get("url"),
                "product": record.get("product"),
                "release": record.get("release"),
            }
        response = (item.get("context") or {}).get("response", {})
        request_context = (item.get("context") or {}).get("request", {})
        results.append({
            "cve": item.get("cve"),
            "product": item.get("product_group"),
            "components": request_context.get("component_names", []),
            "applications": (response.get("application") or {}).get("names", []),
            "operating_systems": (response.get("server") or {}).get("os_names", []),
            "test_context": bool(request_context.get("is_dummy") or response.get("is_dummy")),
            "context_missing": bool(item.get("context_missing")),
            "status": item.get("status"),
            "error": item.get("error"),
            "verdict": verdict,
            "applicability": reasoning.get("applicability"),
            "assessment_summary": reasoning.get("assessment_summary"),
            "assessment_notes": reasoning.get("assessment_notes", []),
            "supporting_claims": reasoning.get("supporting_claims", []),
            "blocked_on": reasoning.get("blocked_on", []),
            "missing_information": reasoning.get("missing_information", []),
            "conflicts": reasoning.get("conflicts", []),
            "operational_notes": reasoning.get("operational_notes", []),
            "recommended_remediation": reasoning.get("recommended_remediation"),
            "candidate_remediations": reasoning.get("candidate_remediations", []),
            "validation_note": reasoning.get("validation_note"),
            "assessed_at": reasoning.get("assessed_at"),
            "evidence_sources": evidence_sources,
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


@app.errorhandler(RequestEntityTooLarge)
def upload_too_large(_exception):
    return error("The CSV is larger than the 25 MB upload limit.", 413)


@app.post("/api/upload")
def upload_csv():
    upload = request.files.get("file")
    if upload is None or not upload.filename:
        return error("Choose a CSV file to upload.")

    if Path(upload.filename).suffix.lower() != ".csv":
        return error("Only CSV files are accepted by this interface.")

    data = upload.read()
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

    job_id = uuid4().hex
    columns = list(source_rows[0].keys())
    # Keep one original source row for each unique CVE record so the UI retains
    # every uploaded column while row selection stays aligned with records.
    deduplicated_rows = [record["observations"][0]["row"] for record in records]
    duplicate_count = sum(
        max(0, len(record["observations"]) - 1) for record in records
    )
    JOBS[job_id] = {
        "filename": Path(upload.filename).name,
        "records": records,
        "skipped_rows": skipped_rows,
        "deduplicated_rows": deduplicated_rows,
        "deduplicated_columns": columns,
        "enriched_rows": [],
        "grouped_rows": [],
    }

    return jsonify(
        {
            "job_id": job_id,
            "filename": JOBS[job_id]["filename"],
            "original_count": original_count,
            "unique_count": len(deduplicated_rows),
            "duplicate_count": duplicate_count,
            "skipped_count": len(skipped_rows),
            "columns": columns,
            "rows": deduplicated_rows,
            "existing_enrichment": (reusable_enrichment_files() or [None])[0],
        }
    )


@app.post("/api/enrich")
def enrich_range():
    payload = request.get_json(silent=True) or {}
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
        client = create_bedrock_client() if has_eligible_source else None
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
    return jsonify(result)


@app.post("/api/enrich/reuse")
def reuse_enrichment():
    payload = request.get_json(silent=True) or {}
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
    return jsonify(result)


@app.post("/api/pipeline-runs")
def start_selected_pipeline():
    payload = request.get_json(silent=True) or {}
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
    run_id = "ui-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-") + uuid4().hex[:8]
    selected_path = DATA_DIR / f"selected_components_{run_id}.csv"
    write_csv(selected_path, selected_rows, COMPONENT_COLUMNS)
    PIPELINE_RUNS[run_id] = {
        "run_id": run_id,
        "status": "queued",
        "selected_count": len(selected_rows),
        "selected_components": [
            {"product": row.get("Product", ""), "component": row.get("Component", "")}
            for row in selected_rows
        ],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "selected_input": str(selected_path.resolve()),
        "context_source": str(REMEDIATION_CONTEXT_DIR.resolve()),
    }
    Thread(target=execute_selected_pipeline, args=(run_id, selected_path), daemon=True).start()
    return jsonify(PIPELINE_RUNS[run_id]), 202


@app.get("/api/pipeline-runs/<run_id>")
def selected_pipeline_status(run_id):
    run = pipeline_run(run_id)
    if not run:
        return error("Pipeline run was not found.", 404)
    return jsonify(run)


@app.get("/api/pipeline-runs/<run_id>/events")
def selected_pipeline_events(run_id):
    if pipeline_run(run_id) is None:
        return error("Pipeline run was not found.", 404)

    @stream_with_context
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

    return Response(
        events(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/api/pipeline-runs/<run_id>/results")
def selected_pipeline_results(run_id):
    aggregate = saved_run_aggregate(run_id)
    if aggregate is None:
        return error("Remediation results were not found.", 404)
    if aggregate.get("status") not in ("completed", "completed_with_errors", "failed"):
        return error("The remediation run is still in progress.", 409)
    return jsonify(public_remediation_results(aggregate))


@app.get("/api/download/<job_id>/<kind>")
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
    return jsonify({"status": "ok"})


@app.get("/")
def frontend():
    if UI_DIST.exists():
        return app.send_static_file("index.html")
    return jsonify(
        {
            "message": "React UI is not built yet. Run npm.cmd install and npm.cmd run build in aegis_engine_prod/ui."
        }
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.getenv("PORT", "5000")), debug=False)
