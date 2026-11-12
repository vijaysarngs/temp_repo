"""Uploads, enrichments, grouped components, run selections and run results, kept in the database.

The same store as sign-in and CVE_APP_STATE (Oracle when AEGIS_AUTH_DB=oracle, otherwise the
local SQLite file). Each upload/enriched/grouped/selected row is one table row: the columns the
UI filters on are real columns, and the full row is kept as JSON (row_json), so a new column
in the enrichment output needs no table change.

    CVE_UPLOAD          one row per uploaded file
    CVE_UPLOAD_ROW      one row per unique CVE row of an upload
    CVE_ENRICHMENT      one row per saved enrichment (what "reuse saved enrichment" lists)
    CVE_ENRICHED_ROW    the rows of an enrichment
    CVE_GROUPED_ROW     the grouped components of an upload (its latest grouping)
    CVE_RUN_SELECTION   the grouped components selected for a remediation run
    CVE_RUN_ARTIFACT    a run's saved JSON: AGGREGATE, SUMMARY, PROGRESS, CONTEXT_REASSESSMENTS,
                        COMPATIBILITY_ANSWERS, SESSION_CONTEXT:<key>

Import an existing enrichment CSV or saved run folders:
    python data_store.py import-enrichment data/customized_data_export_4_enriched.csv
    python data_store.py import-runs [RUN_ID ...]
"""
from __future__ import annotations

import csv
import json
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from aegis_auth.store import get_store

ROOT = Path(__file__).resolve().parent
UPLOAD, UPLOAD_ROW = "CVE_UPLOAD", "CVE_UPLOAD_ROW"
ENRICHMENT, ENRICHED_ROW = "CVE_ENRICHMENT", "CVE_ENRICHED_ROW"
GROUPED_ROW, SELECTION, ARTIFACT = "CVE_GROUPED_ROW", "CVE_RUN_SELECTION", "CVE_RUN_ARTIFACT"

_TS = "TIMESTAMP WITH TIME ZONE"
_TEXT = "VARCHAR2(4000)"
ORACLE_DDL = [
    f"""CREATE TABLE {UPLOAD} (
        upload_id VARCHAR2(128) PRIMARY KEY, filename VARCHAR2(512), owner_id VARCHAR2(128),
        file_sha256 VARCHAR2(64), original_count NUMBER, unique_count NUMBER,
        duplicate_count NUMBER, skipped_count NUMBER, columns_json CLOB,
        created_at {_TS} DEFAULT SYSTIMESTAMP NOT NULL)""",
    f"""CREATE TABLE {UPLOAD_ROW} (
        upload_id VARCHAR2(128) NOT NULL REFERENCES {UPLOAD} (upload_id) ON DELETE CASCADE,
        row_no NUMBER NOT NULL, cve_id VARCHAR2(64), scanner_type VARCHAR2(200), row_json CLOB NOT NULL,
        CONSTRAINT cve_upload_row_pk PRIMARY KEY (upload_id, row_no))""",
    f"""CREATE TABLE {ENRICHMENT} (
        enrichment_id VARCHAR2(64) PRIMARY KEY, display_name VARCHAR2(512) NOT NULL,
        upload_id VARCHAR2(128), enrichment_source VARCHAR2(30), owner_id VARCHAR2(128),
        row_count NUMBER, created_at {_TS} DEFAULT SYSTIMESTAMP NOT NULL,
        updated_at {_TS} DEFAULT SYSTIMESTAMP NOT NULL,
        CONSTRAINT cve_enrichment_name_uk UNIQUE (display_name))""",
    f"""CREATE TABLE {ENRICHED_ROW} (
        enrichment_id VARCHAR2(64) NOT NULL REFERENCES {ENRICHMENT} (enrichment_id) ON DELETE CASCADE,
        row_no NUMBER NOT NULL, cve_ids CLOB, application {_TEXT}, product {_TEXT}, component {_TEXT},
        scanner_type VARCHAR2(200), operating_system {_TEXT}, hostname {_TEXT}, row_json CLOB NOT NULL,
        CONSTRAINT cve_enriched_row_pk PRIMARY KEY (enrichment_id, row_no))""",
    f"""CREATE TABLE {GROUPED_ROW} (
        upload_id VARCHAR2(128) NOT NULL, row_no NUMBER NOT NULL, enrichment_id VARCHAR2(64),
        component_id VARCHAR2(200), product {_TEXT}, component {_TEXT}, scanner_type VARCHAR2(200),
        os_key VARCHAR2(200), cve_ids CLOB, row_json CLOB NOT NULL,
        CONSTRAINT cve_grouped_row_pk PRIMARY KEY (upload_id, row_no))""",
    f"""CREATE TABLE {SELECTION} (
        run_id VARCHAR2(128) NOT NULL, row_no NUMBER NOT NULL, component_id VARCHAR2(200),
        row_json CLOB NOT NULL, CONSTRAINT cve_run_selection_pk PRIMARY KEY (run_id, row_no))""",
    f"""CREATE TABLE {ARTIFACT} (
        run_id VARCHAR2(128) NOT NULL, artifact_kind VARCHAR2(80) NOT NULL, cve_id VARCHAR2(64),
        artifact_json CLOB NOT NULL, updated_at {_TS} DEFAULT SYSTIMESTAMP NOT NULL,
        CONSTRAINT cve_run_artifact_pk PRIMARY KEY (run_id, artifact_kind))""",
    f"CREATE INDEX cve_enriched_row_cve_ix ON {ENRICHED_ROW} (enrichment_id, product)",
    f"CREATE INDEX cve_upload_row_cve_ix ON {UPLOAD_ROW} (cve_id)",
    f"CREATE INDEX cve_run_artifact_kind_ix ON {ARTIFACT} (artifact_kind, run_id)",
]
SQLITE_DDL = [
    f"""CREATE TABLE IF NOT EXISTS {UPLOAD} (upload_id TEXT PRIMARY KEY, filename TEXT, owner_id TEXT,
        file_sha256 TEXT, original_count INTEGER, unique_count INTEGER, duplicate_count INTEGER,
        skipped_count INTEGER, columns_json TEXT, created_at TEXT NOT NULL)""",
    f"""CREATE TABLE IF NOT EXISTS {UPLOAD_ROW} (upload_id TEXT NOT NULL REFERENCES {UPLOAD} (upload_id)
        ON DELETE CASCADE, row_no INTEGER NOT NULL, cve_id TEXT, scanner_type TEXT, row_json TEXT NOT NULL,
        PRIMARY KEY (upload_id, row_no))""",
    f"""CREATE TABLE IF NOT EXISTS {ENRICHMENT} (enrichment_id TEXT PRIMARY KEY, display_name TEXT NOT NULL
        UNIQUE, upload_id TEXT, enrichment_source TEXT, owner_id TEXT, row_count INTEGER,
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL)""",
    f"""CREATE TABLE IF NOT EXISTS {ENRICHED_ROW} (enrichment_id TEXT NOT NULL REFERENCES {ENRICHMENT}
        (enrichment_id) ON DELETE CASCADE, row_no INTEGER NOT NULL, cve_ids TEXT, application TEXT,
        product TEXT, component TEXT, scanner_type TEXT, operating_system TEXT, hostname TEXT,
        row_json TEXT NOT NULL, PRIMARY KEY (enrichment_id, row_no))""",
    f"""CREATE TABLE IF NOT EXISTS {GROUPED_ROW} (upload_id TEXT NOT NULL, row_no INTEGER NOT NULL,
        enrichment_id TEXT, component_id TEXT, product TEXT, component TEXT, scanner_type TEXT,
        os_key TEXT, cve_ids TEXT, row_json TEXT NOT NULL, PRIMARY KEY (upload_id, row_no))""",
    f"""CREATE TABLE IF NOT EXISTS {SELECTION} (run_id TEXT NOT NULL, row_no INTEGER NOT NULL,
        component_id TEXT, row_json TEXT NOT NULL, PRIMARY KEY (run_id, row_no))""",
    f"""CREATE TABLE IF NOT EXISTS {ARTIFACT} (run_id TEXT NOT NULL, artifact_kind TEXT NOT NULL,
        cve_id TEXT, artifact_json TEXT NOT NULL, updated_at TEXT NOT NULL,
        PRIMARY KEY (run_id, artifact_kind))""",
    f"CREATE INDEX IF NOT EXISTS cve_enriched_row_cve_ix ON {ENRICHED_ROW} (enrichment_id, product)",
    f"CREATE INDEX IF NOT EXISTS cve_upload_row_cve_ix ON {UPLOAD_ROW} (cve_id)",
    f"CREATE INDEX IF NOT EXISTS cve_run_artifact_kind_ix ON {ARTIFACT} (artifact_kind, run_id)",
]

_ready_for = None
_ready_lock = threading.Lock()


def _now():
    return datetime.now(timezone.utc)


def _dump(value) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


def _parse(value):
    return json.loads(value) if isinstance(value, (str, bytes)) else value


def _short(value, limit=4000) -> str | None:
    """A searchable column: at most `limit` UTF-8 bytes (the full value is in row_json)."""
    text = str(value or "").strip()
    if not text:
        return None
    data = text.encode("utf-8")
    return text if len(data) <= limit else data[:limit].decode("utf-8", "ignore")


def store():
    """The database, with these tables created once (existing tables are left alone)."""
    global _ready_for
    db = get_store()
    with _ready_lock:
        if _ready_for is db:
            return db
        for statement in (ORACLE_DDL if db.kind == "oracle" else SQLITE_DDL):
            try:
                db.execute(statement)
            except Exception as exc:  # noqa: BLE001 - ORA-00955 / ORA-01408: already exists
                if "ORA-00955" not in str(exc) and "ORA-01408" not in str(exc):
                    raise
        _ready_for = db
    return db


# ---------------------------------------------------------------- uploads
def save_upload(upload_id, filename, owner_id, *, sha256, original_count, rows, records,
                skipped_count, duplicate_count, columns):
    """The uploaded file's details and its unique CVE rows (rows[i] belongs to records[i])."""
    db = store()
    db.execute(f"DELETE FROM {UPLOAD} WHERE upload_id = :id", {"id": upload_id})
    db.execute(f"INSERT INTO {UPLOAD} (upload_id, filename, owner_id, file_sha256, original_count, "
               "unique_count, duplicate_count, skipped_count, columns_json, created_at) VALUES "
               "(:id, :name, :owner, :sha, :original, :unique_count, :dup, :skipped, :cols, :now)",
               {"id": upload_id, "name": filename, "owner": owner_id, "sha": sha256,
                "original": original_count, "unique_count": len(rows), "dup": duplicate_count,
                "skipped": skipped_count, "cols": _dump(columns), "now": _now()})
    db.execute(f"DELETE FROM {UPLOAD_ROW} WHERE upload_id = :id", {"id": upload_id})
    batch = []
    for number, (row, record) in enumerate(zip(rows, records), 1):
        types = sorted({str(c.get("scanner_type") or "").strip() for c in record.get("contexts") or []} - {""})
        batch.append({"id": upload_id, "n": number, "cve": _short(record.get("cve_id"), 64),
                      "type": _short(" | ".join(types), 200), "doc": _dump(row)})
    db.execute_many(f"INSERT INTO {UPLOAD_ROW} (upload_id, row_no, cve_id, scanner_type, row_json) "
                    "VALUES (:id, :n, :cve, :type, :doc)", batch, clobs=("doc",))


# ---------------------------------------------------------------- enrichments
def save_enrichment(name, rows, *, upload_id=None, owner_id=None, source="new_enrichment"):
    """Save (or replace, by name) an enrichment and its rows; returns its enrichment_id."""
    db = store()
    existing = db.one(f"SELECT enrichment_id FROM {ENRICHMENT} WHERE display_name = :name", {"name": name})
    enrichment_id = existing["enrichment_id"] if existing else uuid4().hex
    now = _now()
    if existing:
        db.execute(f"DELETE FROM {ENRICHED_ROW} WHERE enrichment_id = :id", {"id": enrichment_id})
        db.execute(f"UPDATE {ENRICHMENT} SET upload_id = :upload, enrichment_source = :source, "
                   "owner_id = :owner, row_count = :count, updated_at = :now WHERE enrichment_id = :id",
                   {"id": enrichment_id, "upload": upload_id, "source": source, "owner": owner_id,
                    "count": len(rows), "now": now})
    else:
        db.execute(f"INSERT INTO {ENRICHMENT} (enrichment_id, display_name, upload_id, enrichment_source, "
                   "owner_id, row_count, created_at, updated_at) VALUES "
                   "(:id, :name, :upload, :source, :owner, :count, :now, :now)",
                   {"id": enrichment_id, "name": name, "upload": upload_id, "source": source,
                    "owner": owner_id, "count": len(rows), "now": now})
    db.execute_many(
        f"INSERT INTO {ENRICHED_ROW} (enrichment_id, row_no, cve_ids, application, product, component, "
        "scanner_type, operating_system, hostname, row_json) VALUES "
        "(:id, :n, :cves, :app, :product, :component, :type, :os, :host, :doc)",
        [{"id": enrichment_id, "n": number, "cves": str(row.get("CVE IDs") or "") or None,
          "app": _short(row.get("Application")), "product": _short(row.get("Product")),
          "component": _short(row.get("Component")), "type": _short(row.get("Scanner Type"), 200),
          "os": _short(row.get("Operating System")), "host": _short(row.get("Hostname")),
          "doc": _dump(row)} for number, row in enumerate(rows, 1)],
        clobs=("cves", "doc"))
    return enrichment_id


def list_enrichments() -> list[dict]:
    """Every saved enrichment, without its rows: name, owner, upload, row count, updated time."""
    rows = store().query(f"SELECT enrichment_id, display_name, upload_id, owner_id, row_count, updated_at "
                         f"FROM {ENRICHMENT} WHERE row_count > 0")
    return [{**row, "updated_at": _as_datetime(row.get("updated_at"))} for row in rows]


def load_enrichment(name) -> list[dict] | None:
    """An enrichment's rows in their saved order, or None when no enrichment has this name."""
    db = store()
    found = db.one(f"SELECT enrichment_id FROM {ENRICHMENT} WHERE display_name = :name", {"name": name})
    if not found:
        return None
    rows = db.query_text(f"SELECT row_json FROM {ENRICHED_ROW} WHERE enrichment_id = :id ORDER BY row_no",
                         {"id": found["enrichment_id"]})
    return [_parse(row["row_json"]) for row in rows]


def enrichment_id_for(name) -> str | None:
    found = store().one(f"SELECT enrichment_id FROM {ENRICHMENT} WHERE display_name = :name", {"name": name})
    return found["enrichment_id"] if found else None


# ---------------------------------------------------------------- grouped and selected rows
def save_grouped(upload_id, rows, enrichment_id=None):
    """Replace the upload's grouped components with these rows."""
    from group_cves_by_component import _values, os_group_key

    db = store()
    db.execute(f"DELETE FROM {GROUPED_ROW} WHERE upload_id = :id", {"id": upload_id})
    db.execute_many(
        f"INSERT INTO {GROUPED_ROW} (upload_id, row_no, enrichment_id, component_id, product, component, "
        "scanner_type, os_key, cve_ids, row_json) VALUES "
        "(:id, :n, :enrichment, :cid, :product, :component, :type, :os, :cves, :doc)",
        [{"id": upload_id, "n": number, "enrichment": enrichment_id,
          "cid": _short(row.get("Component ID"), 200), "product": _short(row.get("Product")),
          "component": _short(row.get("Component")), "type": _short(row.get("Scanner Type"), 200),
          "os": _short(os_group_key(_values(row.get("Operating System", ""))), 200),
          "cves": str(row.get("CVE IDs") or "") or None, "doc": _dump(row)}
         for number, row in enumerate(rows, 1)],
        clobs=("cves", "doc"))


def load_grouped(upload_id) -> list[dict]:
    rows = store().query_text(f"SELECT row_json FROM {GROUPED_ROW} WHERE upload_id = :id ORDER BY row_no",
                              {"id": upload_id})
    return [_parse(row["row_json"]) for row in rows]


def save_selection(run_id, rows):
    db = store()
    db.execute(f"DELETE FROM {SELECTION} WHERE run_id = :id", {"id": run_id})
    db.execute_many(f"INSERT INTO {SELECTION} (run_id, row_no, component_id, row_json) "
                    "VALUES (:id, :n, :cid, :doc)",
                    [{"id": run_id, "n": number, "cid": _short(row.get("Component ID"), 200), "doc": _dump(row)}
                     for number, row in enumerate(rows, 1)], clobs=("doc",))


def load_selection(run_id) -> list[dict]:
    rows = store().query_text(f"SELECT row_json FROM {SELECTION} WHERE run_id = :id ORDER BY row_no",
                              {"id": run_id})
    return [_parse(row["row_json"]) for row in rows]


# ---------------------------------------------------------------- run artifacts
_ARTIFACT_CACHE: dict[tuple[str, str], tuple[object, str]] = {}
_CACHE_LOCK = threading.Lock()


def _as_datetime(value):
    if isinstance(value, str) and value:
        return datetime.fromisoformat(value)
    return value


def put_artifact(run_id, kind, value, cve_id=None):
    """Save (replace) one JSON artifact of a run."""
    db = store()
    params = {"run": str(run_id), "kind": kind, "cve": _short(cve_id, 64), "doc": _dump(value), "now": _now()}
    with db.transaction() as tx:
        tx.execute(f"DELETE FROM {ARTIFACT} WHERE run_id = :run AND artifact_kind = :kind",
                   {"run": params["run"], "kind": kind})
        tx.execute(f"INSERT INTO {ARTIFACT} (run_id, artifact_kind, cve_id, artifact_json, updated_at) "
                   "VALUES (:run, :kind, :cve, :doc, :now)", params)
    with _CACHE_LOCK:     # two saves within one clock tick share an updated_at
        _ARTIFACT_CACHE.pop((params["run"], kind), None)


def artifact_stamps(kind) -> dict[str, object]:
    """run_id -> updated_at for every saved artifact of this kind (no JSON is read)."""
    rows = store().query(f"SELECT run_id, updated_at FROM {ARTIFACT} WHERE artifact_kind = :kind", {"kind": kind})
    return {row["run_id"]: _as_datetime(row["updated_at"]) for row in rows}


def get_artifact(run_id, kind, stamp=None):
    """A run's saved artifact (a fresh copy each call), or None when it is not saved.

    The JSON text is cached by its updated_at, so re-reading an unchanged run costs one
    small query (none when the caller already knows the stamp)."""
    key = (str(run_id), kind)
    db = store()
    if stamp is None:
        row = db.one(f"SELECT updated_at FROM {ARTIFACT} WHERE run_id = :run AND artifact_kind = :kind",
                     {"run": key[0], "kind": kind})
        if not row:
            return None
        stamp = _as_datetime(row["updated_at"])
    with _CACHE_LOCK:
        cached = _ARTIFACT_CACHE.get(key)
    if cached and cached[0] == stamp:
        return json.loads(cached[1])
    rows = db.query_text(f"SELECT artifact_json, updated_at FROM {ARTIFACT} "
                         "WHERE run_id = :run AND artifact_kind = :kind", {"run": key[0], "kind": kind})
    if not rows:
        return None
    text = rows[0]["artifact_json"]
    text = text if isinstance(text, str) else _dump(text)
    with _CACHE_LOCK:
        if len(_ARTIFACT_CACHE) > 200:
            _ARTIFACT_CACHE.clear()
        _ARTIFACT_CACHE[key] = (_as_datetime(rows[0]["updated_at"]), text)
    return json.loads(text)


RUN_FILES = {"SUMMARY": "run_summary.json", "PROGRESS": "workflow_progress.json",
             "CONTEXT_REASSESSMENTS": "context_reassessments.json",
             "COMPATIBILITY_ANSWERS": "compatibility_answers.json"}


def archive_run_folder(runs_dir: Path, run_id: str) -> list[str]:
    """Copy a finished run's saved JSON (combined result, summary, progress, answers, run-only
    server contexts) from its folder into CVE_RUN_ARTIFACT. Returns the kinds saved."""
    saved = []
    combined = runs_dir / f"grouped_remediation_{run_id}.json"
    files = [("AGGREGATE", combined)] + [(kind, runs_dir / run_id / name) for kind, name in RUN_FILES.items()]
    files += [(f"SESSION_CONTEXT:{path.stem.removeprefix('session_context_')}", path)
              for path in sorted((runs_dir / run_id).glob("session_context_*.json"))]
    for kind, path in files:
        try:
            value = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError):
            continue
        put_artifact(run_id, kind, value)
        saved.append(kind)
    return saved


# ---------------------------------------------------------------- command line
def _import_enrichment(path: Path, name: str | None):
    sys.path.insert(0, str(ROOT))
    from app import read_enriched_csv

    rows = read_enriched_csv(path)
    save_enrichment(name or path.name, rows, source="imported_file")
    print(f"imported {len(rows)} rows from {path.name} as {name or path.name!r}")


def _import_runs(runs_dir: Path, run_ids):
    wanted = run_ids or [p.stem.removeprefix("grouped_remediation_")
                         for p in sorted(runs_dir.glob("grouped_remediation_*.json"))]
    for run_id in wanted:
        print(run_id, archive_run_folder(runs_dir, run_id) or "nothing saved")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    one = sub.add_parser("import-enrichment", help="save an enrichment CSV in the database")
    one.add_argument("csv", type=Path)
    one.add_argument("--name", help="name shown in the UI (default: the file name)")
    runs = sub.add_parser("import-runs", help="save run folders' JSON in the database")
    runs.add_argument("run_ids", nargs="*")
    runs.add_argument("--runs-dir", type=Path, default=ROOT / "aegis-cve-evidence" / "remediation" / "runs")
    args = parser.parse_args()
    if args.command == "import-enrichment":
        _import_enrichment(args.csv, args.name)
    else:
        _import_runs(args.runs_dir, args.run_ids)
