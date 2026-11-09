"""Upload jobs, pipeline runs and rule drafts, kept in the database instead of app memory.

They live in one table, CVE_APP_STATE (Oracle when AEGIS_AUTH_DB=oracle, otherwise the local
SQLite file), through the same store as the sign-in tables. Each object behaves like a dict:
reading loads it from the table and every assignment is written straight back, so a restart
loses nothing and several workers see the same state.

    JOBS = StateDict("JOB")
    job = JOBS[job_id]; job["x"] = 1            # saved immediately (only the changed keys)
"""
from __future__ import annotations

import json
import threading
from datetime import datetime, timezone

from aegis_auth.store import get_store

TABLE = "CVE_APP_STATE"
ORACLE_DDL = [
    f"""CREATE TABLE {TABLE} (
        state_kind  VARCHAR2(30)  NOT NULL,
        state_key   VARCHAR2(128) NOT NULL,
        job_id      VARCHAR2(128),
        status      VARCHAR2(30),
        state_json  CLOB NOT NULL,
        created_at  TIMESTAMP WITH TIME ZONE DEFAULT SYSTIMESTAMP NOT NULL,
        updated_at  TIMESTAMP WITH TIME ZONE DEFAULT SYSTIMESTAMP NOT NULL,
        CONSTRAINT cve_app_state_pk PRIMARY KEY (state_kind, state_key),
        CONSTRAINT cve_app_state_json_ck CHECK (state_json IS JSON)
    )""",
    f"CREATE INDEX cve_app_state_job_ix ON {TABLE} (state_kind, job_id)",
]
SQLITE_DDL = [
    f"""CREATE TABLE IF NOT EXISTS {TABLE} (
        state_kind TEXT NOT NULL, state_key TEXT NOT NULL, job_id TEXT, status TEXT,
        state_json TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
        PRIMARY KEY (state_kind, state_key))""",
    f"CREATE INDEX IF NOT EXISTS cve_app_state_job_ix ON {TABLE} (state_kind, job_id)",
]

_ready_for = None
_ready_lock = threading.Lock()


def _now():
    return datetime.now(timezone.utc)


def ensure_table(store=None):
    """Create CVE_APP_STATE once per store (existing tables are left alone)."""
    global _ready_for
    store = store or get_store()
    with _ready_lock:
        if _ready_for is store:
            return store
        for statement in (ORACLE_DDL if store.kind == "oracle" else SQLITE_DDL):
            try:
                store.execute(statement)
            except Exception as exc:  # noqa: BLE001 - ORA-00955: name is already used
                if "ORA-00955" not in str(exc) and "ORA-01408" not in str(exc):
                    raise
        _ready_for = store
    return store


def _parse(value) -> dict:
    """Oracle 23ai may hand back an IS JSON column already parsed."""
    return json.loads(value) if isinstance(value, (str, bytes)) else dict(value)


def _dump(value) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


class StateRecord(dict):
    """One stored object. Changes are saved to the table as soon as they are made."""

    def __init__(self, owner: "StateDict", key: str, data: dict):
        super().__init__(data)
        self._owner, self._key = owner, key

    def __setitem__(self, name, value):
        self.update({name: value})

    def update(self, *args, **kwargs):
        changes = dict(*args, **kwargs)
        super().update(changes)
        self._owner._merge(self._key, changes)

    def setdefault(self, name, default=None):
        if name not in self:
            self[name] = default
        return self[name]

    def pop(self, name, *default):
        if name in self:
            value = super().pop(name)
            self._owner._merge(self._key, {}, removed=[name])
            return value
        if default:
            return default[0]
        raise KeyError(name)

    def __delitem__(self, name):
        self.pop(name)


class StateDict:
    """A dict-like view of the rows of one kind in CVE_APP_STATE."""

    def __init__(self, kind: str):
        self.kind = kind

    # -- storage -----------------------------------------------------------------------
    def _load(self, row) -> StateRecord:
        return StateRecord(self, row["state_key"], _parse(row["state_json"]))

    def _merge(self, key: str, changes: dict, removed=()):
        """Apply changes to the stored object under a row lock so two writers never overwrite each other."""
        store = ensure_table()
        with store.transaction() as tx:
            row = tx.one(f"SELECT state_json FROM {TABLE} WHERE state_kind = :k AND state_key = :key"
                         + (" FOR UPDATE" if store.kind == "oracle" else ""),
                         {"k": self.kind, "key": key})
            data = _parse(row["state_json"]) if row else {}
            data.update(changes)
            for name in removed:
                data.pop(name, None)
            self._write(tx, key, data, new=row is None)

    def _write(self, tx, key, data, new):
        params = {"k": self.kind, "key": key, "job": str(data.get("job_id") or "") or None,
                  "status": str(data.get("status") or "") or None, "doc": _dump(data), "now": _now()}
        if new:
            tx.execute(f"INSERT INTO {TABLE} (state_kind, state_key, job_id, status, state_json, created_at, "
                       "updated_at) VALUES (:k, :key, :job, :status, :doc, :now, :now)", params)
        else:
            tx.execute(f"UPDATE {TABLE} SET job_id = :job, status = :status, state_json = :doc, "
                       "updated_at = :now WHERE state_kind = :k AND state_key = :key", params)

    # -- dict interface ----------------------------------------------------------------
    def __setitem__(self, key, value):
        store = ensure_table()
        with store.transaction() as tx:
            exists = tx.one(f"SELECT 1 AS present FROM {TABLE} WHERE state_kind = :k AND state_key = :key",
                            {"k": self.kind, "key": key}) is not None
            self._write(tx, key, dict(value), new=not exists)

    def get(self, key, default=None):
        row = ensure_table().one(f"SELECT state_key, state_json FROM {TABLE} "
                                 "WHERE state_kind = :k AND state_key = :key", {"k": self.kind, "key": key})
        return self._load(row) if row else default

    def __getitem__(self, key):
        record = self.get(key)
        if record is None:
            raise KeyError(key)
        return record

    def __contains__(self, key):
        return ensure_table().one(f"SELECT 1 AS present FROM {TABLE} WHERE state_kind = :k AND state_key = :key",
                                  {"k": self.kind, "key": key}) is not None

    def pop(self, key, *default):
        record = self.get(key)
        if record is None:
            if default:
                return default[0]
            raise KeyError(key)
        ensure_table().execute(f"DELETE FROM {TABLE} WHERE state_kind = :k AND state_key = :key",
                               {"k": self.kind, "key": key})
        return dict(record)

    def __delitem__(self, key):
        self.pop(key)

    def values(self, job_id: str | None = None, status=None):
        """Stored objects, optionally only those of one upload (job_id) or with one of the given statuses."""
        sql, params = f"SELECT state_key, state_json FROM {TABLE} WHERE state_kind = :k", {"k": self.kind}
        if job_id is not None:
            sql += " AND job_id = :job"
            params["job"] = job_id
        if status:
            wanted = [status] if isinstance(status, str) else list(status)
            names = {f"s{i}": value for i, value in enumerate(wanted)}
            sql += " AND status IN (" + ", ".join(":" + name for name in names) + ")"
            params.update(names)
        return [self._load(row) for row in ensure_table().query(sql + " ORDER BY created_at", params)]


def mark_interrupted(runs: StateDict) -> int:
    """After a restart the background thread of a queued or running run is gone: say so."""
    count = 0
    for run in runs.values(status=("queued", "running")):
        run.update({"status": "failed", "completed_at": _now().isoformat(),
                    "message": "The server restarted while this run was in progress; start it again."})
        count += 1
    return count
