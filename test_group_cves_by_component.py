import csv
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

import app as web_app
from cve_component_enrichment import COMPONENT_COLUMNS, component_identifier, component_rows
from group_cves_by_component import group_by_product_and_component, write_grouped_csv


CLIENT = TestClient(web_app.app)


def classification(cve_id, product, component):
    empty = {"label": "", "evidence": []}
    return {
        "cve_id": cve_id,
        "product": {"label": product, "evidence": []},
        "component": {"label": component, "evidence": []},
        "affected_symbol": empty,
        "source_path": empty,
        "component_kind": "module",
        "issues": [],
        "status": "SUPPORTED",
    }


class GroupingTests(unittest.TestCase):
    @staticmethod
    def enriched_row(product="Widget", component="Parser", cve="CVE-2026-1000"):
        row = {column: "" for column in COMPONENT_COLUMNS}
        row.update(Product=product, Component=component,
                   **{"Component ID": component_identifier(product, component),
                      "CVE IDs": cve})
        return row

    def test_enrichment_keeps_one_row_per_cve_before_grouping(self):
        records = [
            {"cve_id": cve_id, "contexts": [{
                "application": "Billing", "operating_system": "Linux",
                "row_numbers": [number],
            }]}
            for number, cve_id in enumerate(("CVE-2026-1000", "CVE-2026-1001"), 2)
        ]
        results = {
            record["cve_id"]: classification(record["cve_id"], "Widget", "Parser")
            for record in records
        }

        enriched = component_rows(records, results)
        grouped = group_by_product_and_component(enriched)

        self.assertEqual(2, len(enriched))
        self.assertEqual(["CVE-2026-1000", "CVE-2026-1001"],
                         [row["CVE IDs"] for row in enriched])
        self.assertEqual(1, len(grouped))
        self.assertEqual("Widget", grouped[0]["Product"])
        self.assertEqual("Parser", grouped[0]["Component"])
        self.assertEqual("CVE-2026-1000 | CVE-2026-1001", grouped[0]["CVE IDs"])

    def test_same_component_under_different_products_is_not_combined(self):
        rows = []
        for product, cve_id in (("Widget A", "CVE-2026-1000"),
                                ("Widget B", "CVE-2026-1001")):
            row = {column: "" for column in COMPONENT_COLUMNS}
            row.update(Product=product, Component="Parser", **{"CVE IDs": cve_id})
            rows.append(row)

        self.assertEqual(2, len(group_by_product_and_component(rows)))

    def test_writer_creates_grouped_csv(self):
        row = {column: "" for column in COMPONENT_COLUMNS}
        row.update(Product="Widget", Component="Parser",
                   **{"Component ID": component_identifier("Widget", "Parser"),
                      "CVE IDs": "CVE-2026-1000"})
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "data" / "grouped_by_comp.csv"
            write_grouped_csv(target, [row])
            with target.open(encoding="utf-8-sig", newline="") as handle:
                saved = list(csv.DictReader(handle))
        self.assertEqual([row], saved)

    def test_enrich_endpoint_persists_run_and_grouped_files(self):
        run_id = "abc123"
        enriched = {column: "" for column in COMPONENT_COLUMNS}
        enriched.update(Product="Widget", Component="Parser",
                        **{"CVE IDs": "CVE-2026-1000"})
        web_app.JOBS[run_id] = {
            "records": [{"cve_id": "CVE-2026-1000", "sources": []}],
            "enriched_rows": [],
        }
        try:
            with tempfile.TemporaryDirectory() as directory, \
                    patch.object(web_app, "DATA_DIR", Path(directory)), \
                    patch.object(web_app, "classify_cves", return_value={}), \
                    patch.object(web_app, "component_rows", return_value=[enriched]):
                response = CLIENT.post("/api/enrich", json={
                    "job_id": run_id, "start": 1, "count": 1,
                })
                self.assertEqual(200, response.status_code)
                self.assertTrue((Path(directory) / f"{run_id}.csv").is_file())
                self.assertTrue((Path(directory) / "grouped_by_comp.csv").is_file())
                self.assertEqual(run_id, response.json()["run_id"])
        finally:
            web_app.JOBS.pop(run_id, None)

    def test_reuse_endpoint_groups_saved_enrichment_file(self):
        job_id = "reuse123"
        row = self.enriched_row()
        web_app.JOBS[job_id] = {"enriched_rows": [], "grouped_rows": []}
        try:
            with tempfile.TemporaryDirectory() as directory, \
                    patch.object(web_app, "DATA_DIR", Path(directory)):
                saved = Path(directory) / "previous-run.csv"
                with saved.open("w", encoding="utf-8-sig", newline="") as handle:
                    writer = csv.DictWriter(handle, fieldnames=COMPONENT_COLUMNS)
                    writer.writeheader()
                    writer.writerow(row)

                response = CLIENT.post("/api/enrich/reuse", json={
                    "job_id": job_id, "filename": saved.name,
                })

                self.assertEqual(200, response.status_code)
                payload = response.json()
                self.assertEqual("saved_enrichment", payload["source"])
                self.assertEqual("previous-run.csv", payload["source_filename"])
                self.assertEqual([row], payload["grouped"]["rows"])
                self.assertTrue((Path(directory) / "grouped_by_comp.csv").is_file())
                self.assertEqual([row], web_app.JOBS[job_id]["grouped_rows"])
        finally:
            web_app.JOBS.pop(job_id, None)

    def test_selected_pipeline_writes_only_checked_component_rows(self):
        class DeferredThread:
            def __init__(self, target, args, daemon):
                self.target = target
                self.args = args

            def start(self):
                return None

        job_id = "selected123"
        rows = [
            self.enriched_row("Widget A", "Parser", "CVE-2026-1000"),
            self.enriched_row("Widget B", "Runtime", "CVE-2026-1001"),
        ]
        web_app.JOBS[job_id] = {"run_id": job_id, "grouped_rows": rows}
        try:
            with tempfile.TemporaryDirectory() as directory, \
                    patch.object(web_app, "DATA_DIR", Path(directory)), \
                    patch.object(web_app, "Thread", DeferredThread):
                response = CLIENT.post("/api/pipeline-runs", json={
                    "job_id": job_id, "selected_indices": [1],
                })

                self.assertEqual(202, response.status_code)
                payload = response.json()
                self.assertEqual(job_id, payload["run_id"])
                self.assertEqual(1, payload["selected_count"])
                selected_path = Path(payload["selected_input"])
                with selected_path.open(encoding="utf-8-sig", newline="") as handle:
                    selected = list(csv.DictReader(handle))
                self.assertEqual(1, len(selected))
                self.assertEqual("Widget B", selected[0]["Product"])
                self.assertEqual("Runtime", selected[0]["Component"])
                web_app.PIPELINE_RUNS.pop(payload["run_id"], None)
        finally:
            web_app.JOBS.pop(job_id, None)

    def test_same_upload_can_run_another_component_selection(self):
        class DeferredThread:
            def __init__(self, target, args, daemon):
                pass

            def start(self):
                pass

        job_id = "reselect123"
        rows = [
            self.enriched_row("Widget A", "Parser", "CVE-2026-1000"),
            self.enriched_row("Widget B", "Runtime", "CVE-2026-1001"),
        ]
        web_app.JOBS[job_id] = {"run_id": job_id, "grouped_rows": rows}
        run_ids = []
        try:
            with tempfile.TemporaryDirectory() as directory, \
                    patch.object(web_app, "DATA_DIR", Path(directory)), \
                    patch.object(web_app, "REMEDIATION_RUNS_DIR", Path(directory)), \
                    patch.object(web_app, "Thread", DeferredThread):
                first = CLIENT.post("/api/pipeline-runs", json={
                    "job_id": job_id, "selected_indices": [0]})
                self.assertEqual(202, first.status_code)
                first_id = first.json()["run_id"]
                run_ids.append(first_id)
                blocked = CLIENT.post("/api/pipeline-runs", json={
                    "job_id": job_id, "selected_indices": [1]})
                self.assertEqual(409, blocked.status_code)
                web_app.PIPELINE_RUNS[first_id]["status"] = "completed"

                second = CLIENT.post("/api/pipeline-runs", json={
                    "job_id": job_id, "selected_indices": [1]})
                self.assertEqual(202, second.status_code)
                second_id = second.json()["run_id"]
                run_ids.append(second_id)
                self.assertNotEqual(first_id, second_id)
                self.assertEqual(job_id, second.json()["job_id"])
                with Path(second.json()["selected_input"]).open(encoding="utf-8-sig", newline="") as handle:
                    selected = list(csv.DictReader(handle))
                self.assertEqual("Widget B", selected[0]["Product"])
                self.assertEqual("Widget A", rows[0]["Product"])
        finally:
            for run_id in run_ids:
                web_app.PIPELINE_RUNS.pop(run_id, None)
            web_app.JOBS.pop(job_id, None)

    def test_selected_pipeline_calls_remediation_function(self):
        run_id = "context-runner123"
        web_app.PIPELINE_RUNS[run_id] = {"run_id": run_id, "job_id": "upload-123", "status": "queued"}
        try:
            remediation_root = str(web_app.REMEDIATION_RUNNER.parent.parent)
            if remediation_root not in sys.path:
                sys.path.insert(0, remediation_root)
            from remediation import run_grouped_remediation as runner

            options_seen = []
            def fake_run(options):
                options_seen.append(options)
                (Path(directory) / f"grouped_remediation_{run_id}.json").write_text("{}")
                return {"status": "completed"}

            with tempfile.TemporaryDirectory() as directory, \
                    patch.object(web_app, "REMEDIATION_RUNS_DIR", Path(directory)), \
                    patch.object(runner, "run_grouped_remediation", side_effect=fake_run):
                selected = Path(directory) / "selected.csv"
                web_app.execute_selected_pipeline(run_id, selected)

            self.assertEqual("completed", web_app.PIPELINE_RUNS[run_id]["status"])
            self.assertEqual(1, len(options_seen))
            options = options_seen[0]
            self.assertEqual(selected, options.input_csv)
            # Centralized context: inventory only, no per-CVE files or profile overwrite.
            self.assertEqual(web_app.REMEDIATION_INVENTORY, options.inventory)
            self.assertIsNone(options.context_dir)
            self.assertTrue(options.allow_dummy)
            self.assertEqual("upload-123", options.upload_id)
            self.assertEqual(web_app.PERSIST_RUNS, options.persist_context)
            self.assertTrue(options.latest_per_component)
            self.assertFalse(options.all_cves)
        finally:
            web_app.PIPELINE_RUNS.pop(run_id, None)

    def test_grouping_uses_run_specific_file_when_default_is_locked(self):
        job_id = "locked123"
        row = self.enriched_row()
        web_app.JOBS[job_id] = {"enriched_rows": [], "grouped_rows": []}
        writes = []

        def locked_first_write(path, rows):
            writes.append(Path(path).name)
            if Path(path).name == "grouped_by_comp.csv":
                raise PermissionError("file is locked")
            return path

        try:
            with patch.object(web_app, "write_grouped_csv", side_effect=locked_first_write):
                payload = web_app.grouped_payload(
                    job_id, [row], "saved_enrichment", "previous-run.csv")

            self.assertEqual(
                ["grouped_by_comp.csv", "grouped_by_comp_locked123.csv"], writes)
            self.assertEqual("grouped_by_comp_locked123.csv", payload["grouped"]["filename"])
            self.assertIn("open or locked", payload["grouped"]["warning"])
        finally:
            web_app.JOBS.pop(job_id, None)

    def test_pipeline_events_stream_terminal_status_once(self):
        run_id = "stream123"
        web_app.PIPELINE_RUNS[run_id] = {
            "run_id": run_id,
            "status": "completed",
            "selected_count": 1,
        }
        try:
            response = CLIENT.get(f"/api/pipeline-runs/{run_id}/events")
            body = response.text

            self.assertEqual(200, response.status_code)
            self.assertEqual("text/event-stream",
                             response.headers["content-type"].split(";")[0])
            self.assertEqual(1, body.count("data:"))
            self.assertIn('"status": "completed"', body)
        finally:
            web_app.PIPELINE_RUNS.pop(run_id, None)

    def test_pipeline_status_recovers_saved_run_after_restart(self):
        run_id = "ui-saved-run"
        aggregate = {
            "run_id": run_id,
            "status": "completed",
            "started_at": "2026-10-07T07:00:00+00:00",
            "completed_at": "2026-10-07T07:01:00+00:00",
            "selection": {"selected_cves": 2},
        }
        try:
            with tempfile.TemporaryDirectory() as directory, \
                    patch.object(web_app, "REMEDIATION_RUNS_DIR", Path(directory)):
                combined = Path(directory) / f"grouped_remediation_{run_id}.json"
                combined.write_text(__import__("json").dumps(aggregate), encoding="utf-8")

                response = CLIENT.get(f"/api/pipeline-runs/{run_id}")

                self.assertEqual(200, response.status_code)
                payload = response.json()
                self.assertEqual("completed", payload["status"])
                self.assertEqual(2, payload["selected_count"])
        finally:
            web_app.PIPELINE_RUNS.pop(run_id, None)

    def test_remediation_results_endpoint_returns_public_reasoning(self):
        run_id = "ui-results-run"
        aggregate = {
            "run_id": run_id,
            "status": "completed",
            "started_at": "2026-10-07T07:00:00+00:00",
            "completed_at": "2026-10-07T07:01:00+00:00",
            "results": [{
                "cve": "CVE-2026-1000",
                "product_group": "Widget",
                "component_id": "CMP-123",
                "component_name": "Parser",
                "status": "assessment_saved",
                "error": None,
                "context": {
                    "request": {"component_id": "CMP-123", "component_names": ["Parser"]},
                    "response": {
                        "application": {"names": ["Billing"], "version": "2026.1",
                                        "install_path": "/opt/billing"},
                        "components": [{"name": "Parser", "installed_version": "1.2.3",
                                        "executable_path": "/opt/billing/parser"}],
                        "server": {"os_names": ["Linux"]},
                    },
                },
                "mcp_evidence": {"evidence": [{
                    "source": "Widget advisory",
                    "url": "https://example.com/advisory",
                    "product": "Widget",
                }]},
                "reasoning": {
                    "verdict": "NEEDS_INPUT",
                    "applicability": "UNKNOWN",
                    "assessment_summary": "Installed version is missing.",
                    "supporting_claims": [{"evidence_id": "EV-001", "quote": "Widget"}],
                    "blocked_on": ["installed version"],
                    "candidate_remediations": [],
                },
            }],
        }
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(web_app, "REMEDIATION_RUNS_DIR", Path(directory)):
            combined = Path(directory) / f"grouped_remediation_{run_id}.json"
            combined.write_text(__import__("json").dumps(aggregate), encoding="utf-8")

            response = CLIENT.get(f"/api/pipeline-runs/{run_id}/results")

            self.assertEqual(200, response.status_code)
            payload = response.json()
            self.assertEqual({"NEEDS_INPUT": 1}, payload["verdict_counts"])
            self.assertEqual(run_id, payload["results"][0]["run_id"])
            self.assertEqual("CMP-123", payload["results"][0]["component_id"])
            self.assertEqual("1.2.3", payload["results"][0]["component_version"])
            self.assertEqual("2026.1", payload["results"][0]["application_version"])
            self.assertEqual("Installed version is missing.",
                             payload["results"][0]["assessment_summary"])
            self.assertEqual("Widget advisory",
                             payload["results"][0]["evidence_sources"]["EV-001"]["source"])
            self.assertNotIn("mcp_evidence", payload["results"][0])

    def test_upload_assigns_one_workflow_run_id(self):
        response = CLIENT.post(
            "/api/upload",
            files={"file": ("findings.csv", b"CVE,Description\nCVE-2026-1000,Widget Parser\n",
                            "text/csv")},
        )
        self.assertEqual(200, response.status_code)
        payload = response.json()
        try:
            self.assertEqual(payload["run_id"], payload["job_id"])
            self.assertEqual(payload["run_id"], web_app.JOBS[payload["job_id"]]["run_id"])
        finally:
            web_app.JOBS.pop(payload["job_id"], None)

if __name__ == "__main__":
    unittest.main()
