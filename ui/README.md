# Aegis CVE Enrichment UI

The interface uploads a CSV, shows one unchanged source row per unique CVE,
and lets the user select a contiguous range for enrichment. When a compatible
enrichment CSV already exists in `../data`, **Run pipeline** offers to reuse the
newest saved file or run a fresh enrichment. Both paths generate and display
`data/grouped_by_comp.csv` on a component-selection page. Only checked
product/component groups are written to the selected-run input and sent to the
remediation pipeline.

Every table (uploaded rows, enriched rows, grouped components) has a search
across all columns and any number of column filters. Filtering keeps each row's
original number.

On the grouped page, a **Previous fix** column marks components that a saved
run already assessed as `FIX_AVAILABLE` (still passing the citation checks;
`GET /api/jobs/{job_id}/fix-history`). Clicking the badge asks whether to view
that previous result. **Get remediation** on a selection that includes such
components first offers to view the previous fixes, run only the others, or run
all again. Components without a previous fix run without a prompt.

After **Get remediation**, the grouped page shows a live five-stage workflow for
the current CVE (orchestrator route, vendor/OS evidence adapters, conditional
internet lookup, remediation assessment, compatibility check) and an **Agent
calls** feed: each evidence adapter call (records found, duration or error)
and each stage change, with the adapter-call count and elapsed time. LLM calls
and token counts are recorded in `workflow_progress.json` for reference but not
shown. The updates come from the pipeline status stream; a run's progress,
including the feed (`activity`, last 200 events) and `totals`, is kept in
`workflow_progress.json` and returned by the run-status endpoint.

Unit tests for the table filters: `node --test src/tableFilters.test.js src/remediationResults.test.js`.

## Run the development UI

Start the FastAPI service from `aegis_engine_prod`:

```powershell
pip install -r .\requirements.txt
python -m uvicorn app:app --host 127.0.0.1 --port 5000
```

In another terminal, start React from `aegis_engine_prod\ui`:

```powershell
npm.cmd install
npm.cmd run dev
```

Open `http://127.0.0.1:5173`.

## Run as one application

Build React once from `aegis_engine_prod\ui`:

```powershell
npm.cmd install
npm.cmd run build
```

Then start the FastAPI service from `aegis_engine_prod`:

```powershell
python -m uvicorn app:app --host 127.0.0.1 --port 5000
```

Open `http://127.0.0.1:5000`.
