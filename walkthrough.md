# CSV to remediation UI walkthrough

This document traces the web workflow from a scanner CSV selected in the browser to a remediation card rendered in the UI. It describes the current implementation, including its test-fixture behaviour. It does **not** deploy a patch or run an SSH command.

## One-screen map

```text
Browser CSV
  -> UploadPanel.upload(file)                         [multipart/form-data]
  -> POST /api/upload -> upload_csv(file)             [rows -> CVE records]
  -> POST /api/enrich -> enrich_range(payload)        [records -> enriched CVE rows]
       -> classify_cves -> Bedrock classification      [source text -> validated labels]
       -> component_rows -> grouped_payload            [labels -> component groups]
  -> POST /api/pipeline-runs                           [chosen group indexes -> selected CSV]
       -> background execute_selected_pipeline
       -> run_grouped_remediation(RemediationOptions) [same Python process]
          -> read_grouped_csv                          [grouped CSV -> partial contexts]
          -> apply_context_directory / inventory       [partial -> matching fixture context]
          -> LangGraph route -> vendor + OS adapters   [configured source evidence]
                            -> internet lookup         [only when adapters return no evidence]
          -> run_agent(context, evidence)              [direct function call -> decision]
          -> Oracle CVE_CONTEXT (opt-in)                [audit persistence]
  -> GET /api/pipeline-runs/{run_id}/results
       -> public_remediation_results                   [evidence + reasoning -> UI DTO]
  -> RemediationResultCard(result)                     [DTO -> remediation card]
```

## Running example

The saved sample at `data/selected_components_ui-20261011-155342-510a3f5e.csv` contains this group:

```csv
Application,Product,Component,Component ID,CVE IDs,Operating System
RMS Foundation,Apache Log4j2,Thread Context Map,CMP-8CA0CE20E2211BBBB75DFB9C,CVE-2021-45105,IBM AIX 7.2
```

The UI runner explicitly enables test context (`allow_dummy=True`, `reuse_test_inventory=True`) and searches `aegis-cve-evidence/context_gathered/test`. The matching CVE context supplies the Log4j2 component facts: installed version `2.14.1`, Java 8, JAR path, application-bundled Maven lineage, and manifest/classpath verification. These are synthetic test facts, not host observations.

## 1. Browser upload and API validation

**Caller:** `UploadPanel.upload(file)` in `ui/src/App.jsx`

- Receives a browser `File` from the drop zone or file picker.
- Rejects filenames that do not end in `.csv` before sending them.
- Creates `FormData`, appends it under the `file` key, and calls `POST /api/upload`.
- On a successful JSON response, calls the `onUploaded(result)` callback, which sets the `dataset` React state.

Example request shape:

```http
POST /api/upload
Content-Type: multipart/form-data

file=@scanner-findings.csv
```

**Receiver:** `upload_csv(file: UploadFile | None)` in `app.py`

The function receives FastAPI's `UploadFile` parameter and applies these transformations:

1. Rejects an absent filename, non-CSV extension, empty body, body over 25 MiB, and non-UTF-8/UTF-8-BOM input.
2. Counts every parsable source row with `csv.DictReader`; this is the UI's `original_count`.
3. Writes the upload to a temporary CSV only so `read_source_file(temp_path)` can use the common parser, then deletes that temporary file in `finally`.
4. Calls `build_records(source_rows)`, described next.
5. Generates one `ui-YYYYMMDD-HHMMSS-xxxxxxxx` run ID and stores the working state in the in-memory `JOBS` dictionary.

It returns a dataset object such as:

```json
{
  "job_id": "ui-20261011-155342-510a3f5e",
  "run_id": "ui-20261011-155342-510a3f5e",
  "filename": "scanner-findings.csv",
  "original_count": 24,
  "unique_count": 19,
  "duplicate_count": 5,
  "skipped_count": 0,
  "columns": ["CVE ID", "Description", "Primary Application", "OS Name"],
  "rows": [{"CVE ID": "CVE-2021-45105", "Description": "..."}],
  "existing_enrichment": {"filename": "my-run-001.csv", "row_count": 142}
}
```

`JOBS` is process-local: restarting the API loses upload/enrichment session state. Remediation run artifacts are durable and can be re-read after restart.

## 2. Parse, normalize, and deduplicate the scanner rows

**Parser:** `read_source_file(path, sheet_name=None)` in `cve_component_enrichment.py`

- Input: the temporary CSV path (the CLI also supports `.xlsx`; the web upload route does not).
- Uses `csv.DictReader` with `utf-8-sig` so an Excel BOM is removed.
- Requires headers, rejects duplicate headers and rows with more values than headers.
- Output: `list[dict]`, one dictionary per source row, retaining every uploaded column.

**Record builder:** `build_records(rows)` in `cve_component_enrichment.py`

- Input: source row dictionaries.
- Looks for normalized CVE header aliases: `cve`, `cve id`, `cve ids`, or `vulnerability id`.
- Extracts every `CVE-YYYY-NNNN...` value from those cells, uppercases it, and deduplicates by CVE ID.
- Keeps all original observations, application/OS contexts, and text sources rather than dropping the duplicate details.
- Text sources only come from description-like columns (`description`, `summary`, `technical details`, etc.). A source associated with multiple CVEs is marked `shared_cve_ids`; it cannot be used for confident per-CVE classification.

For a source row such as:

```json
{
  "CVE ID": "CVE-2021-45105",
  "Description": "Apache Log4j2 ... Thread Context Map data ...",
  "Primary Application": "RMS Foundation",
  "OS Name": "IBM AIX 7.2"
}
```

the record returned contains the following shape (abridged):

```json
{
  "cve_id": "CVE-2021-45105",
  "observations": [{"row_number": 15, "row": {"CVE ID": "CVE-2021-45105"}}],
  "contexts": [{"application": "RMS Foundation", "operating_system": "IBM AIX 7.2", "row_numbers": [15]}],
  "sources": [{
    "source_id": "row15:col8",
    "row_number": 15,
    "column": "Description",
    "text": "Apache Log4j2 ... Thread Context Map data ...",
    "shared_cve_ids": []
  }]
}
```

The upload response's `rows` field takes the first preserved `observations[0].row` for each CVE, so the initial data table shows the original columns but only one row per unique CVE. Invalid CVE rows are retained internally under `skipped_rows` and counted, but are not passed to enrichment.

## 3. Enrich the selected CVE range

**Browser call:** `runEnrichment(mode)` in `ui/src/App.jsx`

- Fresh mode sends `POST /api/enrich` with `{ "job_id", "start", "count" }`.
- Reuse mode sends `POST /api/enrich/reuse` with `{ "job_id", "filename" }`.
- Uses a 30-minute abort timer because model classification can retry unresolved items.

**Fresh endpoint:** `enrich_range(payload: dict | None)` in `app.py`

Example payload:

```json
{"job_id": "ui-20261011-155342-510a3f5e", "start": 1, "count": 10}
```

The endpoint validates that the job exists and that `start`/`count` select a valid one-based slice of `job["records"]`. It creates a Bedrock client only when at least one selected CVE has a non-shared description, then calls:

### 3a. LLM classification with source validation

**`classify_cves(client, records, batch_size=5, max_batches=None, max_tokens=6000, diagnostics=None, caller=None)`** in `cve_component_enrichment.py`

- Input: unique CVE records, including their scanner-text sources and metadata contexts.
- Separates records with no sources (`MISSING_DESCRIPTION`) or only shared sources (`AMBIGUOUS_SOURCE`) without asking the model to guess.
- Sends eligible records in batches of five through `classify_batch`.
- For every non-`SUPPORTED` response, retries that one CVE once with feedback, then merges only previously validated facts using `merge_retry`.
- Output: a dictionary keyed by CVE ID. Each value has `product`, `component`, `affected_symbol`, and `source_path` facts, `component_kind`, `status`, and `issues`.

**`classify_batch(client, records, max_tokens=6000, retry_feedback=None)`** builds a Bedrock tool-use request. Its prompt asks for exact source-backed labels only and forces the `submit_detailed_component_classifications` schema. `agent_utils.invoke_bedrock(client, body, purpose)` serializes that request and returns the provider response JSON.

**`interpret_response(response, records)`** and **`validate_classification(item, record)`** are the safety transformation. They require exactly one model item per requested CVE and verify that every evidence quote:

- references a real `source_id`;
- is an exact contiguous substring of that source text; and
- includes the claimed label.

This produces labels such as:

```json
{
  "cve_id": "CVE-2021-45105",
  "product": {"label": "Apache Log4j2", "evidence": [{"source_id": "row15:col8", "quote": "Apache Log4j2"}]},
  "component": {"label": "Thread Context Map", "evidence": [{"source_id": "row15:col8", "quote": "Thread Context Map"}]},
  "component_kind": "library_feature",
  "status": "SUPPORTED",
  "issues": []
}
```

The classifier identifies text evidence only. `SUPPORTED` does not mean the product is installed, vulnerable, or safe to patch.

### 3b. Convert classifications to enriched rows and groups

**`component_rows(records, classifications)`** in `cve_component_enrichment.py`

- Input: selected unique records and their validated classification dictionary.
- Output: one normalized component-CVE row for each `(CVE, application, OS)` context, sorted by application/product/component/OS/CVE.
- Uses `component_identifier(product, component)` to create the deterministic ID `CMP-` plus the first 24 uppercase hex digits of SHA-256 over `product + U+001F + component`.
- Joins repeatable evidence fields with ` | ` and carries the original source row numbers.

The Log4j2 example becomes (abridged):

```json
{
  "Application": "RMS Foundation",
  "Product": "Apache Log4j2",
  "Component": "Thread Context Map",
  "Component ID": "CMP-8CA0CE20E2211BBBB75DFB9C",
  "CVE IDs": "CVE-2021-45105",
  "Operating System": "IBM AIX 7.2",
  "Component Kind": "library_feature",
  "Classification Status": "SUPPORTED",
  "Source Rows": "15"
}
```

`enrich_range` writes these rows to `data/<job_id>.csv` via `write_csv(path, rows, columns)`, then calls `grouped_payload(job_id, enriched_rows, source, source_filename)` in `app.py`.

**`grouped_payload`** calls **`group_by_product_and_component(rows)`** in `group_cves_by_component.py`:

- Group key: exact `(Product, Component)` pair; application and OS do not create separate groups.
- Scalar columns retain the first row's value.
- List-style columns (including CVE IDs, application, OS, evidence, classification status, and source rows) are split on ` | `, deduplicated in first-seen order, then joined back with ` | `.
- It saves `data/grouped_by_comp.csv`; if Excel has locked that file, it falls back to `data/grouped_by_comp_<job_id>.csv` and returns a warning.

The JSON response contains both `rows` (un-grouped enriched entries) and `grouped.rows` (the selectable remediation groups). `finishGrouping(result)` stores each in React state and switches the UI to the grouped view.

The reuse endpoint follows the same grouping path but calls `read_enriched_csv(DATA_DIR / filename)` first. That reader verifies the enrichment column contract and regenerates any missing stable component ID; it does not call Bedrock.

## 4. Select groups and start the background remediation run

**Selection UI:** `GroupedTable({ columns, rows, selected, setSelected })` in `ui/src/App.jsx`

The table stores zero-based row indexes in a JavaScript `Set`. `runSelectedComponents()` sorts those indexes and sends:

```json
{
  "job_id": "ui-20261011-155342-510a3f5e",
  "selected_indices": [0]
}
```

**Endpoint:** `start_selected_pipeline(payload: dict | None)` in `app.py`

- Validates the job, the integer indexes, and that at least one group was selected.
- Deduplicates indexes while preserving order, extracts `job["grouped_rows"][index]`, and writes them to `data/selected_components_<run_id>.csv` with the common component columns.
- Uses the upload ID for the first remediation run and a fresh run ID for each later selection. After viewing results, **Back to remediation selection** clears the previous checkboxes and lets the user select new groups without regrouping or reuploading. Earlier run artifacts remain under their original IDs.
- Rejects a second submission with HTTP 409 only while another remediation run for the same upload is queued or running.
- Creates a `PIPELINE_RUNS[run_id]` status record (`queued`) and starts a daemon thread targeting `execute_selected_pipeline(run_id, selected_path)`.
- Returns HTTP 202 with run metadata including the selected count and source paths.

`execute_selected_pipeline` changes the in-memory status to `running`, imports the runner, and calls it directly in that background thread:

```python
aggregate = run_grouped_remediation(RemediationOptions(
    input_csv=selected_path,
    latest_per_component=True,
    continue_on_error=True,
    run_id=run_id,
    context_dir=REMEDIATION_CONTEXT_DIR,
    allow_dummy=True,
    reuse_test_inventory=True,
))
```

The API uses the returned aggregate to mark the run completed or failed. The aggregate JSON file, rather than the in-memory status, is the durable record. The UI path uses synthetic inventory; a CLI or embedded caller can omit those test options.

## 5. Convert the selected grouped CSV into assessment inputs

**`read_grouped_csv(path: Path)`** in `aegis-cve-evidence/remediation/run_grouped_remediation.py`

- Requires `Product`, `Component`, and `CVE IDs` columns.
- Splits every CVE ID from the group, creating one item per `(component, CVE)`.
- Creates an initial **partial context** from the grouped row: request identity, application names, product, component, OS names, classification status/reason, and no installed version.

The runner applies `select_items(...)` and then `latest_cve_per_component(items)` before loading context files. Because the UI sets `latest_per_component=True`, only the numerically highest `(year, sequence)` CVE in each selected component group is assessed.

For the sample row, the initial item has this important shape:

```json
{
  "cve": "CVE-2021-45105",
  "vendor": "auto",
  "products": ["Apache Log4j2"],
  "components": ["Thread Context Map"],
  "component_id": "CMP-8CA0CE20E2211BBBB75DFB9C",
  "os_names": ["IBM AIX 7.2"],
  "product_group": "Apache Log4j2",
  "context": {
    "request": {"cve_id": "CVE-2021-45105", "component_names": ["Thread Context Map"]},
    "response": {"status": "PARTIAL", "components": [{"installed_version": null}]}
  }
}
```

**Context replacement:** `apply_context_directory(items, context_dir)` recursively indexes `*.context.json` files by CVE. For each item it scores candidates by matching `request.product_group`, application product, and component name. The highest positive score replaces the partial context; otherwise `context_missing` is set and the partial context remains.

For this example, it selects `aegis-cve-evidence/context_gathered/test/apache-log4j2/cves/CVE-2021-45105.context.json`.

**Synthetic inventory overlay:** `apply_test_inventory(items, profiles_path)` loads `test_inventory_profiles.json` and matches the product to a profile. It marks the context dummy, writes `SYNTHETIC_TEST_INVENTORY` provenance, and overlays the profile's version, path, lineage, runtime, verification method, application version, and install path. This only happens because the UI sets `reuse_test_inventory=True` along with `allow_dummy=True`.

**Identity attachment:** `apply_run_identity(items, run_id)` adds `run_id`, `component_id`, and `component_names` to `context.request`, adds `run_id` to `context.response`, and puts the component ID on the matching response component.

## 6. Route, fetch, and preserve CVE evidence

The runner compiles `build_workflow(...)` in `aegis-cve-evidence/remediation/orchestrator.py` once, then streams the graph for each selected CVE. Its nodes call Python functions in the same process: `route`, `vendor_evidence`, optional `internet_lookup`, then `assess`. `--fetch-only` skips the assessment node's model call. The UI run asks for the latest CVE per selected component; a direct CLI call has its own selection options.

After grouping from a fresh or reused enrichment file, **Get remediation** starts the selected CVEs. Each orchestrator node reports when it starts and completes. The runner saves the current CVE and node states in `workflow_progress.json` under that run's artifact directory, and the API includes the same snapshot in `/api/pipeline-runs/{run_id}` and its live events stream. The UI shows the actual branch: vendor/OS evidence first when selected, internet lookup only when the adapters return no evidence or no configured adapter applies, then remediation assessment. A skipped internet step is marked as skipped once assessment starts. The completed view keeps this path visible beside the results.

Progress snapshots use a unique temporary file and retry a Windows rename lock. If the snapshot still cannot be saved, the assessment continues and the in-memory live update is sent; the last durable snapshot may be older than the current UI state.

### 6a. Configured vendor and OS adapters

`vendor_route(item)` chooses a configured component vendor from the product/component text when possible. For each CVE, it reads OS names from the resolved `context.response.server.os_names`, falling back to the grouped row only when the context has none. `Engine.lookup(...)` loads CVE metadata and references, calls `select(...)` for the component vendor, and adds every matching `os_sources(os_name)` publisher. For example, an AIX 7.2 host adds `IBM` (`src/aegis_evidence/sources/ibm.py`), and Rocky Linux or an unspecified Linux host adds `Rocky Linux` (`rocky.py`). Unspecified Linux makes Rocky evidence a lead, not proof of host applicability.

The engine calls each source adapter's `search(ctx)` directly, accumulating evidence and per-source errors. It checks the OS adapter even if the component vendor already returned evidence. IBM bulletin service packs and interim fix IDs, and Rocky fixed package versions, remain source records even when their release line differs from the host. Compatibility and applicability are assessed later; the source product and release stay attached to each record.

If the configured adapters return at least one record, the graph goes directly to `assess`. This includes IBM evidence for AIX components and Rocky evidence for Rocky Linux components; their source adapters provide the OS fix without an internet search. A configured component vendor adapter runs in the same `Engine.lookup(...)` call when selected. If the adapters return no evidence, the graph continues to internet lookup. An unrecognized vendor with no matching OS adapter can route directly to internet lookup. On a direct internet route with a known OS, the internet node first calls the matching OS adapter so that source is not skipped.

### 6b. Internet lookup workflow

For an AIX 7.2 host, the remediation prompt receives at most one concise IBM AIX 7.2 fix record plus any configured component-adapter records. The selector discards IBM VIOS, AIX 7.3, and unrelated Linux distribution package rows from the prompt, prefers the host's technology level when known, and removes the repeated bulletin paragraph and instruction links. The original IBM adapter records remain in `mcp_evidence.json` and the UI's expandable evidence section. Evidence IDs retain their original positions so citations still point to the saved records.

On Bedrock, page fact extraction and other small `fast` lookup calls use Claude Haiku 4.5 by default (`CVE_FALLBACK_FAST_MODEL` overrides it). Conflict resolution and host mapping use the `deep` tier, which continues to use `BEDROCK_MODEL_ID` unless `CVE_FALLBACK_DEEP_MODEL` is set. The remediation assessor also keeps its configured main model.

`internet_lookup` builds a `CveRow` from the CVE, product, and component, plus a `HostProfile` from the OS names. It calls `Internet_lookup.run_fallback(...)` as a function and passes prior adapter evidence when available. `FallbackRun` then:

1. Checks a per-CVE/component/host cache (seven-day default lifetime) and classifies the component type using rules, with a small model call only when rules cannot decide.
2. Builds bounded, source-oriented search queries. AIX component searches query IBM and, when known, the component publisher site (for example OpenSSH or OpenSSL) for the same CVE. Other plans target relevant vendor, distribution, or upstream sites. The default `CVE_FALLBACK_SEARCH=ddgs` submits each query through DDGS metasearch with its `auto` backend (configurable with `CVE_DDGS_BACKEND`). Search calls are spaced by `AEGIS_SEARCH_MIN_INTERVAL_SECONDS`; the per-CVE search budget remains in force. If DDGS fails and `BRAVE_API_KEY` is configured, the same query is sent to Brave Search API. Explicit `duckduckgo` remains available, as do `brave` and `anthropic`. Internet lookup fetches only URLs returned by the chosen search provider.
3. Filters discovered URLs to allowlisted domains, rejects URLs naming only another CVE, deduplicates candidates, ranks by source tier, and fetches at most two search-result pages by default. When both IBM and a known component publisher appear in results, one fetch slot is reserved for each. A multi-CVE bulletin remains eligible if its URL includes the target CVE. For an AIX host, IBM i-only search results are skipped because IBM i is a different operating system. It continues to later queries after a search error, within the per-CVE search budget. `Fetcher.fetch` performs live HTTP GET requests for those pages, follows only redirects that stay on the allowlist, and converts HTML to text. Tier 1 is vendor/distribution/upstream; tier 2 is NVD/CVE.org/CISA; tier 3 aggregators are leads. If no usable facts are found, fix status stays unknown and no `no_fix` option is created.
4. Validates a search-result page only if its text contains the exact CVE ID. For a long multi-CVE bulletin, the model excerpt includes both the target CVE entry and the later bulletin remediation section within the page text limit. Extracted fix versions need a supporting excerpt present on that fetched page; CVSS values are checked against the target CVE's section instead of other entries on the bulletin. Unsupported fix and stance claims are dropped. Reference following is off by default (`max_follow_refs=0`); if enabled, followed tier-1/2 pages carry their own provenance.
5. Reconciles facts and conflicts, maps up to three options to the host, and marks host applicability unverified when the source does not establish compatibility. It saves a `LookupResult` with `verified_facts`, `sources`, conflicts, options, statistics, and logs. A result with description data but no verified fix or vendor stance is `partial`.

`lookup_to_evidence(item, lookup)` is the gate into remediation. It uses only `verified_facts` whose URL belongs to a fetched, validated source. Each fixed version needs both a version and a supporting excerpt; a cited vendor stance also becomes a record. Search hits, unvalidated pages, and unsupported claims do not become assessor evidence. The orchestrator appends OS/vendor adapter records and preserves the full lookup result for review. `run_agent` selects the host-relevant IBM records before numbering the evidence passed to the model. Search hits, unvalidated pages, and unrelated IBM platform fixes do not enter the assessment prompt.

The runner writes the combined evidence to:

```text
aegis-cve-evidence/remediation/runs/<run_id>/<safe product>/<component id>/<CVE>/mcp_evidence.json
```

The default lookup limits per CVE are 6 searches, 12 page fetches, 2 search-result pages considered for extraction, 15 model calls, 12,000 model-input bytes, 5,000 input tokens, 15,000 reserved output tokens, and a 240-second deadline. It sends at most 2,500 characters per page to its extraction model. The lookup's counted input is subtracted from the shared remediation budget of 36,000 input bytes and 15,000 input tokens per CVE. Remediation itself has a 10,000 output-token limit per call and a 15,000 output-token total across its initial call and one repair. Model calls are paced at least 2 seconds apart and page requests at least 0.25 seconds apart per Python worker by default; environment variables `AEGIS_MODEL_MIN_INTERVAL_SECONDS` and `AEGIS_PAGE_MIN_INTERVAL_SECONDS` adjust those intervals. Multiple workers need a shared external limiter for a deployment-wide rate limit.

## 7. Produce and validate a remediation decision

For each selected item, the graph calls `run_agent(context, evidence, client, config, allow_dummy)` in `remedition_agent.py` directly. No child process or standard-input handoff is used. The runner saves the returned result and public reasoning in the CVE's artifact directory.

**`prepare(context, evidence)`** in `remedition_agent.py` receives those two dictionaries and returns the model package:

- verifies a context response object and matching request/response CVE;
- verifies evidence carries the same CVE and an `evidence`/`advisories` list;
- assigns stable `EV-001`, `EV-002`, ... IDs without removing provider-specific record fields;
- keeps concise evidence metadata while leaving the full raw internet lookup payload in the saved evidence artifact, avoiding its duplication in the model prompt;
- returns `{ "cve_id", "context", "evidence", "mcp_metadata" }`.

**`run_agent(context, evidence, client, config, allow_dummy=False)`** then:

1. rejects dummy data unless the runner supplied `allow_dummy=True`;
2. removes fixture-only provenance from the LLM's view while retaining inventory facts when test mode is enabled;
3. calls `assess(package, client, config)`;
4. returns the decision plus model/provider metadata, input/prompt SHA-256 values, token usage, the audit snapshot, and `execution_ready: false`. If a hard model budget prevents a valid decision, it instead returns `ASSESSMENT_LIMITED` with no recommended remediation and preserves the source evidence. When both model responses fail validation, a narrowly scoped IBM AIX fallback may retain one exact, citation-checked service-pack fix as a conditional candidate. It returns `NEEDS_INPUT` until the installed fileset level is confirmed. Other validation failures remain `ASSESSMENT_LIMITED` and record a short `validation_failure` category for diagnosis.

**`assess(package, client, config)`** sends the structured package and the Pydantic `Decision` schema to either Bedrock or Azure OpenAI through `LLMClient.generate(messages, prompt)`. It permits one repair attempt if validation fails. The repair resends the package with a short validation correction, avoiding a second copy of the potentially large invalid model response. Before each call, the client checks remaining per-CVE input bytes, counted or conservatively estimated input tokens, and reserved output tokens. The 15,000 input-token limit is cumulative across internet lookup, initial assessment, and repair. If the remaining budget is insufficient, the CVE becomes `ASSESSMENT_LIMITED`; its raw evidence stays available and the UI labels any displayed source fix as unverified. Older saved byte/token-budget failures are presented the same way when loaded in the UI.

The required decision includes a verdict (`FIX_AVAILABLE`, `NOT_APPLICABLE`, `NEEDS_INPUT`, `INSUFFICIENT_EVIDENCE`, or `NO_FIX_AVAILABLE`), applicability, recommendations/candidates, exact supporting claims, blockers, and assessment notes.

**`validate_decision(decision, package)`** applies the final constraints:

- decision CVE must match the input;
- every evidence ID must exist and every quote must be an exact substring in that evidence record;
- non-workaround fixes need a cited target version or patch ID;
- `FIX_AVAILABLE` needs `AFFECTED`, a selected non-workaround fix, and compatibility support/blockers as appropriate;
- `NOT_APPLICABLE` and `NO_FIX_AVAILABLE` require positive evidence; `NEEDS_INPUT` must say what blocks the decision.

The runner writes `remediation_result.json`, extracts the reviewable public fields with `public_reasoning_record(...)`, and writes `reasoning.json` and the run's `reasoning_by_cve.json`.

## 8. Persist artifacts and optional database audit record

The runner continuously updates `aegis-cve-evidence/remediation/runs/grouped_remediation_<run_id>.json`. Each result embeds the source context, evidence, agent result, public reasoning, paths, status, and persistence status. It also writes `<run_id>/run_summary.json` at completion.

Oracle persistence is **off by default**, including in the UI path. A CLI/embedded run must set `persist_context=True` (`--persist-context` in the CLI) to call `try_persist_remediation_context(run_id, item, reasoning)`. That function calls `persist_remediation_context`, which opens Oracle through `context_manager.connect_database()`, creates/checks the table, and calls `save_remediation_context(...)`.

`remediation_context_values(...)` maps context + reasoning to normalized database columns such as `run_id`, `component_id`, `product`, component/app versions and paths, `verdict`, `reasoning_json`, and `assessed_at`. `save_remediation_context` updates an existing `(run_id, component_id, cve_id)` record or inserts one. A database error becomes `persistence_error`; the completed remediation assessment remains usable.

## 9. Convert the run artifact into the UI result DTO

**Status stream:** `selected_pipeline_events(run_id)` in `app.py` emits Server-Sent Events when the run record changes, ending on `completed` or `failed`. The React `useEffect` opens `EventSource` and updates `pipelineRun`; the user opens the completed results from the grouped view.

**Results endpoint:** `selected_pipeline_results(run_id)` loads the durable aggregate with `saved_run_aggregate(run_id)` and calls `public_remediation_results(aggregate)`.

`session_remediation_results(job_id)` loads every completed run belonging to the current upload session. Opening results after another selection reloads earlier runs from saved artifacts, so an earlier `FIX_AVAILABLE` card remains visible alongside new assessments. Each card retains its own run ID. A saved run can also be fetched directly by run ID after an API restart.

The **Previous fixes** button beside **Get remediation** calls `POST /api/jobs/<job_id>/previous-fixes`. It searches saved UI run artifacts across products and components, regardless of the current selection. It shows the newest saved `FIX_AVAILABLE` decision for each product, component, and CVE when its recommended remediation still passes schema, evidence ID, and exact quote checks. Stale synthetic inventory versions and Debian package identifiers on non-Debian hosts are excluded. The active run ID is excluded; each card retains its original run ID. If nothing qualifies, the view shows an empty state. API callers can request only selected grouped components by sending `scope: "selected"` and `selected_indices`.

`public_remediation_results` is the API-to-UI transformation. For each stored item it:

- chooses `reasoning` directly or falls back to `remediation_result.decision`;
- computes verdict counts and turns missing reasoning plus an error into `FAILED`;
- marks which `EV-xxx` records were cited by claims/remedies and exposes records relevant to the installed OS and Java branch, plus any cited records, in `evidence_records`; the complete raw source payload remains in the saved aggregate;
- includes the internet lookup page list once per URL, preferring a fetched and validated entry when duplicates exist;
- retains `source_fix_groups` for audit and selects one `primary_source_fix` by component and host level for the main card when the assessor has no recommendation; Debian/Ubuntu package versions are downranked for AIX hosts;
- extracts component, application, OS, version, path, lineage, runtime, and verification fields from the stored context;
- keeps persistence failures distinct from assessment failures.

Representative response:

```json
{
  "run_id": "ui-20261011-155342-510a3f5e",
  "status": "completed",
  "total": 1,
  "verdict_counts": {"FIX_AVAILABLE": 1},
  "uses_test_context": true,
  "results": [{
    "cve": "CVE-2021-45105",
    "product": "Apache Log4j2",
    "component_id": "CMP-8CA0CE20E2211BBBB75DFB9C",
    "component": "Thread Context Map",
    "component_version": "2.14.1",
    "component_path": "/opt/rms-foundation/lib/log4j-core-2.14.1.jar",
    "application_version": "TEST-RMS-2026.1",
    "verdict": "FIX_AVAILABLE",
    "recommended_remediation": {"route": "component_upgrade", "target_version": "..."},
    "evidence_route": "vendor_evidence",
    "evidence_records": [{"evidence_id": "EV-001", "source": "Apache", "cited": true}],
    "evidence_sources": {"EV-001": {"source": "Apache", "url": "..."}},
    "source_fix_groups": null,
    "lookup_sources": []
  }]
}
```

## 10. Render the remediation engine results

`showRemediationResults()` fetches `GET /api/jobs/<job_id>/remediation-results`, merges the returned runs by run ID, and changes the view to `results`.

`RemediationResultCard({ result })` renders one result as:

- CVE, verdict, applicability, product, run/component identity, and supplied application/component/OS context;
- component/application version and paths;
- assessment summary and error, if any;
- one assessed recommendation when available, otherwise the most relevant source-reported fix lead, with compatibility marked unverified;
- conditional candidate remedies in an expandable section;
- blockers, missing information, operational guidance, conflicts, assessment notes, and the relevant or cited evidence records with source links in an expandable audit section;
- deduplicated internet lookup pages with validation state when fallback ran.

The top-level results view also renders aggregate assessment and verdict counts. If `uses_test_context` is true, it visibly labels the run as test-context inventory. The displayed decision is an evidence-backed recommendation only; the agent's `execution_ready` is always `false`, and no part of this workflow executes the recommended remediation.

## Failure and state boundaries

| Boundary | Behaviour |
| --- | --- |
| Invalid upload | `/api/upload` returns a JSON `{ "error": ... }` with 400/413; the UI shows its error banner. |
| No usable CVE | `build_records` yields no records; upload is rejected. |
| Missing description/shared description | The CVE is returned as an unresolved enrichment status; it is not guessed by the classifier. |
| Bad LLM classification evidence | Exact-quote validation sets an error status and triggers at most one per-CVE repair. |
| Excel lock | Grouped data writes to a per-run fallback CSV and returns a warning. |
| API restart | Upload `JOBS` state is gone, but run status/results can be rebuilt from aggregate remediation JSON. |
| Missing context JSON | The pipeline continues with partial CSV context and exposes `context_missing` to the UI. |
| Adapter returns no records | The graph runs internet lookup, preserving adapter search notes and errors. No result alone proves non-applicability. |
| Internet lookup is partial or exhausted | It records errors/degradation and returns any validated facts already found; only those facts enter assessment evidence. |
| Per-CVE model limit | Requests beyond the remaining byte, input-token, or output-token budget are refused before inference; the CVE receives `ASSESSMENT_LIMITED` with no model recommendation, retains its source evidence, and later items continue. |
| Bad remediation decision | The agent repairs once. If both responses fail, it records the validation category; a single matching IBM AIX source fix can be retained as a cited conditional candidate, with fileset applicability unresolved. Otherwise the item remains `ASSESSMENT_LIMITED`. |
| Oracle persistence failure | Recorded separately as `persistence_error`; it does not turn a saved assessment into a failed remediation decision. |
