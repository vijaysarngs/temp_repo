# Function call sequence: from CSV upload to remediation card

This document follows one scanner CSV through the platform, function by function, in the
order the functions are called. For every function it gives the file and line, what the
function does, its parameters, and what it returns.

- **Starting point:** the user picks a CSV in the browser (the web workflow). The command-line
  entry points reuse the same functions; see [Appendix A](#appendix-a-command-line-entry-points).
- **End point:** the remediation result card rendered in the UI.
- **Verified against the code on:** 2026-10-19.
- Paths are relative to `aegis_engine_prod/`.
- Steps marked **(UI run: skipped)** exist in the code but are switched off by the options
  the web backend passes. They are listed so the sequence is complete.

Related documents: [aegis-cve-evidence/CODE_UNDERSTANDING.md](aegis-cve-evidence/CODE_UNDERSTANDING.md)
(design and behaviour per module) and [walkthrough.md](walkthrough.md) (a worked example).

---

## Contents

0. [The whole sequence on one screen](#0-the-whole-sequence-on-one-screen)
1. [Phase 1: upload and de-duplicate](#phase-1-upload-and-de-duplicate)
2. [Phase 2: enrichment (LLM product/component labels)](#phase-2-enrichment-llm-productcomponent-labels)
3. [Phase 3: grouping by product and component](#phase-3-grouping-by-product-and-component)
4. [Phase 4: starting a remediation run](#phase-4-starting-a-remediation-run)
5. [Phase 5: batch runner setup](#phase-5-batch-runner-setup)
6. [Phase 6: per-CVE workflow (LangGraph)](#phase-6-per-cve-workflow-langgraph)
   - [6.1 route](#61-node-route)
   - [6.2 vendor_evidence (source adapters)](#62-node-vendor_evidence-source-adapters)
   - [6.3 internet_lookup](#63-node-internet_lookup)
   - [6.4 assess (remediation agent)](#64-node-assess-remediation-agent)
   - [6.5 compatibility](#65-node-compatibility)
7. [Phase 7: saving each CVE's results](#phase-7-saving-each-cves-results)
8. [Phase 8: live progress in the browser](#phase-8-live-progress-in-the-browser)
9. [Phase 9: loading and showing results](#phase-9-loading-and-showing-results)
10. [Shared helpers called from many places](#10-shared-helpers-called-from-many-places)
11. [Main data shapes passed between functions](#11-main-data-shapes-passed-between-functions)
- [Appendix A: command-line entry points](#appendix-a-command-line-entry-points)
- [Appendix B: "previous fixes" path](#appendix-b-previous-fixes-path)

---

## 0. The whole sequence on one screen

Indentation means "called by the line above". `→` marks an HTTP request from the browser.

```text
BROWSER  UploadPanel.upload(file)                                     ui/src/App.jsx
  → POST /api/upload
      upload_csv(file)                                                app.py
        read_source_file(path)                                        cve_component_enrichment.py
        build_records(rows)                                           cve_component_enrichment.py
        generated_run_id()                                            app.py
        reusable_enrichment_files() → read_enriched_csv(path)         app.py

BROWSER  requestPipelineRun() → runEnrichment(mode)                   ui/src/App.jsx
  → POST /api/enrich            (or POST /api/enrich/reuse → reuse_enrichment → read_enriched_csv)
      enrich_range(payload)                                           app.py
        create_bedrock_client()                                       agent_utils.py
        classify_cves(client, records)                                cve_component_enrichment.py
          attempt(batch) → classify_batch → classification_prompt
                           → invoke_bedrock → model_requests.wait     agent_utils.py
                         → interpret_response → validate_classification → validate_fact → set_status
          (per unresolved CVE) attempt([record], feedback) → merge_retry
        component_rows(records, classifications) → component_identifier, result_reason
        write_csv(data/<run_id>.csv)
        grouped_payload(...)                                          app.py
          group_by_product_and_component(rows)                        group_cves_by_component.py
          write_grouped_csv(data/grouped_by_comp.csv)

BROWSER  finishGrouping(result); user ticks rows; runSelectedComponents()
  → POST /api/pipeline-runs
      start_selected_pipeline(payload)                                app.py
        pipeline_run(run_id) → saved_pipeline_run(run_id)
        write_csv(data/selected_components_<run_id>.csv)
        Thread → execute_selected_pipeline(run_id, selected_path)     app.py  (background)
          run_grouped_remediation(RemediationOptions(...))            remediation/run_grouped_remediation.py
            load_environment()
            read_grouped_csv(path) → _split, component_identifier
            select_items(...)
            latest_cve_per_component(items) → cve_sort_key
            host_inventory.load_inventory(path)                       context_gathered/host_inventory.py
            host_inventory.apply_host_inventory(items, hosts)
              find_host → _candidates, _host_score, _components_for, _matches
              context_for_item → _components_for, _python_package, _matches
            apply_run_identity(items, run_id)
            validate_model_credentials(config_path)
            load_config(path)                                         remediation/remedition_agent.py
            Internet_lookup.Config()
            provider_from_env(inventory)                              compatibility/context_provider.py
            build_workflow(...)                                       remediation/orchestrator.py
            token_ledger.reset()
            FOR EACH CVE ITEM:
              token_ledger.set_cve(cve); publish_progress()
              workflow.stream({"item": item})
                route            → vendor_route → context_os_names, select, os_sources
                vendor_evidence  → Engine.lookup                      src/aegis_evidence/engine.py
                                     cve_record → HTTP.json → HTTP.get
                                     record_context, os_sources, select
                                     <Adapter>.search(ctx) → <Adapter>._search(ctx)
                                       (on parser error) extract_evidence → _invoke
                                     result(...)                      src/aegis_evidence/models.py
                  needs_internet_lookup(item, evidence)?  yes → internet_lookup, no → assess
                internet_lookup  → run_fallback(row, host, ...)       Internet_lookup/pipeline.py
                                     FallbackRun.run → _run:
                                       _intake, _cache_lookup, _build_context,
                                       _plan_sources, _build_queries, _search,
                                       _fetch_pages, _validate_hits, _extract_all
                                       (steps.extract_facts → LLM.complete),
                                       _follow_references, _reconcile, _map_and_rank
                                     _emit_step → _build_result
                                   lookup_to_evidence(item, lookup)
                assess           → run_agent(context, evidence, LLMClient, config)
                                     prepare → _assessment_records → _relevant_records
                                     assess(package, client, config)
                                       LLMClient.generate → count_input_tokens, converse
                                       repair_quote_whitespace, require_version_for_not_applicable,
                                       normalize_fix_availability, normalize_source_fix_identifiers,
                                       validate_decision   (one repair retry on failure)
                compatibility    → assess_compatibility(...)          compatibility/agent.py
                                     provider.host_for, _component_for_context,
                                     evaluate_fix (×fix), _source_leads, summarize
              write_json(...) × evidence / result / compatibility / reasoning
              public_reasoning_record(...)
              (opt-in) try_persist_remediation_context → context_manager.*
              token_ledger.print_summary(...); publish_progress()
            write_json(grouped_remediation_<run_id>.json, run_summary.json)

BROWSER  useEffect live status: EventSource
  → GET /api/pipeline-runs/{run_id}/events → selected_pipeline_events → pipeline_run (every 1 s)
  → (fallback) GET /api/pipeline-runs/{run_id} → selected_pipeline_status

BROWSER  showRemediationResults()
  → GET /api/jobs/{job_id}/remediation-results
      session_remediation_results(job_id)                             app.py
        saved_run_aggregate(run_id)
        public_remediation_results(aggregate)
          _assessment_records, unique_lookup_sources, saved_run_compatibility,
          source_fix_groups, primary_source_fix → fix_major
BROWSER  mergeRemediationRuns → RemediationResultCard(result)          ui/src
```

---

## Phase 1: upload and de-duplicate

### 1.1 `UploadPanel.upload(file)` (browser)

[ui/src/App.jsx:631](ui/src/App.jsx#L631)

Sends the chosen file to the backend as `multipart/form-data` and hands the response to
`onUploaded`, which stores it as the current `dataset`.

| Param | Type | Meaning |
|---|---|---|
| `file` | `File` | The CSV the user picked. |

**Calls:** `POST /api/upload`.

### 1.2 `upload_csv(file)` — `POST /api/upload`

[app.py:630](app.py#L630)

Checks the upload, parses it, and groups the rows by CVE. Creates the **run ID** that names
every later artifact for this upload.

1. Rejects a missing file, a non-`.csv` name, more than 25 MB, an empty file, or non-UTF-8 text.
2. Writes the bytes to a temporary file (deleted afterwards), then calls `read_source_file`
   and `build_records`.
3. Stores the job in the in-memory `JOBS` dict under `job_id` (= `run_id`).

| Param | Type | Meaning |
|---|---|---|
| `file` | `fastapi.UploadFile \| None` | The uploaded CSV. |

**Returns:** JSON with `job_id`, `run_id`, `filename`, `original_count`, `unique_count`,
`duplicate_count`, `skipped_count`, `columns`, `rows` (one original row per unique CVE), and
`existing_enrichment` (the newest reusable enrichment CSV in `data/`, or `null`).

### 1.3 `read_source_file(path, sheet_name=None)`

[cve_component_enrichment.py:97](cve_component_enrichment.py#L97)

Reads a CSV (or XLSX) into a list of row dicts. Rejects missing headers, duplicate headers,
rows with more values than headers, and files with no data rows.

| Param | Type | Meaning |
|---|---|---|
| `path` | `str \| Path` | File to read; must be `.csv` or `.xlsx`. |
| `sheet_name` | `str \| None` | XLSX worksheet; default is the active sheet. Unused for CSV. |

**Returns:** `list[dict]`, one dict per data row keyed by header.

### 1.4 `build_records(rows)`

[cve_component_enrichment.py:132](cve_component_enrichment.py#L132)

De-duplicates the scanner rows **by CVE ID**. A row can name several CVEs; each CVE gets one
record that keeps every row it appeared in.

- CVE IDs come only from columns named like `CVE`, `CVE ID`, `CVE IDs` or `Vulnerability ID`.
- Application and OS come from columns like `Primary Application`/`Application` and
  `OS Name`/`Operating System`.
- Description-like columns (`Description`, `Summary`, `Technical Details`…) become
  `sources`, each with an ID `row<N>:col<M>`. If one description names several CVEs it is
  marked `shared_cve_ids`, because it cannot safely be assigned to each of them.
- Rows with no valid CVE are returned as `skipped`.

| Param | Type | Meaning |
|---|---|---|
| `rows` | `list[dict]` | Output of `read_source_file`. |

**Returns:** `(records, skipped)`. See [record shape](#record-from-build_records).

Helpers it uses (same file):

| Function | Params | What it does |
|---|---|---|
| `clean(value)` | any | `str(value).strip()`, `""` for `None`. |
| `normalized(value)` | any | NFKC-normalizes, collapses whitespace, casefolds. Formatting only, never wording. |
| `header_key(value)` | header text | `normalized` with `_` and `-` turned into spaces, so `CVE_ID` = `cve id`. |
| `meaningful(value)` | any | `False` for blanks and placeholders such as `-`, `n/a`, `unknown`. |
| `get_value(row, *aliases)` | row dict, accepted header names | First meaningful value whose header matches one of the aliases. |

### 1.5 `generated_run_id()`

[app.py:61](app.py#L61)

**Returns:** a run ID such as `ui-20261016-045350-6ae10ae1` (UTC time + 8 random hex chars).
No parameters.

### 1.6 `reusable_enrichment_files()` → `read_enriched_csv(path)`

[app.py:101](app.py#L101), [app.py:78](app.py#L78)

Lists earlier enrichment outputs in `data/` (skipping `grouped_by_comp.csv` and
`selected_components_*`) so the UI can offer to reuse one instead of paying for a new
enrichment. `read_enriched_csv` validates that a file has the enrichment columns and
recomputes `Component ID` for older files that lack it.

| Function | Param | Meaning |
|---|---|---|
| `read_enriched_csv` | `path` (`str \| Path`) | Saved enrichment CSV. Raises `ValueError` if it is not one. |

**Returns:** `reusable_enrichment_files` → list of `{filename, row_count, modified_at}`,
newest first. `read_enriched_csv` → list of row dicts with every `COMPONENT_COLUMNS` key.

---

## Phase 2: enrichment (LLM product/component labels)

### 2.1 `requestPipelineRun()` → `runEnrichment(mode)` (browser)

[ui/src/App.jsx:831](ui/src/App.jsx#L831), [ui/src/App.jsx:836](ui/src/App.jsx#L836)

`requestPipelineRun` asks whether to reuse a saved enrichment when one exists; otherwise it
calls `runEnrichment("fresh")`. `runEnrichment` posts to the backend with a 30-minute
timeout and passes the result to `finishGrouping`.

| Param | Type | Meaning |
|---|---|---|
| `mode` | `"fresh" \| "reuse"` | `fresh` → `POST /api/enrich` with `{job_id, start, count}`; `reuse` → `POST /api/enrich/reuse` with `{job_id, filename}`. |

### 2.2 `enrich_range(payload)` — `POST /api/enrich`

[app.py:702](app.py#L702)

Enriches a slice of the uploaded CVE records, saves the result, and groups it.

1. Validates `start`/`count` against the number of records.
2. Creates a Bedrock client **only if** at least one selected record has a description that
   is not shared between CVEs (otherwise there is nothing the model may classify).
3. `classify_cves` → `component_rows` → `write_csv(data/<job_id>.csv)` → `grouped_payload`.

| Param (`payload` keys) | Type | Meaning |
|---|---|---|
| `job_id` | `str` | ID returned by `/api/upload`. |
| `start` | `int` | 1-based index of the first CVE record to enrich. |
| `count` | `int` | How many records to enrich. |

**Returns:** the `grouped_payload` dict plus `start` and `count`.

**Alternative:** `reuse_enrichment(payload)` ([app.py:745](app.py#L745)) — `POST /api/enrich/reuse`.
Takes `{job_id, filename}`, checks the filename is in `reusable_enrichment_files()`, reads it
with `read_enriched_csv`, and goes straight to `grouped_payload`. No model calls.

### 2.3 `create_bedrock_client()`

[agent_utils.py:36](agent_utils.py#L36)

Builds a `bedrock-runtime` boto3 client from [config.py](config.py) (`.env`): explicit access
keys if set, otherwise an AWS profile. Timeouts: 10 s connect, 60 s read; one attempt (no
automatic retries). Raises if `USE_BEDROCK` is false. No parameters.

**Returns:** a boto3 `bedrock-runtime` client. The connection is first tested by the first request.

### 2.4 `classify_cves(client, records, batch_size=5, max_batches=None, max_tokens=6000, diagnostics=None, caller=None)`

[cve_component_enrichment.py:360](cve_component_enrichment.py#L360)

Labels each CVE's **product** and **component** from its own description text, in batches.

1. Records with no description → `MISSING_DESCRIPTION`; with only shared descriptions →
   `AMBIGUOUS_SOURCE`. Neither is sent to the model.
2. The rest are sent in batches of `batch_size` through the inner `attempt(batch, feedback)`.
3. Any CVE that is not `SUPPORTED` after the batch call gets **one** individual retry with
   feedback, and the two results are combined by `merge_retry`.

| Param | Type | Meaning |
|---|---|---|
| `client` | Bedrock client \| `None` | Passed to `caller`. |
| `records` | `list[dict]` | Records from `build_records`. |
| `batch_size` | `int` | CVEs per model call. |
| `max_batches` | `int \| None` | Testing limit; later batches become `NOT_PROCESSED`. `None` = all. |
| `max_tokens` | `int` | Output-token limit per model call. |
| `diagnostics` | `list \| None` | If given, each attempt's request IDs and response (or error type) are appended. |
| `caller` | callable \| `None` | Replaces `classify_batch` (used by tests). |

**Returns:** `dict[cve_id, classification]`. Classification statuses: `SUPPORTED`, `PARTIAL`,
`NEEDS_ENRICHMENT`, `EVIDENCE_MISMATCH`, `CONFLICTING_EVIDENCE`, `MISSING_DESCRIPTION`,
`AMBIGUOUS_SOURCE`, `MODEL_ERROR`, `MODEL_OUTPUT_MISSING`, `MODEL_OUTPUT_TRUNCATED`,
`MODEL_OUTPUT_DUPLICATE`, `NOT_PROCESSED`.

Inner `attempt(batch, feedback=None)`: calls `caller`, then `interpret_response`. If the call
raises, every CVE in the batch becomes `MODEL_ERROR` instead of being dropped.

### 2.5 `classify_batch(client, records, max_tokens=6000, retry_feedback=None)`

[cve_component_enrichment.py:211](cve_component_enrichment.py#L211)

Builds the Anthropic-on-Bedrock request: one user message from `classification_prompt`, and a
forced tool call to `submit_detailed_component_classifications` (a strict JSON schema).

| Param | Type | Meaning |
|---|---|---|
| `client` | Bedrock client | |
| `records` | `list[dict]` | The batch. |
| `max_tokens` | `int` | Output limit. |
| `retry_feedback` | `dict \| None` | `{cve_id: {previous_validated_result, instruction}}` on a retry. |

**Returns:** the raw model response dict from `invoke_bedrock`.

`classification_prompt(records, retry_feedback=None)` ([line 173](cve_component_enrichment.py#L173))
returns the instruction text followed by a JSON payload of each record's `cve_id`, `sources`
and `application_context`. The rules require labels to be **contiguous quotes** of the source text.

### 2.6 `invoke_bedrock(client, body, purpose="model request")`

[agent_utils.py:69](agent_utils.py#L69)

Sends one `InvokeModel` request with `performanceConfigLatency="optimized"`; if the model
rejects that setting it retries once at standard latency. Calls `model_requests.wait()`
before each request (process-wide pacing, see [section 10](#10-shared-helpers-called-from-many-places)).

| Param | Type | Meaning |
|---|---|---|
| `client` | Bedrock client | |
| `body` | `dict` | Anthropic Messages request body. |
| `purpose` | `str` | Label for the console log. |

**Returns:** parsed JSON response body. Re-raises any failure after logging elapsed time.

### 2.7 `interpret_response(response, records)` → `validate_classification` → `validate_fact` → `set_status`

[cve_component_enrichment.py:300](cve_component_enrichment.py#L300), [276](cve_component_enrichment.py#L276), [235](cve_component_enrichment.py#L235), [264](cve_component_enrichment.py#L264)

Turns the model's tool call into validated classifications. **This is where the model is
checked, not trusted.**

| Function | Params | What it does |
|---|---|---|
| `interpret_response(response, records)` | model response; the batch records | Collects tool-call items, matches them to requested CVEs. A CVE with zero or several items gets `MODEL_OUTPUT_MISSING`/`_TRUNCATED`/`_DUPLICATE`. Exactly one item → `validate_classification`. |
| `validate_classification(item, record)` | one model item; its record | Checks the schema, validates each field (`product`, `component`, `affected_symbol`, `source_path`) with `validate_fact`, checks `component_kind`, and drops a product that is only the protocol name. |
| `validate_fact(value, sources)` | `{label, evidence:[{source_id, quote}]}`; `{source_id: text}` | A label is kept only if each quote is found verbatim (after whitespace/case normalization) in the cited source **and** the label appears as whole words inside the quote. Returns `(fact, "")` or `(None, reason)`. |
| `set_status(result)` | classification dict | Sets `EVIDENCE_MISMATCH` (any issue), `SUPPORTED` (product and component), `PARTIAL` (some label) or `NEEDS_ENRICHMENT`. |
| `require_keys(value, keys)` | any; key tuple | `True` only for a dict with exactly those keys. |
| `empty_result(cve_id)` | CVE ID | Blank classification with status `NEEDS_ENRICHMENT`. |

### 2.8 `merge_retry(previous, repaired)`

[cve_component_enrichment.py:334](cve_component_enrichment.py#L334)

Combines the first result and the retry result for one CVE. A validated label from the first
attempt is kept if the retry drops it. If both attempts give different validated labels, the
status becomes `CONFLICTING_EVIDENCE`.

| Param | Type | Meaning |
|---|---|---|
| `previous` | classification dict | First (batch) result. |
| `repaired` | classification dict | Single-CVE retry result. |

**Returns:** merged classification dict.

### 2.9 `component_rows(records, classifications)`

[cve_component_enrichment.py:422](cve_component_enrichment.py#L422)

Produces the **enriched CSV rows**: one row per (CVE, application/OS context). Missing labels
become `Unidentified` / `Unspecified component`. Evidence quotes, symbols and paths are joined
with ` | `. Rows are sorted by application, product, component, OS and CVE.

| Param | Type | Meaning |
|---|---|---|
| `records` | `list[dict]` | From `build_records`. |
| `classifications` | `dict` | From `classify_cves`. |

**Returns:** `list[dict]` with the `COMPONENT_COLUMNS` keys (see [enriched row](#enriched--grouped-row)).

| Helper | Params | What it does |
|---|---|---|
| `component_identifier(product, component)` ([line 44](cve_component_enrichment.py#L44)) | two strings | Stable ID `CMP-` + first 24 hex chars of SHA-256 of `product␟component`. The same function exists in `run_grouped_remediation.py` so both agree. |
| `result_reason(result)` ([line 415](cve_component_enrichment.py#L415)) | classification | Human-readable `Classification Reason` text. |

### 2.10 `write_csv(path, rows, columns)`

[cve_component_enrichment.py:461](cve_component_enrichment.py#L461)

Writes rows to a UTF-8-with-BOM CSV (Excel-friendly), creating parent folders.

| Param | Type | Meaning |
|---|---|---|
| `path` | `str \| Path` | Output file. |
| `rows` | `list[dict]` | Rows to write. |
| `columns` | `list[str]` | Header order. |

---

## Phase 3: grouping by product and component

### 3.1 `grouped_payload(job_id, enriched_rows, source, source_filename)`

[app.py:126](app.py#L126)

Groups the enriched rows, stores them on the job, writes `data/grouped_by_comp.csv`, and
builds the API response. If Excel has that file locked, it writes
`data/grouped_by_comp_<job_id>.csv` instead and returns a warning.

| Param | Type | Meaning |
|---|---|---|
| `job_id` | `str` | Upload job. |
| `enriched_rows` | `list[dict]` | Output of `component_rows` or `read_enriched_csv`. |
| `source` | `str` | `"new_enrichment"` or `"saved_enrichment"`. |
| `source_filename` | `str` | Name of the enrichment CSV used. |

**Returns:** `{run_id, source, source_filename, columns, rows, grouped: {columns, rows, filename, warning}}`.

### 3.2 `group_by_product_and_component(rows)`

[group_cves_by_component.py:21](group_cves_by_component.py#L21)

Merges rows that have **exactly the same** `Product` and `Component`. List-like columns
(`CVE IDs`, `Application`, `Evidence`, …) are unioned in order without duplicates; the
`Component ID` is recomputed for the group.

| Param | Type | Meaning |
|---|---|---|
| `rows` | `list[dict]` | Enriched rows. |

**Returns:** grouped rows sorted by product then component. `_values(value)` splits a
` | `-joined cell back into a list.

### 3.3 `write_grouped_csv(path, rows)`

[group_cves_by_component.py:47](group_cves_by_component.py#L47)

Calls `group_by_product_and_component(rows)` and writes the result to `path`.

| Param | Type | Meaning |
|---|---|---|
| `path` | `str \| Path` | Usually `data/grouped_by_comp.csv`. |
| `rows` | `list[dict]` | **Ungrouped** enriched rows (it groups them itself). |

**Returns:** the `Path` written.

### 3.4 `finishGrouping(result)` (browser)

[ui/src/App.jsx:818](ui/src/App.jsx#L818)

Stores the enriched and grouped data, clears any previous selection and run, and switches to
the grouped table, where the user ticks the component rows to remediate.

---

## Phase 4: starting a remediation run

### 4.1 `runSelectedComponents()` (browser)

[ui/src/App.jsx:871](ui/src/App.jsx#L871)

Posts `{job_id, selected_indices}` (indexes into the grouped rows, sorted) to
`POST /api/pipeline-runs` and stores the returned run as `pipelineRun`, which starts the
live-status effect ([Phase 8](#phase-8-live-progress-in-the-browser)).

### 4.2 `start_selected_pipeline(payload)` — `POST /api/pipeline-runs`

[app.py:764](app.py#L764)

1. Validates the job and the indexes (whole numbers, in range, de-duplicated).
2. Refuses a second run for the same upload while one is queued/running (HTTP 409).
3. Chooses the run ID: the upload's ID for the first run, a fresh `generated_run_id()` for
   later runs, so earlier results stay reviewable. `pipeline_run(run_id)` is used to check
   that an ID is free.
4. Writes the chosen rows to `data/selected_components_<run_id>.csv` (`write_csv`).
5. Registers the run in `PIPELINE_RUNS` with status `queued` and starts
   `execute_selected_pipeline` on a **daemon thread**.

| Param (`payload` keys) | Type | Meaning |
|---|---|---|
| `job_id` | `str` | Upload job. |
| `selected_indices` | `list[int]` | Grouped-row indexes the user selected. |

**Returns:** HTTP 202 with the run record (`run_id`, `status`, `selected_count`,
`selected_components`, `selected_input`, `context_source`, …).

### 4.3 `execute_selected_pipeline(run_id, selected_path)` (background thread)

[app.py:160](app.py#L160)

Marks the run `running`, then calls the batch runner **in the same Python process**:

```python
run_grouped_remediation(RemediationOptions(
    input_csv=Path(selected_path),
    latest_per_component=True,   # one CVE (the newest ID) per selected component
    continue_on_error=True,      # one failed CVE does not stop the others
    run_id=run_id,
    allow_dummy=True,            # synthetic inventory hosts are allowed
    inventory=REMEDIATION_INVENTORY,  # AEGIS_HOST_INVENTORY or inventory/sterling_rocky8.yaml
    progress_callback=lambda progress: run.update({"workflow_progress": progress}),
))
```

Afterwards it checks that `remediation/runs/grouped_remediation_<run_id>.json` exists and sets
`status` to `completed` (with a message) or `failed` (with the exception text).

| Param | Type | Meaning |
|---|---|---|
| `run_id` | `str` | Run ID chosen in 4.2. |
| `selected_path` | `Path` | The `selected_components_<run_id>.csv` file. |

**Returns:** nothing; it updates `PIPELINE_RUNS[run_id]`.

---

## Phase 5: batch runner setup

All functions in this phase are in
[aegis-cve-evidence/remediation/run_grouped_remediation.py](aegis-cve-evidence/remediation/run_grouped_remediation.py)
unless noted.

### 5.1 `RemediationOptions(**kwargs)`

[run_grouped_remediation.py:27](aegis-cve-evidence/remediation/run_grouped_remediation.py#L27)

The options object shared by the CLI and the web backend. Unknown keys raise `TypeError`.

| Option | Default | UI run | Meaning |
|---|---|---|---|
| `input_csv` | `data/grouped_by_comp.csv` | selected CSV | Grouped CSV to read. |
| `rows`, `start_row` | `None`, `2` | defaults | Limit to a range of CSV rows (header is row 1). |
| `product` | `None` | — | Only product groups containing this text. |
| `cve` | `None` | — | Only these exact CVE IDs. |
| `all_cves` | `False` | — | Every CVE (instead of one per product). |
| `latest_per_component` | `False` | **True** | Only the highest CVE ID per component. |
| `output_dir` | `remediation/runs` | default | Where artifacts go. |
| `run_id` | generated | upload ID | Names the run folder and aggregate file. |
| `upload_id` | `None` | **job ID** | Stored in `CVE_RUN.upload_id`. |
| `config` | `remediation/agent_configs.json` | default | Agent provider and budgets. |
| `fetch_only` | `False` | — | Collect evidence, skip the agent. |
| `persist_context` | `False` | `AEGIS_PERSIST_RUNS` | Also save to Oracle `CVE_RUN`, `CVE_EVIDENCE` and `CVE_ASSESSMENT`. |
| `include_related` | `False` | — | Also query publishers detected from the CVE text. |
| `dry_run` | `False` | — | Print selected CVEs and stop. |
| `continue_on_error` / `fail_fast` | `False` | **True** / — | Error handling across CVEs. |
| `allow_dummy` | `False` | **True** | Allow `is_dummy` fixtures; treat supplied inventory facts as authoritative. |
| `context_dir` | `None` | — | Load per-CVE `*.context.json` files. |
| `inventory` | `None` | **inventory YAML** | Host inventory file/folder. |
| `max_output_tokens` | `None` | — | Override the agent's output limit (≥ 1000). |
| `progress_callback` | `None` | **set** | Receives each progress snapshot. |

### 5.2 `run_grouped_remediation(args)`

[run_grouped_remediation.py:502](aegis-cve-evidence/remediation/run_grouped_remediation.py#L502)

The batch runner. It prepares one **item** per CVE, compiles the workflow once, runs the
workflow for each item, and saves everything. The calls below (5.3–5.12) happen in order.

| Param | Type | Meaning |
|---|---|---|
| `args` | `RemediationOptions` | See 5.1. |

**Returns:** the aggregate dict (also saved as `grouped_remediation_<run_id>.json`) with
`status` = `completed` / `completed_with_errors` (or `failed` when it stops early).

It first validates option combinations (for example `--cve` with `--rows` is refused) and the
run ID format.

### 5.3 `load_environment()`

[run_grouped_remediation.py:107](aegis-cve-evidence/remediation/run_grouped_remediation.py#L107)

Loads the repository `.env` (without overriding existing variables) and removes empty
`AWS_PROFILE`/`AWS_DEFAULT_PROFILE` so boto3 doesn't look for a profile named `""`.

### 5.4 `read_grouped_csv(path)`

[run_grouped_remediation.py:357](aegis-cve-evidence/remediation/run_grouped_remediation.py#L357)

Turns each grouped row into one **item per CVE** in its `CVE IDs` cell. Each item carries a
**partial context** built only from the CSV (OS names, application names, product, component,
classification). Missing component IDs are recomputed with `component_identifier`.

| Param | Type | Meaning |
|---|---|---|
| `path` | `Path` | Grouped CSV; must have `Product`, `Component`, `CVE IDs`. |

**Returns:** `list[item]` (see [item shape](#item-from-read_grouped_csv)). `_split(value)` splits
` | ` cells into a de-duplicated list.

### 5.5 `select_items(all_items, rows, start_row, product, one_per_product=False, cves=None)`

[run_grouped_remediation.py:411](aegis-cve-evidence/remediation/run_grouped_remediation.py#L411)

Filters items by row range, product text and CVE set; removes duplicate
`(component_id, cve)` pairs; optionally keeps one item per product group.

| Param | Type | Meaning |
|---|---|---|
| `all_items` | `list[item]` | From `read_grouped_csv`. |
| `rows` | `int \| None` | Number of CSV rows to include. |
| `start_row` | `int` | First CSV row number. |
| `product` | `str \| None` | Case-insensitive substring of `product_group`. |
| `one_per_product` | `bool` | Keep the first item per product group. `False` in the UI run. |
| `cves` | `set[str] \| None` | Exact CVE filter (ignores the row range). |

**Returns:** selected items, each with `selected_source_rows`, sorted by CSV row.

### 5.6 `latest_cve_per_component(items)`

[run_grouped_remediation.py:445](aegis-cve-evidence/remediation/run_grouped_remediation.py#L445)

Keeps, for each `component_id`, the item with the highest CVE (year, then sequence number via
`cve_sort_key(cve)`). **This is why a UI run assesses one CVE per selected component.**

| Param | Type | Meaning |
|---|---|---|
| `items` | `list[item]` | Selected items. |

### 5.7 (UI run: skipped) `apply_context_directory(items, context_dir)`

[run_grouped_remediation.py:183](aegis-cve-evidence/remediation/run_grouped_remediation.py#L183)

- Replaces each item's partial context with the best-scoring per-CVE `*.context.json`
  file in `context_dir` (scored on product group, product and component). Returns the
  CVEs it could not match.
- (`apply_test_inventory` and the synthetic profiles were removed on 2026-10-20; see
  `redundant.md`.)

### 5.8 `host_inventory.load_inventory(path)` → `host_inventory.apply_host_inventory(items, hosts)`

[context_gathered/host_inventory.py:24](aegis-cve-evidence/context_gathered/host_inventory.py#L24), [245](aegis-cve-evidence/context_gathered/host_inventory.py#L245)

Replaces each item's partial CSV context with a **host-inventory context**: the real (or
synthetic) installed versions, paths, packages and OS facts for that application.

**`load_inventory(path)`** reads one YAML file, or every `*.yaml`/`*.yml` in a folder
(`schema_version` must be 1). Each host gets its file's `shared_components` appended and the
private keys `_file`, `_synthetic`, `_collected_at`, `_warning`. Observed hosts are sorted
before synthetic ones.

| Param | Type | Meaning |
|---|---|---|
| `path` | `Path` | Inventory file or folder. |

**Returns:** `list[host dict]`.

**`apply_host_inventory(items, hosts)`** — for each item, `find_host` then `context_for_item`.
Items with no matching host keep the CSV context and get `context_missing = True`.

| Param | Type | Meaning |
|---|---|---|
| `items` | `list[item]` | Modified in place (`context`, `context_file`, `context_missing`, `os_names`). |
| `hosts` | `list[host dict]` | From `load_inventory`. |

**Returns:** how many items received an inventory context.

**`find_host(item, hosts, product=None)`** ([line 100](aegis-cve-evidence/context_gathered/host_inventory.py#L100))
— picks the `(host, application)` whose application name matches the item's application.
When an application spans several hosts it prefers, in order: observed over synthetic, the host
that knows most about the product (`_host_score`: version 4 > present 3 > python/absent 2 >
gap 1 > nothing 0), no open gap, more recorded detail, earlier in the file.

**`context_for_item(item, host, application, hosts=None)`** ([line 130](aegis-cve-evidence/context_gathered/host_inventory.py#L130))
— builds the context passed to every later step. It contains **only the component(s) matching
the item's product**: the copy the application uses first; otherwise a Python package entry,
an explicit "not found" observation, or nothing. Gaps, other applications and the same product
on sibling hosts become `missing_context` lines. `request.context_kind` is
`OBSERVED_HOST_INVENTORY` or `SYNTHETIC_TEST_INVENTORY`.

| Param | Type | Meaning |
|---|---|---|
| `item` | item dict | The CVE item. |
| `host` | host dict | Chosen host. |
| `application` | dict | The host's matching application entry. |
| `hosts` | `list \| None` | All hosts, used to mention sibling hosts. |

**Returns:** context dict (see [context shape](#context-per-item)).

Small helpers in the same file:

| Function | What it does |
|---|---|
| `_norm(value)` | Lower-case, keep only `a-z 0-9 . +`, collapse spaces. |
| `_matches(aliases, product, exact=False)` | An alias equals the product, or appears in it as whole words. |
| `_item_applications(item)` | The item's application names. |
| `_candidates(item, hosts)` | Every `(host, application)` whose application name matches. |
| `_components_for(host, product)` | Host components whose `products` aliases match. |
| `_python_package(host, product)` | `(name, version, packages)` from the host's pip list or `not_listed`. |
| `_host_score(host, product)` | 0–4 knowledge score used by `find_host`. |

### 5.9 `apply_run_identity(items, run_id)`

[run_grouped_remediation.py:301](aegis-cve-evidence/remediation/run_grouped_remediation.py#L301)

Writes `run_id`, `component_id` and `component_names` into every item's `context.request`, and
`run_id`/`component_id` into the response, **after** the inventory replaced the context.

| Param | Type | Meaning |
|---|---|---|
| `items` | `list[item]` | Modified in place. |
| `run_id` | `str` | |

### 5.10 `validate_model_credentials(config_path)`

[run_grouped_remediation.py:119](aegis-cve-evidence/remediation/run_grouped_remediation.py#L119)

For the Bedrock provider, builds a boto3 session the same way the agent will and fails early
if no AWS credentials are found. Skipped with `fetch_only`.

| Param | Type | Meaning |
|---|---|---|
| `config_path` | `Path` | `agent_configs.json`. |

### 5.11 `load_config(path)`

[remediation/remedition_agent.py:100](aegis-cve-evidence/remediation/remedition_agent.py#L100)

Reads `agent_configs.json`, applies `LLM_PROVIDER` from the environment, fills default budgets,
checks they are positive integers, and loads the prompt file (`remediation_prompt_compact.txt`)
into `config["prompt"]`.

| Param | Type | Meaning |
|---|---|---|
| `path` | `Path` | Config JSON. |

**Returns:** config dict: `provider`, `prompt`, `max_output_tokens` (8000),
`max_total_output_tokens` (15000), `max_total_input_bytes` (36000),
`max_total_input_tokens` (15000), `max_input_characters` (250000), provider settings.

Back in the runner: with `allow_dummy`, a section **"10. PROVIDED CONTEXT HANDLING"** is
appended to the prompt, telling the model to treat the supplied inventory facts as authoritative.

### 5.12 Workflow construction

| Call | Where | What it does |
|---|---|---|
| `Internet_lookup.Config()` | [Internet_lookup/config.py:46](aegis-cve-evidence/Internet_lookup/config.py#L46) | Lookup settings and per-CVE budgets (6 searches, 12 fetches, 15 LLM calls, 15 000 input bytes, 240 s deadline). The runner points `cache_dir`, `log_dir` and `out_dir` into the run folder. |
| `provider_from_env(inventory)` | [compatibility/context_provider.py:169](aegis-cve-evidence/compatibility/context_provider.py#L169) | Returns `YamlContextProvider(inventory)`, or `OracleContextProvider()` when `AEGIS_COMPAT_CONTEXT_SOURCE=oracle`. Gives the compatibility agent the **whole** host, not just one component. |
| `build_workflow(...)` | [remediation/orchestrator.py:196](aegis-cve-evidence/remediation/orchestrator.py#L196) | Compiles the LangGraph graph described in Phase 6. |
| `token_ledger.reset()` | [remediation/token_ledger.py:92](aegis-cve-evidence/remediation/token_ledger.py#L92) | Clears the per-process record of model-call tokens. |

**`build_workflow(*, include_related=False, config=None, allow_dummy=False, engine=None, lookup_fn=run_fallback, lookup_config=None, client=None, progress_callback=None, compatibility_provider=None, check_compatibility=True)`**

| Param | Type | Meaning |
|---|---|---|
| `include_related` | `bool` | Passed to `Engine.lookup`. |
| `config` | `dict \| None` | Agent config. `None` (fetch-only) makes `assess` and `compatibility` no-ops. |
| `allow_dummy` | `bool` | Passed to `run_agent`. |
| `engine` | `Engine \| None` | Evidence engine; default `Engine()` (one HTTP cache for the whole run). |
| `lookup_fn` | callable | Internet lookup entry point; default `run_fallback`. |
| `lookup_config` | `Internet_lookup.Config \| None` | Lookup settings. |
| `client` | LLM client \| `None` | Test hook; default is a new `LLMClient` per CVE. |
| `progress_callback` | callable \| `None` | Receives `{stage, status, ...}` events (the runner's `workflow_event`). |
| `compatibility_provider` | provider \| `None` | Host-fact source for the compatibility node. |
| `check_compatibility` | `bool` | Turns the compatibility node off. |

**Returns:** a compiled LangGraph graph:

```text
START → route ─┬─ "vendor_evidence" → vendor_evidence ─┬─ needs_internet_lookup? yes → internet_lookup → assess
               │                                       └─ no  ─────────────────────────────────────→ assess
               └─ "internet_lookup" → internet_lookup → assess
assess → compatibility → END
```

The runner then writes the initial aggregate file and enters the per-CVE loop. For each item:
`token_ledger.set_cve(cve)`, `publish_progress()`, create the artifact folder
`runs/<run_id>/<product>/<component_id>/<CVE>/`, and call
`workflow.stream({"item": item}, stream_mode="updates")`. Each node's output is merged into the
state; evidence is written to `mcp_evidence.json` as soon as a node returns it.

---

## Phase 6: per-CVE workflow (LangGraph)

Nodes are closures defined inside `build_workflow` in
[remediation/orchestrator.py](aegis-cve-evidence/remediation/orchestrator.py). Each takes the
workflow `state` dict and returns only the keys it changes. Every node reports progress with
`emit(stage, status, **details)` → `progress_callback`.

**State keys:** `item`, `route`, `vendor`, `evidence`, `vendor_evidence`, `lookup_result`,
`assessment`, `compatibility`.

### 6.1 Node `route`

[orchestrator.py:213](aegis-cve-evidence/remediation/orchestrator.py#L213)

Calls `vendor_route(state["item"])` and returns `{"route", "vendor"}`.

#### `vendor_route(item)`

[orchestrator.py:46](aegis-cve-evidence/remediation/orchestrator.py#L46)

Decides which publisher to ask first, or whether to go straight to the Internet lookup.

1. The **CVE's own product** (scanner product + context component products) decides first.
   `Oracle Java/JDK/JRE` → `oracle java`; `Oracle Linux` → `oracle linux`; other `Oracle` → `oracle`.
2. Then regex patterns: IBM/AIX/OpenJ9 → `ibm`, Apache/Tomcat → `apache`, PostgreSQL, SQLite,
   OpenSSL, Red Hat, Rocky, Debian, Ubuntu, SUSE.
3. The **hosting application's** product is used only when the scanner product is
   `Unidentified`.
4. A generic "linux" product uses the host OS distribution, else `auto`.
5. If the host OS has a publisher adapter (`os_sources`), route to `vendor_evidence` anyway.
6. Otherwise route to `internet_lookup`.

| Param | Type | Meaning |
|---|---|---|
| `item` | item dict | Uses `vendor`, `products`, `components` and the context's application/component products and OS. |

**Returns:** `(route, vendor)`, for example `("vendor_evidence", "apache")` or
`("internet_lookup", "auto")`.

`context_os_names(item)` ([line 37](aegis-cve-evidence/remediation/orchestrator.py#L37)) returns
the context's `server.os_names` (falling back to the item's), cleaned into a list.

### 6.2 Node `vendor_evidence` (source adapters)

[orchestrator.py:219](aegis-cve-evidence/remediation/orchestrator.py#L219)

Collects the installed versions recorded in the context and calls

```python
evidence_engine.lookup(cve, state["vendor"], ", ".join(products), ", ".join(os_names),
                       include_related=include_related, installed_version=...)
```

**Returns:** `{"evidence": result, "vendor_evidence": result}`.

#### `Engine.lookup(cve, vendor, product=None, os_name=None, description=None, include_related=False, installed_version=None)`

[src/aegis_evidence/engine.py:94](aegis-cve-evidence/src/aegis_evidence/engine.py#L94)

Runs every relevant **publisher adapter** for one CVE and combines their evidence.

1. `cve_id(cve)` — normalizes and validates the ID.
2. `cve_record(http, cve)` — CVE.org record (`{}` on failure).
3. `record_context(record)` — references, English description, affected product names.
4. `os_sources(os_name)` — publisher(s) for the host OS.
5. `select(vendor, description, product, os_name, refs, include_related)` — adapter names
   for the vendor. If the vendor is unknown but the OS has a publisher, the OS adapter alone is used.
6. Host OS adapters are appended (for example Rocky Linux for a Rocky host).
7. Builds a `Context` and calls `SOURCES[name](self.http).search(ctx)` for each adapter. An
   adapter that raises is recorded in `errors` and the others continue.
8. Adds hints (no CVE.org data, nothing matched, no fix found, unspecified Linux distribution,
   Oracle Linux ≠ Rocky).
9. `result(...)` builds the output.

| Param | Type | Meaning |
|---|---|---|
| `cve` | `str` | CVE ID. |
| `vendor` | `str` | From `vendor_route`: an alias (`ibm`, `apache`, `oracle java`…) or `auto`. |
| `product` | `str \| None` | Product names, comma-joined. |
| `os_name` | `str \| None` | Host OS names, comma-joined. |
| `description` | `str \| None` | Overrides the CVE.org description used for `auto` detection. |
| `include_related` | `bool` | Also run publishers detected from the description/product/references. |
| `installed_version` | `str \| None` | Installed version(s); some adapters use it as a hint. |

**Returns:** evidence result (see [evidence shape](#evidence-result-from-enginelookup)).

Functions it calls:

| Function | File | Params | What it does |
|---|---|---|---|
| `cve_id(value)` | [models.py:11](aegis-cve-evidence/src/aegis_evidence/models.py#L11) | `str` | Uppercases; raises `ValueError` unless it is `CVE-YYYY-NNNN…`. |
| `cve_record(http, cve)` | [registry.py:6](aegis-cve-evidence/src/aegis_evidence/registry.py#L6) | `HTTP`, CVE | `GET https://cveawg.mitre.org/api/cve/<CVE>`. Discovery only; never treated as proof of a fix. |
| `record_context(record)` | [registry.py:14](aegis-cve-evidence/src/aegis_evidence/registry.py#L14) | CVE.org JSON | `(references, description, products)` from the CNA and ADP containers. |
| `os_sources(os_name)` | [engine.py:44](aegis-cve-evidence/src/aegis_evidence/engine.py#L44) | OS text | AIX/VIOS → IBM, Oracle Linux, Rocky, Red Hat, Debian, Ubuntu, SUSE; plain "linux" → Rocky Linux. |
| `select(vendor, description="", product="", os_name="", refs=None, include_related=False)` | [engine.py:61](aegis-cve-evidence/src/aegis_evidence/engine.py#L61) | see names | Maps a vendor alias to adapter names via `ALIASES`. For `auto`, matches whole-word aliases in the text and asks each adapter's `matches_reference` about the CVE references. Raises `ValueError` for an unknown vendor. |
| `Context(...)` | [models.py:39](aegis-cve-evidence/src/aegis_evidence/models.py#L39) | `cve, vendor, product, os_name, description, references, installed_version` | Data class handed to every adapter. |
| `result(cve, vendor, evidence, errors, searched, hints=None)` | [models.py:49](aegis-cve-evidence/src/aegis_evidence/models.py#L49) | adapter outputs | De-duplicates evidence, sorts newest first, sets `status` (`evidence_found` / `no_verified_remediation_found`) and `coverage` (`partial` if any adapter failed, else `searched_configured_sources`). |

#### `Source.search(context)` → `<Adapter>._search(context)`

[sources/base.py:37](aegis-cve-evidence/src/aegis_evidence/sources/base.py#L37)

Every adapter inherits `search`. It tracks the URLs the adapter requests, then calls the
adapter's own `_search`. If `_search` raises (usually because a vendor page layout changed),
it calls the strict LLM fallback `extract_evidence` on those same pages. If the fallback also
fails, it raises a combined error, which `Engine.lookup` records as a source error.

| Param | Type | Meaning |
|---|---|---|
| `context` | `Context` | CVE, product, OS, references, installed-version hint. |

**Returns:** `list[Evidence]` (see [Evidence fields](#evidence-record)).

Base-class helpers:

| Method | What it does |
|---|---|
| `matches_reference(url)` (classmethod) | `True` for an `https` URL whose host is in the adapter's `hosts`. |
| `referenced(context)` | The CVE references that point at this publisher. |
| `document_or_none(url)` | Fetches and parses a page; `None` on HTTP 404 (the vendor has no page for this CVE). |

Each adapter implements `_search(self, context) -> list[Evidence]`. One line each (details in
[CODE_UNDERSTANDING.md §15](aegis-cve-evidence/CODE_UNDERSTANDING.md#15-each-adapter-in-detail)):

| Adapter (`name`) | File | What `_search` reads |
|---|---|---|
| IBM | [sources/ibm.py](aegis-cve-evidence/src/aegis_evidence/sources/ibm.py) | IBM security bulletins found from references and IBM's search API (`_discover_bulletins`); parses remediation tables by column meaning; follows "consult bulletin X" pointers. |
| Oracle Critical Patch Updates | [sources/oracle_cpu.py](aegis-cve-evidence/src/aegis_evidence/sources/oracle_cpu.py) | Oracle CVE→advisory map, CPU risk matrices; `_jdk_releases` adds Java SE CPU release builds. |
| Oracle Linux | [sources/oracle_linux.py](aegis-cve-evidence/src/aegis_evidence/sources/oracle_linux.py) | `linux.oracle.com/cve/<CVE>.html` and ELSA errata RPM tables. |
| Rocky Linux | [sources/rocky.py](aegis-cve-evidence/src/aegis_evidence/sources/rocky.py) | Apollo v2 advisory API (0-indexed pages) → fixed RPMs. |
| Red Hat | [sources/redhat.py](aegis-cve-evidence/src/aegis_evidence/sources/redhat.py) | CVE page statement + CSAF documents → fixed packages per product branch. |
| Debian | [sources/debian.py](aegis-cve-evidence/src/aegis_evidence/sources/debian.py) | Security tracker status and fixed-version tables. |
| Ubuntu | [sources/ubuntu.py](aegis-cve-evidence/src/aegis_evidence/sources/ubuntu.py) | `ubuntu.com/security/<CVE>` package/release/status table (uses `table_grid` for row spans). |
| SUSE | [sources/suse.py](aegis-cve-evidence/src/aegis_evidence/sources/suse.py) | SUSE CVE page "Fixed package version" table. |
| Apache | [sources/apache.py](aegis-cve-evidence/src/aegis_evidence/sources/apache.py) | Log4j security page, Tomcat `security-N.html` pages, other Apache pages; `_add_latest` adds the newest release per branch. |
| OpenSSL | [sources/openssl.py](aegis-cve-evidence/src/aegis_evidence/sources/openssl.py) | OpenSSL vulnerabilities page, "from X before Y" per branch. |
| PostgreSQL | [sources/postgresql.py](aegis-cve-evidence/src/aegis_evidence/sources/postgresql.py) | `postgresql.org/support/security/<CVE>/` affected/fixed table. |
| SQLite | [sources/sqlite.py](aegis-cve-evidence/src/aegis_evidence/sources/sqlite.py) | `sqlite.org/cves.html` row for the CVE. |
| TIBCO | [sources/tibco.py](aegis-cve-evidence/src/aegis_evidence/sources/tibco.py) | Advisory references (often blocked by Cloudflare → reported as an error). |
| Eclipse | [sources/eclipse.py](aegis-cve-evidence/src/aegis_evidence/sources/eclipse.py) | OMR pull requests, OpenJ9 GitHub releases, IBM Semeru fix table. |

#### HTTP layer used by the adapters

[src/aegis_evidence/http.py](aegis-cve-evidence/src/aegis_evidence/http.py)

| Function | Params | What it does |
|---|---|---|
| `HTTP(cache_dir=None, ttl_hours=6, offline=False)` | cache folder (`AEGIS_CACHE_DIR` or `.cache/aegis-evidence`), cache lifetime, offline mode | Creates the client. One instance is shared by all adapters in a run. |
| `HTTP.get(url, max_bytes=12_000_000)` ([line 50](aegis-cve-evidence/src/aegis_evidence/http.py#L50)) | URL, size limit | Only `https` hosts in `ALLOWED` (also checked after redirects). Serves from the disk cache when fresh; otherwise `page_requests.wait()` then fetches, retrying twice on 429/5xx/timeouts. Raises `FetchError` (with `status`). |
| `HTTP.json(url)` / `HTTP.document(url)` | URL | `get` + JSON parse / lxml HTML parse. |
| `clean(value)` | string or element | Collapsed text. |
| `table_rows(table)` | lxml table | Cell texts per row (spans not expanded). |
| `table_grid(table)` | lxml table | Rows with `rowspan`/`colspan` expanded into a full grid. |
| `section(node, heading)` | document, heading text | Text under the first h2/h3/h4 containing `heading`. |

#### `extract_evidence(http, context, source_name, urls, cause)` (LLM fallback)

[src/aegis_evidence/llm_fallback.py:153](aegis-cve-evidence/src/aegis_evidence/llm_fallback.py#L153)

Called **only** when an adapter's parser raised. Sends up to 4 of the pages the adapter
tried (≤ 12 000 characters each, centred on the CVE) to the model, then accepts the answer only
if it is exactly the Evidence shape and **every factual field is a verbatim excerpt of its page**.
Anything else raises. Disabled with `AEGIS_ADAPTER_LLM_FALLBACK=false`.

| Param | Type | Meaning |
|---|---|---|
| `http` | `HTTP` | Used to re-read the pages (normally cached). |
| `context` | `Context` | CVE and hints. |
| `source_name` | `str` | The adapter's `name`; the model must return it unchanged. |
| `urls` | `list[str]` | Pages the adapter requested plus its references. |
| `cause` | `Exception` | The parser error (its message is sent to the model). |

**Returns:** `list[Evidence]`, each with a note that the LLM fallback was used.

`_invoke(system, user)` ([line 71](aegis-cve-evidence/src/aegis_evidence/llm_fallback.py#L71))
does the model call for `LLM_PROVIDER` = `bedrock` (Converse), `azure_openai` or `anthropic`,
records tokens with `token_ledger.from_usage("adapter_llm_fallback", ...)`, and returns the
text. It raises on an incomplete response.

#### Edge decision: `needs_internet_lookup(item, evidence)`

[orchestrator.py:123](aegis-cve-evidence/remediation/orchestrator.py#L123)

Chooses the edge after `vendor_evidence`. Returns `True` (go to `internet_lookup`) when:

1. there are no evidence records; or
2. no record mentions the CVE's product (for example only unrelated IBM OS filesets); or
3. the installed copy is packaged separately (AIX Toolbox, `/opt/freeware`, bundled jar,
   virtualenv, upstream build) **and** every record is an OS fileset/package fix.

| Param | Type | Meaning |
|---|---|---|
| `item` | item dict | Products and context components (`package_lineage`, `executable_path`). |
| `evidence` | evidence result | From `Engine.lookup`. |

### 6.3 Node `internet_lookup`

[orchestrator.py:234](aegis-cve-evidence/remediation/orchestrator.py#L234)

Runs the search-driven lookup and merges its verified facts with the publisher evidence.

1. Builds `CveRow(cve_id, component=product or component, status=<vendor evidence status>, extra={"csv_component": component})` and `HostProfile(os=...)`.
2. If the graph routed here **directly** (no vendor evidence yet) and the host OS has a
   publisher, it first calls `Engine.lookup` for the OS publisher, so the host OS is always checked.
3. Calls `run_fallback(row, host, cfg=..., console=False, mcp_evidence=vendor_evidence)` with
   `rank_options=False` and `llm_reconcile=False` (the assessor reads only verified facts, so
   those two model calls would be wasted).
4. `lookup_to_evidence(item, lookup)` converts the result to evidence records.
5. Vendor evidence records come first, lookup records after; searched sources, errors and notes
   are combined.

**Returns:** `{"lookup_result", "evidence", "route": "internet_lookup"}`.

#### `run_fallback(row, host=None, mcp_evidence=None, cfg=None, *, llm=None, search=None, fetcher=None, use_cache=True, console=True)`

[Internet_lookup/pipeline.py:434](aegis-cve-evidence/Internet_lookup/pipeline.py#L434)

The lookup's single public entry point. Validates the CVE ID (an invalid one returns a
`LookupResult` with `status="error"`), then runs `FallbackRun(...).run()`. **Never raises.**

| Param | Type | Meaning |
|---|---|---|
| `row` | `CveRow` | `cve_id`, `component`, `component_type`, `status`, `extra`. |
| `host` | `HostProfile \| None` | `os`, `tl`, `sp`, `packages`. |
| `mcp_evidence` | `dict \| None` | Vendor evidence already collected (used by `_intake`). |
| `cfg` | `Config \| None` | Settings and budgets. |
| `llm`, `search`, `fetcher` | objects \| `None` | Test hooks; defaults are `LLM`, `make_search(...)`, `Fetcher`. |
| `use_cache` | `bool` | Read/write the 7-day result cache. |
| `console` | `bool` | Print progress lines (the orchestrator passes `False`). |

**Returns:** `LookupResult` (the orchestrator calls `.to_dict()`).

#### `FallbackRun.run()` → `_run()` steps, in order

[Internet_lookup/pipeline.py:79](aegis-cve-evidence/Internet_lookup/pipeline.py#L79)

`FallbackRun.__init__` ([line 28](aegis-cve-evidence/Internet_lookup/pipeline.py#L28)) creates
the `RunLogger`, `Budget`, `LLM`, search provider and `Fetcher`. Each step runs inside
`guarded(name, detail, fn)`, which logs it and turns an exception into a recorded error so the
next step still runs (a degraded result, never a crash). `expired()` stops the collection steps
after `run_deadline_s` (240 s).

| # | Step | Line | What it does |
|---|---|---|---|
| 1 | `_intake` | [110](aegis-cve-evidence/Internet_lookup/pipeline.py#L110) | Logs which fields are missing. |
| 2 | `_cache_lookup` | [122](aegis-cve-evidence/Internet_lookup/pipeline.py#L122) | Returns a cached `LookupResult` (key = CVE + component + host, `_cache_path`) if younger than 7 days; the run then jumps to emit. |
| 3 | `_build_context` | [141](aegis-cve-evidence/Internet_lookup/pipeline.py#L141) | Logs component/type/host. |
| 4 | `_plan_sources` | [145](aegis-cve-evidence/Internet_lookup/pipeline.py#L145) | Component type from `heuristic_component_type(component, host_os)`; if unclear, one small model call `steps.classify_component`. `plan_for(type)` gives the site targets. |
| 5 | `_build_queries` | [158](aegis-cve-evidence/Internet_lookup/pipeline.py#L158) | `build_queries(cve_id, component, plan, host_label, context_term)`: broad queries first, then `site:` queries for authoritative domains. |
| 6 | `_search` | [170](aegis-cve-evidence/Internet_lookup/pipeline.py#L170) | Runs queries through the search provider (each takes a `searches` budget unit). Keeps only allowlisted URLs (`tier_of`), drops URLs naming another CVE (`other_cve_in_url`) and IBM i results on an AIX host. Ranks by tier; keeps the top `max_pages_to_fetch_from_search` (2) plus spares. |
| 7 | `_fetch_pages` | [249](aegis-cve-evidence/Internet_lookup/pipeline.py#L249) | `_fetch_many(urls, "search")` in parallel through `Fetcher.fetch`; replaces failed fetches with spares. |
| 8 | `_validate_hits` | [264](aegis-cve-evidence/Internet_lookup/pipeline.py#L264) | Accepts only pages containing the **exact** CVE ID (`exact_cve_regex`). |
| 9 | `_extract_all` | [300](aegis-cve-evidence/Internet_lookup/pipeline.py#L300) | `_extract_pages` → `_extract_one` → `steps.extract_facts` per accepted page, in parallel. |
| 10 | `_follow_references` | [304](aegis-cve-evidence/Internet_lookup/pipeline.py#L304) | Fetches tier 1/2 references the facts mention, one hop. `max_follow_refs` is 0 by default, so this normally does nothing. |
| 11 | `_reconcile` | [327](aegis-cve-evidence/Internet_lookup/pipeline.py#L327) | `steps.reconcile(facts)`. (`llm_resolve` is off in the workflow.) |
| 12 | `_map_and_rank` | [338](aegis-cve-evidence/Internet_lookup/pipeline.py#L338) | In the workflow (`rank_options=False`): `steps.deterministic_options(rec)` only, no model call. |
| — | `_emit_step` → `_build_result` | [410](aegis-cve-evidence/Internet_lookup/pipeline.py#L410), [362](aegis-cve-evidence/Internet_lookup/pipeline.py#L362) | Builds the `LookupResult` (status `ok` / `partial` / `not_found` / `error`, `needs_human_reasons`, `verified_facts`, `sources`, `stats`), writes it to `out_dir`, and caches it if `ok`/`partial`. |

Functions called by those steps:

| Function | File | Params | What it does |
|---|---|---|---|
| `heuristic_component_type(component, host_os=None)` | [sources.py:142](aegis-cve-evidence/Internet_lookup/sources.py#L142) | label, OS | Rule-based type: `open_source`, `ibm_aix`, `postgresql`, `other`, or `None` if unsure. |
| `steps.classify_component(llm, component, cve_id, status)` | [steps.py:370](aegis-cve-evidence/Internet_lookup/steps.py#L370) | | One fast-model call returning one of the four types. |
| `plan_for(component_type)` | [sources.py:158](aegis-cve-evidence/Internet_lookup/sources.py#L158) | type | `Plan` with `site_domains` and a note. |
| `build_queries(cve_id, component, plan, host_label, context_term=None)` | [sources.py:169](aegis-cve-evidence/Internet_lookup/sources.py#L169) | | List of search strings; CSV text is quoted and length-bounded (`_query_term`). |
| `make_search(cfg, llm, log)` | [search.py:237](aegis-cve-evidence/Internet_lookup/search.py#L237) | | `DDGSSearch` (default, `CVE_FALLBACK_SEARCH=ddgs`), `DuckDuckGoSearch`, `BraveSearch` or `AnthropicWebSearch`. Each has `.search(query, max_results) -> list[SearchHit]`. |
| `tier_of(url)` | [sources.py:45](aegis-cve-evidence/Internet_lookup/sources.py#L45) | URL | 1 vendor/distro/upstream, 2 NVD/CVE.org/CISA, 3 aggregator, `None` = not allowlisted (never fetched). |
| `other_cve_in_url(url, cve_id)` | [sources.py:60](aegis-cve-evidence/Internet_lookup/sources.py#L60) | | The other CVE ID if the URL is about a different CVE. |
| `exact_cve_regex(cve_id)` | [sources.py:70](aegis-cve-evidence/Internet_lookup/sources.py#L70) | | Regex that does not match longer IDs (`CVE-2006-6698` ≠ `CVE-2006-66980`). |
| `Fetcher.fetch(url, via="search")` | [fetch.py:97](aegis-cve-evidence/Internet_lookup/fetch.py#L97) | URL, `"search"`/`"reference"` | Allowlist check (also after redirects), `fetches` budget, `page_requests.wait()`, streamed GET with 5 s connect / 20 s total / 1.5 MB limits, HTML → text (`html_to_text`). Returns a `Page` (`ok`, `text` or `error`). |
| `steps.extract_facts(llm, cfg, log, page, cve_id)` | [steps.py:58](aegis-cve-evidence/Internet_lookup/steps.py#L58) | | Sends a 2 500-character window (`evidence_window`) to the fast model, parses JSON (`parse_json`), builds `ExtractedFacts`, then `_verify_provenance`. |
| `_verify_provenance(f, page_text, cve_id, log, tag)` | [steps.py:160](aegis-cve-evidence/Internet_lookup/steps.py#L160) | | **Drops** every fixed version and stance whose evidence snippet is not on the page, and CVSS numbers not in the CVE's own section (`target_cve_section`). Can recover an exact IBM remediation row (`_ibm_fix_row`) or a table row split by a spanning cell (`_table_row_excerpt`). |
| `steps.reconcile(all_facts)` | [steps.py:206](aegis-cve-evidence/Internet_lookup/steps.py#L206) | `list[ExtractedFacts]` | Rule-based merge, best tier first: description, product, affected versions, severity (tier 2 > 1 > 3), de-duplicated fixes, stances, and `summary_stance` (`fix_available`, `mixed`, `wontfix`, `not_affected`, `unknown`). |
| `steps.deterministic_options(rec)` | [steps.py:322](aegis-cve-evidence/Internet_lookup/steps.py#L322) | `Reconciled` | Up to 3 "upgrade to X" options, all `applicable_to_host="unverified"`, `confidence="low"`. |
| `LLM.complete(tier, system, user, max_tokens, purpose)` | [llm.py:92](aegis-cve-evidence/Internet_lookup/llm.py#L92) | `"fast"`/`"deep"`, prompts, output limit, label | Checks the input-byte budget, counts input tokens (`count_input_tokens`), reserves the call in the `Budget`, `model_requests.wait()`, calls Bedrock Converse / Azure / Anthropic, records usage. Returns the text. |
| `Budget.take(kind)` / `reserve_model_call(...)` | [config.py:105](aegis-cve-evidence/Internet_lookup/config.py#L105) | | Raise `BudgetExceeded` once a per-CVE limit is reached. |

#### `lookup_to_evidence(item, lookup)`

[orchestrator.py:154](aegis-cve-evidence/remediation/orchestrator.py#L154)

Turns verified lookup facts into evidence records the agent can cite. Only facts from pages
that were **fetched and validated** are used. Each fixed version becomes a record with
`source="Internet lookup"`, `evidence_kind="validated_page_excerpt"`, and the page excerpt as
both `remediation` and `verbatim_excerpt`; a vendor stance becomes a record with
`vendor_stance` and its excerpt.

| Param | Type | Meaning |
|---|---|---|
| `item` | item dict | CVE, products, component. |
| `lookup` | `dict` | `LookupResult.to_dict()`. |

**Returns:** evidence result with `searched_sources=["internet_lookup"]`, `coverage="partial"`,
`notes` = the lookup's `needs_human_reasons`, and the full lookup under `internet_lookup`.

### 6.4 Node `assess` (remediation agent)

[orchestrator.py:281](aegis-cve-evidence/remediation/orchestrator.py#L281)

Subtracts what the Internet lookup already spent (`llm_input_bytes`,
`llm_input_tokens_reserved`) from this CVE's agent budget. If nothing is left it returns
`budget_limited_result(...)` without a model call; otherwise it calls

```python
run_agent(item["context"], state["evidence"], client or LLMClient(assessment_config),
          assessment_config, allow_dummy)
```

**Returns:** `{"assessment": result}`. No-op when `config` is `None` (fetch-only).

All functions below are in
[remediation/remedition_agent.py](aegis-cve-evidence/remediation/remedition_agent.py).

#### `run_agent(context, evidence, client, config, allow_dummy=False)`

[remedition_agent.py:1058](aegis-cve-evidence/remediation/remedition_agent.py#L1058)

1. `prepare(context, evidence)` → assessment package.
2. `contains_dummy(package)`: synthetic data without `allow_dummy` raises.
3. With synthetic data and `allow_dummy`, the model sees
   `normalize_test_context_for_assessment(context)` (fixture markers removed); the saved snapshot
   keeps the original.
4. `assess(package, client, config)`.
5. On `RemediationBudgetExceeded` → `budget_limited_result(..., kind)`.
   On `RemediationValidationFailed` → `aix_source_fallback(package)` if it applies, else
   `budget_limited_result(..., "validation")`.

| Param | Type | Meaning |
|---|---|---|
| `context` | context dict | From the host inventory. |
| `evidence` | evidence result | From `vendor_evidence` and/or `internet_lookup`. |
| `client` | `LLMClient` | Model client with its own per-CVE budgets. |
| `config` | `dict` | From `load_config` (with lookup spend subtracted). |
| `allow_dummy` | `bool` | Permit synthetic contexts. |

**Returns:** assessment result dict: `is_dummy`, `execution_ready` (always `False`),
`decision` (see [Decision](#decision-remediation-agent-output)), `model_id`, `provider`,
`prompt_sha256`, `assessed_at`, `usage`, `input_token_count_modes`, `input_sha256`,
`input_snapshot` (the package), `validation_note`. Limited results add `assessment_limited`,
`assessment_limit_reason`, `validation_failure`, `validation_failure_detail` and use verdict
`ASSESSMENT_LIMITED`.

#### `prepare(context, evidence)`

[remedition_agent.py:467](aegis-cve-evidence/remediation/remedition_agent.py#L467)

Checks that context and evidence are for the same CVE, filters the evidence to what can
describe **this** host (`_assessment_records`), and numbers the kept records `EV-001`,
`EV-002`, … using their **original** position, so citations map back to the full records in the
UI. Adds a note when a distribution only had fixes for other OS releases.

| Param | Type | Meaning |
|---|---|---|
| `context` | context dict | Must have a `response` object. |
| `evidence` | evidence result | Must have `cve`/`cve_id` and an `evidence` (or `advisories`) list. |

**Returns:** `{cve_id, context, evidence: [{evidence_id, source_data}], mcp_metadata}`.

#### `_assessment_records(records, context)` → `_relevant_records(indexed, context, installed)`

[remedition_agent.py:372](aegis-cve-evidence/remediation/remedition_agent.py#L372), [267](aegis-cve-evidence/remediation/remedition_agent.py#L267)

Deterministic, conservative evidence filtering (also reused by the results API):

- IBM Semeru and Java SE release rows only for installed Java branches.
- Distribution packages only for the host's OS major release (no Rocky 9 RPMs on Rocky 8).
- Upstream fixes only for the installed major branch, when one exists for it.
- Only the host's CPU architecture (+ `noarch`); no debug builds.
- Only the RPM names and Java branches the inventory says are installed.
- Package rows from one advisory and release merged into one record; long remediation text
  trimmed to 600 characters.
- On AIX, only the single best IBM AIX fix for the host's level and TL.

| Param | Type | Meaning |
|---|---|---|
| `records` | `list[dict]` | Evidence records. |
| `context` | context dict | Host OS, architecture, components, products. |

**Returns:** `list[(original_index, record)]`.

Helpers: `_aix_host_level(context)` → `(major, minor, tl)` or `None`; `_host_os_major(context)`
→ e.g. `"8"`; `_record_os_major(record)` → major number from the record's `release`.

#### `assess(package, client, config)`

[remedition_agent.py:932](aegis-cve-evidence/remediation/remedition_agent.py#L932)

The model call with **at most one repair**.

1. Refuses a package larger than `max_input_characters`.
2. Builds one compact user message: the package with empty context fields removed
   (`_without_empty`) and the `Decision` JSON schema without titles (`_schema_without_titles`).
3. Up to 2 attempts: `client.generate(messages, config["prompt"])` → parse `Decision` →
   post-process → `validate_decision`.
4. If attempt 1 fails, attempt 2 resends the same package plus a short, specific correction
   (no echo of the bad answer).
5. If attempt 2 fails: a citation error → `downgrade_invalid_citations` (returns a safe
   `INSUFFICIENT_EVIDENCE` result); twice truncated → `RemediationBudgetExceeded("output_tokens")`;
   otherwise `RemediationValidationFailed`.

| Param | Type | Meaning |
|---|---|---|
| `package` | `dict` | From `prepare`. |
| `client` | `LLMClient` | |
| `config` | `dict` | Needs `prompt`, `max_input_characters`. |

**Returns:** `(Decision, usage_list)`.

Post-processing applied to every parsed answer, in this order:

| Function | Line | What it does |
|---|---|---|
| `repair_quote_whitespace(decision, package)` | [895](aegis-cve-evidence/remediation/remedition_agent.py#L895) | A quote that differs from its record only in whitespace is replaced by the record's exact text. No model call. |
| `require_version_for_not_applicable(decision, package)` | [679](aegis-cve-evidence/remediation/remedition_agent.py#L679) | `NOT_APPLICABLE` without a recorded installed version (or explicit absence) becomes `NEEDS_INPUT`. |
| `normalize_fix_availability(decision)` | [704](aegis-cve-evidence/remediation/remedition_agent.py#L704) | An affected `NEEDS_INPUT` answer with a complete, cited fix candidate becomes `FIX_AVAILABLE` (compatibility stays `UNVERIFIED`). |
| `normalize_source_fix_identifiers(decision, package)` | [615](aegis-cve-evidence/remediation/remedition_agent.py#L615) | If the model joined release and fix ("AIX 7.2 TL05 SP13"), uses the record's exact `fixed_version` ("SP13"); then `_ground_identifiers` adds a quote for an identifier found in another field of the same record (e.g. an APAR in `notes`). |
| `validate_decision(decision, package)` | [557](aegis-cve-evidence/remediation/remedition_agent.py#L557) | The final gate (below). |

#### `validate_decision(decision, package)`

[remedition_agent.py:557](aegis-cve-evidence/remediation/remedition_agent.py#L557)

Raises `ValueError` (or `CitationValidationError`) unless:

- the CVE matches;
- every non-workaround remedy has a `target_version` or `patch_id`, and that identifier appears
  in its `fix_support` quotes;
- every claim cites an existing `EV-nnn` with a quote of ≥ 3 characters that is an **exact
  substring** of that record;
- `FIX_AVAILABLE` has `AFFECTED`, a non-workaround recommended remedy, quoted compatibility
  evidence if `SUPPORTED`, and a blocker if `UNVERIFIED`;
- only `FIX_AVAILABLE` selects a remediation;
- `NOT_APPLICABLE` / `NO_FIX_AVAILABLE` have supporting claims; `NO_FIX_AVAILABLE` quotes an
  explicit no-fix statement; `NOT_APPLICABLE` has `NOT_AFFECTED`; `NEEDS_INPUT` lists blockers.

| Param | Type | Meaning |
|---|---|---|
| `decision` | `Decision` | Parsed model answer. |
| `package` | `dict` | From `prepare`. |

#### `LLMClient(config)` and `LLMClient.generate(messages, prompt)`

[remedition_agent.py:131](aegis-cve-evidence/remediation/remedition_agent.py#L131), [180](aegis-cve-evidence/remediation/remedition_agent.py#L180)

The constructor creates a Bedrock (`BEDROCK_MODEL_ID`, 120 s read timeout, one attempt) or Azure
OpenAI client and sets this CVE's remaining budgets. `generate`:

1. Raises `RemediationBudgetExceeded("input_bytes")` if the request exceeds the remaining bytes.
2. `count_input_tokens(...)` (provider count, or a byte estimate); raises
   `RemediationBudgetExceeded("input_tokens")` if over the remaining tokens.
3. Sets `max_tokens = min(max_output_tokens, remaining output)`; raises
   `RemediationBudgetExceeded("output_tokens")` if none is left.
4. Deducts the budgets, `model_requests.wait()`, calls Converse / chat completions, and records
   usage with `token_ledger.from_usage("remediation_agent", ...)`.

| Param | Type | Meaning |
|---|---|---|
| `messages` | `list[{role, content}]` | Conversation (one user message). |
| `prompt` | `str` | System prompt. |

**Returns:** `(text, usage, stop_reason)`.

#### Fallback results

| Function | Line | Params | What it does |
|---|---|---|---|
| `budget_limited_result(context, evidence, client, config, allow_dummy, kind, validation_failure=None, usage=None, validation_detail=None)` | [1015](aegis-cve-evidence/remediation/remedition_agent.py#L1015) | `kind` = `input_bytes`/`input_tokens`/`output_tokens`/`validation` | Reviewable `ASSESSMENT_LIMITED` result that keeps the evidence and snapshot but recommends nothing. |
| `aix_source_fallback(package)` | [785](aegis-cve-evidence/remediation/remedition_agent.py#L785) | package | For IBM AIX product groups only: if exactly one IBM AIX service-pack record matches the host level, returns a validated `NEEDS_INPUT` decision with that fix as a candidate and the fileset level as the blocker. Otherwise `None`. |
| `downgrade_invalid_citations(decision, package)` | [743](aegis-cve-evidence/remediation/remedition_agent.py#L743) | | Removes unsupported claims and any remedy relying on one; forces `INSUFFICIENT_EVIDENCE` / `UNKNOWN`. |
| `validation_failure_kind(error)` | [863](aegis-cve-evidence/remediation/remedition_agent.py#L863) | exception | `unsupported_citation`, `invalid_schema`, `uncited_fix_identifier` or `invalid_decision`. |
| `contains_dummy(value)` | [512](aegis-cve-evidence/remediation/remedition_agent.py#L512) | any | `True` if any nested dict has `is_dummy: true`. |
| `normalize_test_context_for_assessment(context)` | [518](aegis-cve-evidence/remediation/remedition_agent.py#L518) | context | Copy without `is_dummy`/`context_kind`, fixture status values mapped to `VERIFIED`/`COMPLETE`, synthetic warnings removed. |

### 6.5 Node `compatibility`

[orchestrator.py:306](aegis-cve-evidence/remediation/orchestrator.py#L306)

Checks the agent's fixes against the **full** host inventory. Deterministic and offline; an
exception becomes `{"status": "FAILED", ...}` and never changes the assessment.

**Returns:** `{"compatibility": result}`.

#### `assess_compatibility(remediation, context, *, provider=None, evidence=None, knowledge=None, proposals=None, host=None)`

[compatibility/agent.py:577](aegis-cve-evidence/compatibility/agent.py#L577)

1. `load_knowledge()` — curated product rules from `knowledge.yaml` (cached).
2. `provider.host_for(context)` — the full host entry (`_pick`: exact hostname first; by
   application only if exactly one host matches).
3. `_component_for_context(context, host)` — the context's component merged with its full host entry.
4. `evaluate_fix(...)` for the recommended remedy and each candidate. With no recommendation,
   for **source leads** (`_source_leads`: fixed versions from cited records, same branch as
   installed preferred).
5. `summarize(...)` builds a one-paragraph summary.

| Param | Type | Meaning |
|---|---|---|
| `remediation` | `dict` | `run_agent` result (`decision`, `input_snapshot`). |
| `context` | context dict | The CVE's context. |
| `provider` | context provider | Default `provider_from_env()`. |
| `evidence` | evidence result \| `None` | Used to find all packages an advisory ships. |
| `knowledge` | `dict \| None` | Override for `knowledge.yaml`. |
| `proposals` | `list[dict] \| None` | Extra fixes to test (not used by the workflow). |
| `host` | `dict \| None` | Override the host lookup. |

**Returns:** `{schema_version, agent: "compatibility", cve_id, checked_at, context_source, host,
host_found, remediation_verdict, status, summary, evaluations, execution_ready: False}`.
`status` is the recommended fix's status, or `NOT_EVALUATED`.

#### `evaluate_fix(fix, component, host, context, *, knowledge, evidence=None, cve=None)`

[compatibility/agent.py:184](aegis-cve-evidence/compatibility/agent.py#L184)

Runs every check for one fix on one installed copy. Each check is `PASS`, `WARN`, `FAIL` or
`UNKNOWN` with the facts it used:

`fix_identifier`, `installed_version`, `ownership_route` (RPM vs. vendor directory vs. bundled),
`platform_match` (RPM built for this OS major and architecture), `upgrade_direction` (newer than
installed), `branch`, `runtime_requirements` (Java minimum), `dependencies`,
`public_availability`, `sibling_packages`, `other_copies`, `application_support`.

| Param | Type | Meaning |
|---|---|---|
| `fix` | `dict` | A remedy: `route`, `target_version`, `patch_id`, optional `product`. |
| `component` | `dict` | Merged component from `_component_for_context`. |
| `host` | `dict \| None` | Full host entry. |
| `context` | context dict | Fallback for OS and architecture. |
| `knowledge` | `dict` | Product rules. |
| `evidence` | `list \| None` | Evidence records. |
| `cve` | `str \| None` | For suggested commands. |

**Returns:** `{route, target, scheme, product_rules, component, installed_version, ownership,
status, checks, required_actions, verification_commands}`. `status` from `overall_status`:
any `FAIL` → `INCOMPATIBLE`; a critical `UNKNOWN` → `UNVERIFIED`; any `WARN`/`UNKNOWN` →
`COMPATIBLE_WITH_WARNINGS`; else `COMPATIBLE`.

Helpers (same file unless noted):

| Function | What it does |
|---|---|
| `product_rules(names, knowledge)` | First `knowledge.yaml` product whose aliases match. |
| `target_scheme(target, product_key, rules)` | `rpm`, `aix_sp`, `advisory`, `java`, `upstream` or `none`. |
| `ownership(component)` | `os_package`, `vendor_bundled`, `manual`, `python_package` or `unknown`, from `package_lineage`, jars, packages and path. |
| `host_os_major(host, context)` / `host_arch(host, context)` | OS major number / CPU architecture. |
| `upstream_of(component)` | Upstream version, from `upstream_version` or the RPM's version part. |
| `installed_packages(component)` | Parsed NEVRAs of the component's packages. |
| `component_runtimes(component, host, knowledge)` | Java runtimes this copy may run on. |
| `advisory_packages(evidence, advisory, os_major)` | Every NEVRA an advisory ships for this OS major. |
| `verification_commands(component, scheme, cve, pkgs, product_key, target)` | Read-only commands for an operator (e.g. `dnf updateinfo list --cves …`). **Never executed.** |
| `parse_nevra`, `rpmvercmp`, `compare_evr`, `compare_upstream`, `java_version`, `java_feature`, `branch`, `satisfies` | [compatibility/versions.py](aegis-cve-evidence/compatibility/versions.py): RPM NEVRA parsing and `rpmvercmp` ordering, upstream/Java version comparison, branch extraction, range checks. |

---

## Phase 7: saving each CVE's results

Back in the loop of `run_grouped_remediation` after `workflow.stream` finishes:

| Call | Line | What it does |
|---|---|---|
| `write_json(evidence_path, evidence)` | [63](aegis-cve-evidence/remediation/run_grouped_remediation.py#L63) | `mcp_evidence.json` (written during streaming). |
| `write_json(result_path, state["assessment"])` | | `remediation_result.json`. |
| `write_json(compatibility_path, ...)` | | `compatibility.json`. |
| `public_reasoning_record(run_id, product, cve_id, result, component_id=None, component_name=None)` | [149](aegis-cve-evidence/remediation/run_grouped_remediation.py#L149) | Extracts the reviewable decision fields plus model/hash/validation metadata; the runner adds `compatibility_status`/`summary` and writes `reasoning.json` and `reasoning_by_cve.json`. |
| On an exception | | Marks the running stage `failed`, writes a `FAILED` reasoning record, and (with `continue_on_error`) moves to the next CVE. |
| (UI run: skipped) `try_persist_remediation_context(run_id=, item=, reasoning=)` | [341](aegis-cve-evidence/remediation/run_grouped_remediation.py#L341) | Only with `persist_context`. Calls `persist_remediation_context` → `context_manager.connect_database()` → `ensure_table(conn)` → `save_remediation_context(...)` → `remediation_context_values(...)` (Oracle `CVE_CONTEXT` upsert). A failure is recorded, never fatal. |
| `token_ledger.print_summary(label, since=...)` | [token_ledger.py:82](aegis-cve-evidence/remediation/token_ledger.py#L82) | Prints and returns this CVE's token subtotal (stored as `token_usage`). |
| Append to `aggregate["results"]`, `write_json(combined_path, aggregate)` | | The item's context, evidence, result, compatibility, reasoning and status. |
| `publish_progress()` | [608](aegis-cve-evidence/remediation/run_grouped_remediation.py#L608) | Marks unvisited stages `skipped` and publishes the snapshot. |

After the loop: `aggregate.status` = `completed` or `completed_with_errors`, the run's token
total, and `run_summary.json`. The aggregate is returned to `execute_selected_pipeline`.

#### `publish_workflow_progress(path, snapshot, callback=None)`

[run_grouped_remediation.py:68](aegis-cve-evidence/remediation/run_grouped_remediation.py#L68)

Called by the inner `publish_progress()` (and indirectly by `workflow_event(event)`, which the
graph nodes call through `emit`). Atomically replaces `workflow_progress.json` (retrying briefly
on Windows file locks) and calls `callback(snapshot)`, which updates
`PIPELINE_RUNS[run_id]["workflow_progress"]` in the web backend.

| Param | Type | Meaning |
|---|---|---|
| `path` | `Path` | `runs/<run_id>/workflow_progress.json`. |
| `snapshot` | `dict` | `{total, completed, current, stages, updated_at}`. |
| `callback` | callable \| `None` | The `progress_callback` option. |

**Returns:** `True` if the file was saved.

---

## Phase 8: live progress in the browser

While the run is `queued`/`running`, a React `useEffect`
([ui/src/App.jsx:752](ui/src/App.jsx#L752)) opens an `EventSource`; if that fails it polls every
2 seconds. `WorkflowView` renders the stages.

| Endpoint | Function | Line | What it does |
|---|---|---|---|
| `GET /api/pipeline-runs/{run_id}/events` | `selected_pipeline_events(run_id)` | [824](app.py#L824) | Server-sent events: every second it calls `pipeline_run(run_id)` and sends the run when it changed; stops at `completed`/`failed`. |
| `GET /api/pipeline-runs/{run_id}` | `selected_pipeline_status(run_id)` | [816](app.py#L816) | The current run record (polling fallback). |
| — | `pipeline_run(run_id)` | [257](app.py#L257) | The live in-memory record while running; otherwise merges it with `saved_pipeline_run`. |
| — | `saved_pipeline_run(run_id)` | [210](app.py#L210) | Rebuilds status from `grouped_remediation_<run_id>.json` and `workflow_progress.json`, so status survives an API restart. Validates `run_id` with a strict regex. |

---

## Phase 9: loading and showing results

### 9.1 `showRemediationResults()` (browser)

[ui/src/App.jsx:891](ui/src/App.jsx#L891)

Calls `GET /api/jobs/{job_id}/remediation-results`, merges the runs into state with
`mergeRemediationRuns` ([ui/src/remediationResults.js](ui/src/remediationResults.js)), and opens
the results view, which renders one `RemediationResultCard(result)`
([App.jsx:278](ui/src/App.jsx#L278)) per CVE.

### 9.2 `session_remediation_results(job_id)` — `GET /api/jobs/{job_id}/remediation-results`

[app.py:861](app.py#L861)

For every run started from this upload (oldest first), loads the saved aggregate with
`saved_run_aggregate(run_id)` and, if finished, converts it with `public_remediation_results`.

| Param | Type | Meaning |
|---|---|---|
| `job_id` | `str` | Upload job. |

**Returns:** `{"runs": [public results, ...]}`.

`selected_pipeline_results(run_id)` ([app.py:851](app.py#L851)), `GET /api/pipeline-runs/{run_id}/results`,
does the same for one run (HTTP 409 while still running).

`saved_run_aggregate(run_id)` ([app.py:265](app.py#L265)) validates the ID and reads
`grouped_remediation_<run_id>.json`; `None` if absent or unreadable.

### 9.3 `public_remediation_results(aggregate)`

[app.py:453](app.py#L453)

Converts the stored aggregate into what the UI shows, one entry per CVE item:

- Separates database-persistence errors from assessment errors (also for older runs) and maps
  old budget errors to `ASSESSMENT_LIMITED`.
- Takes the decision from `reasoning`, collecting every cited `EV-nnn`.
- Re-applies `_assessment_records` so the evidence list shows the same records the agent saw,
  plus any cited ones, each with its `EV-nnn` number.
- `unique_lookup_sources(...)` — each Internet-lookup page once, preferring its validated entry.
- Component, application, OS and test-context facts from the context.
- `compatibility` from the run, or `saved_run_compatibility(item)` for runs saved before the
  compatibility agent existed (computed offline, `None` on any error).
- `source_fix_groups(records)` — fixes grouped as upstream (IBM, Rocky Linux) vs. downstream,
  shown even when applicability is unresolved.
- `primary_source_fix(...)` — one evidence-backed lead (below).
- Counts verdicts per run.

| Param | Type | Meaning |
|---|---|---|
| `aggregate` | `dict` | Saved run aggregate. |

**Returns:** `{run_id, status, started_at, completed_at, total, verdict_counts, uses_test_context, results}`.

#### `primary_source_fix(records, product, component, installed_version, runtime, operating_systems)`

[app.py:337](app.py#L337)

Picks one source fix to highlight, **without claiming it is installable** (`compatibility:
"unverified"`). Its inner `rank(record)` scores: product name match, AIX level match, same
release branch as installed (`fix_major`), same OS major for distribution packages, first fixed
release over "latest release" rows; penalizes VIOS on AIX and Linux distributions on AIX. With no
installed version and equal-ranked fixes on different branches, it returns `None`.

| Param | Type | Meaning |
|---|---|---|
| `records` | `list[dict]` | Public evidence records. |
| `product`, `component` | `str` | Item product group and component. |
| `installed_version` | `str \| None` | From the context component. |
| `runtime` | `str \| None` | From the context component. |
| `operating_systems` | `list[str]` | Host OS names. |

**Returns:** `{identifier, identifier_kind, source, url, product, component, release,
evidence_id, compatibility: "unverified", match_scope}` or `None`. `match_scope` is
`component`, `host` or `source_only`.

`fix_major(version)` ([app.py:327](app.py#L327)): release branch of a version
(`9.0.119` → `9`, `8u503` / `1.8.0_501` → `8`).

---

## 10. Shared helpers called from many places

| Function | File | Params | What it does | Called from |
|---|---|---|---|---|
| `RateLimiter.wait()` | [remediation/rate_limit.py:17](aegis-cve-evidence/remediation/rate_limit.py#L17) | — | Thread-safe pacing. Instances: `model_requests` (2 s, `AEGIS_MODEL_MIN_INTERVAL_SECONDS`), `page_requests` (0.25 s), `search_requests` (2 s). | `invoke_bedrock`, `LLMClient.generate`, `LLM.complete`, `_invoke`, `HTTP.get`, `Fetcher.fetch`, search providers |
| `count_input_tokens(provider, client, model, system, messages, input_bytes)` | [remediation/token_count.py:13](aegis-cve-evidence/remediation/token_count.py#L13) | | Provider `count_tokens` (Bedrock/Anthropic); on any failure `fallback_tokens` = bytes / 2.5 + 64. Returns `(count, "provider" \| "byte_estimate")`. | `LLMClient.generate`, `LLM.complete` |
| `token_ledger.set_cve(cve)` | [token_ledger.py:18](aegis-cve-evidence/remediation/token_ledger.py#L18) | CVE or `None` | Labels later calls. | batch runner |
| `token_ledger.record(stage, model, input_tokens, output_tokens)` / `from_usage(stage, model, usage)` | [token_ledger.py:32](aegis-cve-evidence/remediation/token_ledger.py#L32), [45](aegis-cve-evidence/remediation/token_ledger.py#L45) | | Stores and prints one call's tokens; `from_usage` reads Bedrock, Azure or Anthropic usage shapes. | every model call site |
| `token_ledger.count()` / `summary(...)` / `print_summary(label, cve=None, since=0)` / `reset()` | [token_ledger.py](aegis-cve-evidence/remediation/token_ledger.py) | | Totals per CVE and per run. | batch runner |
| `write_json(path, value)` / `read_json(path)` | [run_grouped_remediation.py:63](aegis-cve-evidence/remediation/run_grouped_remediation.py#L63) | | UTF-8 JSON with indent, creating folders. | batch runner |
| `safe_path_part(value)` | [run_grouped_remediation.py:101](aegis-cve-evidence/remediation/run_grouped_remediation.py#L101) | | Windows-safe folder name for a product group. | batch runner |
| `error(message, status=400)` | [app.py:57](app.py#L57) | | `{"error": message}` JSON response. | API routes |

---

## 11. Main data shapes passed between functions

### Record (from `build_records`)

```python
{"cve_id": "CVE-2024-50379",
 "sources": [{"source_id": "row2:col5", "row_number": 2, "column": "Description",
              "text": "...", "shared_cve_ids": []}],
 "contexts": [{"application": "Sterling_Middleware", "operating_system": "Rocky Linux 8.10",
               "row_numbers": [2, 7]}],
 "observations": [{"row_number": 2, "row": {...original CSV row...}}]}
```

### Enriched / grouped row

Keys = `COMPONENT_COLUMNS`: `Application`, `Product`, `Component`, `Component ID`,
`Description`, `CVE IDs`, `Operating System`, `Technical Details`, `Evidence`,
`Affected Symbol`, `Source Path`, `Component Kind`, `Classification Status`,
`Classification Reason`, `Source Rows`. Multi-valued cells are joined with ` | `.

### Item (from `read_grouped_csv`)

```python
{"cve": "CVE-…", "vendor": "auto", "products": ["Apache Tomcat"], "product": "Apache Tomcat",
 "product_group": "Apache Tomcat", "components": ["…"], "component_id": "CMP-…",
 "applications": ["…"], "os_names": ["…"], "hostnames": [], "source_rows": [3],
 "selected_source_rows": [3],          # added by select_items
 "context": {...},                     # replaced by the host inventory
 "context_file": "…", "context_missing": False}   # set by apply_host_inventory
```

### Context (per item)

```python
{"platform_name": "CVE_Remediation_Platform",
 "request": {"is_dummy": False, "cve_id": "CVE-…", "vendor": "auto", "product_group": "…",
             "component_id": "CMP-…", "component_names": ["…"], "run_id": "ui-…",
             "context_kind": "OBSERVED_HOST_INVENTORY", "inventory_file": "…"},
 "response": {"is_dummy": False, "cve_id": "CVE-…", "status": "COMPLETE", "collected_at": "…",
              "server": {"hostnames": [...], "os_names": [...], "version_id": "…", "architecture": "…"},
              "application": {"names": [...], "products": [...], "version": "…", "install_path": "…"},
              "components": [{"name": "…", "inventory_component": "…", "installed_version": "…",
                              "executable_path": "…", "packages": [...], "package_lineage": "…",
                              "runtime": "…", "used_by_application": True,
                              "collection_status": "OBSERVED", "scan_observations": [...]}],
              "missing_context": [...], "warnings": [...]}}
```

### Evidence record

Fields of `Evidence` ([models.py:19](aegis-cve-evidence/src/aegis_evidence/models.py#L19)):
`source`, `url`, `cve`, `product`, `affected_versions`, `fixed_version`, `remediation`,
`advisory`, `component`, `release`, `published`, `evidence_kind` (e.g. `vendor_advisory`,
`fixed_package`, `service_pack_or_fix_pack`, `interim_fix`, `cpu_release`, `latest_release`,
`validated_page_excerpt`), `notes`. Internet-lookup records add `verbatim_excerpt`, `tier` and
`vendor_stance`.

### Evidence result (from `Engine.lookup`)

```python
{"cve": "CVE-…", "vendor": "apache", "retrieved_at": "…",
 "status": "evidence_found" | "no_verified_remediation_found",
 "coverage": "searched_configured_sources" | "partial",
 "searched_sources": ["Apache", "Rocky Linux"], "evidence": [...records...],
 "source_errors": [{"source": "…", "error": "…"}], "notes": [...]}
# after internet_lookup also: "internet_lookup": {LookupResult}, "vendor_evidence": {...}
```

### Decision (remediation agent output)

`cve_id`; `verdict` ∈ `FIX_AVAILABLE`, `NOT_APPLICABLE`, `NEEDS_INPUT`,
`INSUFFICIENT_EVIDENCE`, `NO_FIX_AVAILABLE` (plus `ASSESSMENT_LIMITED` from
`budget_limited_result`); `applicability` ∈ `AFFECTED`, `NOT_AFFECTED`, `UNKNOWN`;
`recommended_remediation` (`Remedy` or `null`); `candidate_remediations`; `supporting_claims`
(`{evidence_id, quote}`); `blocked_on`; `assessment_summary`; `assessment_notes`; `conflicts`;
`missing_information`; `operational_notes`.

`Remedy`: `route` ∈ `component_upgrade`, `application_upgrade`, `vendor_patch`,
`os_package_update`, `os_upgrade`, `workaround`; `target_version`; `patch_id`; `summary`;
`compatibility` ∈ `SUPPORTED`, `UNVERIFIED`; `fix_support`, `applicability_support`,
`compatibility_support` (lists of claims).

### Artifacts of one run

```text
aegis-cve-evidence/remediation/runs/
  grouped_remediation_<run_id>.json          aggregate (read by the results API)
  _internet_lookup_cache/                    7-day lookup cache (shared across runs)
  <run_id>/
    workflow_progress.json, run_summary.json, reasoning_by_cve.json
    _internet_lookup/logs/, _internet_lookup/results/
    <product>/<component_id>/<CVE>/
      mcp_evidence.json, remediation_result.json, compatibility.json, reasoning.json
data/
  <run_id>.csv                               enriched rows
  grouped_by_comp.csv                        grouped rows
  selected_components_<run_id>.csv           rows chosen for this run
```

---

## Appendix A: command-line entry points

The CLI runs the same functions without the web layer.

| Command | Entry function | Sequence |
|---|---|---|
| `python cve_component_enrichment.py findings.csv [--run-id ID]` | `main()` [cve_component_enrichment.py:477](cve_component_enrichment.py#L477) | `read_source_file` → `build_records` → `write_csv(deduplicated_cves.csv)` → `create_bedrock_client` → `classify_cves` → `component_rows` → `write_csv` → `write_grouped_csv(data/grouped_by_comp.csv)`; also writes `classification_diagnostics.json`. |
| `python aegis-cve-evidence/remediation/run_grouped_remediation.py [options]` | `main(argv)` [run_grouped_remediation.py:458](aegis-cve-evidence/remediation/run_grouped_remediation.py#L458) | Parses the flags into `RemediationOptions` → `run_grouped_remediation` (Phases 5–7). Defaults differ from the UI: one CVE per product, no inventory unless `--inventory`. |
| `aegis-cve` (one CVE) | [src/aegis_evidence/cli.py](aegis-cve-evidence/src/aegis_evidence/cli.py) | `Engine().lookup(...)` only; saves JSON to `src/output_data/`. |
| `python -m Internet_lookup` | [Internet_lookup/__main__.py](aegis-cve-evidence/Internet_lookup/__main__.py) | `run_fallback(...)` with ranking and reconciliation **on**. |
| `python aegis-cve-evidence/remediation/remedition_agent.py --context … --evidence …` | `main()` [remedition_agent.py:1102](aegis-cve-evidence/remediation/remedition_agent.py#L1102) | `load_config` → `LLMClient` → `run_agent` on saved files. |

---

## Appendix B: "previous fixes" path

`showPreviousFixes()` ([ui/src/App.jsx:908](ui/src/App.jsx#L908)) →
`POST /api/jobs/{job_id}/previous-fixes` → `previous_saved_fixes(job_id, payload)`
([app.py:971](app.py#L971)).

It scans every `grouped_remediation_ui-*.json`, keeps items for which
`saved_fix_is_reviewable(item)` ([app.py:908](app.py#L908)) is true, keeps the newest per
`saved_fix_key(item)` (CVE, product, component), and returns them through
`public_remediation_results`.

`saved_fix_is_reviewable(item)` accepts a saved fix only if:

- it is a `FIX_AVAILABLE` decision with a recommended remedy and no error;
- it is not a synthetic result for an application the observed inventory now covers
  (`observed_inventory_covers`);
- the inventory file was not edited after the assessment;
- it is not a Debian package version on a non-Debian host;
- a test fixture's installed versions have not changed since;
- it still passes `Decision.model_validate` → `prepare` → `validate_decision` with the current code.

| Param (`payload` keys) | Type | Meaning |
|---|---|---|
| `scope` | `"selected"` \| omitted | Limit to the selected grouped rows. |
| `selected_indices` | `list[int]` | Required with `scope="selected"`. |
| `exclude_run_id` | `str` | Leave out the run just shown. |
