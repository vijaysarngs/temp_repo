# AEGIS code reference

**Repository inspected:** `aegis_engine_prod`  
**Inspection date:** 2026-10-08  
**Scope:** Project-owned Python, JavaScript/JSX, PowerShell, configuration, prompts, tests, and representative stored-data schemas. Generated CVE/context files are documented by field structure, as requested, rather than repeated file by file. Installed packages under `.venv`, build output, caches, and Git internals are not project source.

This document describes what the inspected code actually does. It does not treat a filename, prompt, comment, or intended architecture as proof that a capability is implemented.

## 1. Verified capability map

| Intended capability | What exists in this repository | Status and boundary |
|---|---|---|
| Import and normalize scanner findings | CSV/XLSX readers, CVE extraction, deduplication, source-text classification, grouping, FastAPI upload endpoints, and React UI | **Implemented.** Classification proves that labels appear in supplied text; it does not prove installation or vulnerability on a host. |
| Collect server context | A standalone one-command Paramiko example; an Oracle JSON context store; context JSON templates; synthetic fixture generation | **Partial/demo only.** There is no integrated general-purpose live context collector that executes the generated discovery probes and builds production context JSON. |
| Retrieve vulnerability/fix evidence | Vendor-specific evidence engine and MCP/CLI interfaces; separate experimental `Internet_lookup` pipeline | **Implemented with source-specific parsers and partial-coverage reporting.** HTML/API changes, unavailable sources, and scope mismatches can leave gaps. |
| Assess applicability | Remediation LLM consumes inventory context plus evidence and produces structured verdicts with exact-quote validation | **Implemented as an assessment.** Structural and quote checks do not independently prove the model's semantic interpretation. |
| Assess compatibility | Prompt and schema require compatibility support for `FIX_AVAILABLE` | **Implemented as evidence-based reasoning, not an executable compatibility test.** There is no application test suite, package solver, or deterministic ecosystem version comparator. |
| Recommend remediation | `Decision`/`Remedy` schemas, validation, evidence citations, UI result cards | **Implemented as recommendation output.** `execution_ready` is always `False`. |
| Human approval | Selection of rows/components in the UI | **Only selection is implemented.** There is no approval record, approver identity, policy engine, signature, or approval state transition. |
| Deploy remediation | None in the remediation workflow | **Not implemented.** The SSH example can run one manually configured command, but it is not connected to recommendations, approval, rollback, or deployment. |

## 2. Architecture and principal flows

```text
Scanner CSV/XLSX
      |
      v
cve_component_enrichment.py / FastAPI app.py
  - deduplicate CVEs
  - Bedrock classifies product/component from supplied text
  - validate exact supporting quotes
      |
      v
group_cves_by_component.py -> data/grouped_by_comp.csv
      |
      v
run_grouped_remediation.py
  - select CVEs/components
  - optionally load context JSON (the UI uses synthetic test context)
  - Engine retrieves vendor evidence
      |
      v
remedition_agent.py
  - LLM assesses applicability/compatibility
  - Pydantic + exact-quote validation
  - recommendation JSON, never execution
      |
      v
FastAPI result projection -> React review UI
```

The separate `Internet_lookup/` package follows a second, currently unintegrated path:

```text
CveRow + optional HostProfile
 -> query planning -> URL discovery -> allowlisted fetch
 -> exact CVE validation -> LLM extraction -> provenance checks
 -> reconciliation -> conservative remediation options -> JSON/cache/logs
```

## 3. Root application files

### `agent_utils.py`

**Purpose and dependencies.** Shared normalization and Amazon Bedrock invocation helpers used by `cve_component_enrichment.py` and `component_version_command_agent.py`. It imports `boto3`, `botocore`, and root `config.py`. It makes model calls but does not retrieve CVE evidence, execute server commands, or write data itself.

| Function (line) | Inputs and return | How it works, side effects, and project role |
|---|---|---|
| `clean(value)` ([line 12](agent_utils.py#L12)) | Any value -> stripped string | Converts `None` to `""`; serializes `date`/`datetime` with ISO format. Used before CSV/prompt handling. |
| `normalize_name(value)` ([line 20](agent_utils.py#L20)) | Header-like value -> normalized string | Calls `clean`, converts `_`/`-` to spaces, lowercases, and collapses whitespace so header aliases compare consistently. |
| `get_value(row, *names)` ([line 26](agent_utils.py#L26)) | Mapping plus accepted aliases -> string | Normalizes candidate names and row keys, returning the first matched cleaned value or `""`. |
| `create_bedrock_client()` ([line 34](agent_utils.py#L34)) | No arguments -> boto3 Bedrock Runtime client | Requires `config.USE_BEDROCK`; uses explicit credentials, session token, or profile; applies region, 10-second connect/60-second read timeouts, and one standard retry attempt. It logs initialization but performs no verification until the first request. |
| `invoke_bedrock(client, body, purpose="model request")` ([line 67](agent_utils.py#L67)) | Client, Anthropic-on-Bedrock payload, log label -> parsed response dictionary | Calls `invoke_model` using `config.BEDROCK_MODEL_ID`, tries optimized latency, retries without that option only for an applicable validation error, reads and JSON-decodes the body, logs timing, and re-raises provider/network/JSON errors. **LLM call:** yes. |

### `config.py`

**Purpose.** Import-time root configuration ([lines 1-52](config.py#L1)); it has no functions. It adds the optional `aegis_core/aegis_core` path, loads root `.env` without overriding existing variables, removes blank AWS profile variables, optionally imports an internal config module under an isolated name, and exposes cleaned values.

**Inputs/environment:** `USE_BEDROCK`, `BEDROCK_MODEL_ID`, `AWS_DEFAULT_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_PROFILE`, and `NVD_API_KEY`. `MODEL_PROVIDER=bedrock` and `DEMO_MODE=0` are defaulted in `os.environ`. Missing optional dotenv/internal configuration is silently tolerated. **Output:** module globals only; no files or database changes.

### `cve_component_enrichment.py`

**Purpose.** The evidence-grounded product/component classifier. It reads scanner CSV/XLSX records, extracts and deduplicates CVEs, sends eligible source descriptions to Bedrock, verifies every returned label against exact supplied quotes, writes diagnostics/deduplicated/enriched CSVs, and calls `group_cves_by_component.py`. `app.py` imports its reusable functions.

**Important constants and schemas** ([lines 19-87](cve_component_enrichment.py#L19)):

- `COMPONENT_COLUMNS` is the 14-column enriched CSV contract.
- `FIELDS` requires `product`, `component`, `affected_symbol`, and `source_path` facts.
- `KINDS` restricts component categories.
- Header aliases and `CVE_PATTERN` control ingestion.
- `EVIDENCE_SCHEMA`, `FACT_SCHEMA`, `ITEM_SCHEMA`, and `CLASSIFICATION_TOOL` define a closed Bedrock tool response. These constrain shape, not truth; subsequent quote checks supply grounding.

| Function (line) | Inputs/return | Logic, validation, side effects, and connection |
|---|---|---|
| `clean(value)` ([39](cve_component_enrichment.py#L39)) | Any -> string | Converts `None` to empty text and strips whitespace. |
| `normalized(value)` ([43](cve_component_enrichment.py#L43)) | Any -> normalized string | Unicode NFKC normalization, whitespace collapse, and case-folding. It deliberately normalizes formatting rather than doing fuzzy semantic matching. |
| `header_key(value)` ([48](cve_component_enrichment.py#L48)) | Header -> string | Calls `normalized` and treats `_`/`-` as spaces. |
| `meaningful(value)` ([52](cve_component_enrichment.py#L52)) | Value -> boolean | Rejects blank/sentinel values in `EMPTY`. |
| `get_value(row, *aliases)` ([56](cve_component_enrichment.py#L56)) | Row and aliases -> string | Searches normalized headers and returns the first meaningful cleaned value. |
| `object_schema(properties)` ([64](cve_component_enrichment.py#L64)) | JSON Schema properties -> closed object schema | Requires every supplied property and forbids extra properties; used to construct the tool schema. |
| `read_source_file(path, sheet_name=None)` ([90](cve_component_enrichment.py#L90)) | CSV/XLSX path and optional sheet -> list of row dictionaries | Validates existence, extension, nonempty/unique headers, excess CSV values, and at least one data row. CSV is UTF-8-BOM aware; XLSX uses `openpyxl` read-only/data-only mode and closes the workbook. **File read:** yes. |
| `build_records(rows)` ([125](cve_component_enrichment.py#L125)) | Source rows -> `(records, skipped)` | Ignores empty rows; only extracts CVEs from recognized ID columns; records application/OS context, original row observations, and description-like source cells with stable `rowN:colN` IDs. A description shared across multiple CVEs is marked ambiguous. No LLM/network call. |
| `classification_prompt(records, retry_feedback=None)` ([166](cve_component_enrichment.py#L166)) | Eligible records and repair feedback -> prompt string | Embeds strict rules: source text is untrusted, labels must be contiguous text, contexts are metadata, unknowns remain empty, and evidence must quote a supplied source ID. |
| `classify_batch(client, records, max_tokens=6000, retry_feedback=None)` ([204](cve_component_enrichment.py#L204)) | Bedrock client and record batch -> raw provider dictionary | Calls `agent_utils.invoke_bedrock` with the forced classification tool. **LLM call:** yes. |
| `require_keys(value, keys)` ([218](cve_component_enrichment.py#L218)) | Candidate mapping and exact keys -> boolean | Rejects non-dictionaries, missing fields, and unexpected fields. |
| `empty_result(cve_id)` ([222](cve_component_enrichment.py#L222)) | CVE -> conservative result dictionary | Initializes all facts empty, kind `unknown`, status `NEEDS_ENRICHMENT`. |
| `validate_fact(value, sources)` ([228](cve_component_enrichment.py#L228)) | Model fact and source-ID/text mapping -> `(validated_fact, error)` | Validates exact schema/types; enforces evidence for nonempty labels; checks that normalized quotes occur in the referenced source and contain the label as a word-bounded substring; deduplicates citations. This proves textual support, not that the label is operationally applicable. |
| `set_status(result)` ([257](cve_component_enrichment.py#L257)) | Mutable classification -> same mapping | Chooses `EVIDENCE_MISMATCH`, `SUPPORTED`, `PARTIAL`, or `NEEDS_ENRICHMENT` from issues and populated fields. `SUPPORTED` means product/component are supported by input text only. |
| `validate_classification(item, record)` ([269](cve_component_enrichment.py#L269)) | One model item and record -> validated result | Checks outer schema, validates every fact, restricts kind, prevents a protocol alone being used as its own version-bearing product, then sets status. |
| `interpret_response(response, records)` ([293](cve_component_enrichment.py#L293)) | Raw Bedrock response and requested records -> CVE/result mapping | Detects truncation, finds the named tool block, groups candidates by requested CVE, rejects missing/duplicate outputs, and calls `validate_classification`. |
| `merge_retry(previous, repaired)` ([327](cve_component_enrichment.py#L327)) | First and repaired validated results -> merged result | Retains previously verified facts if retry omits/conflicts, reports disagreements as `CONFLICTING_EVIDENCE`, and never replaces support silently. |
| `classify_cves(client, records, batch_size=5, max_batches=None, max_tokens=6000, diagnostics=None, caller=None)` ([353](cve_component_enrichment.py#L353)) | Records, model limits, diagnostics, injectable caller -> results mapping | Excludes missing/ambiguous descriptions from model calls; batches eligible CVEs; records raw attempts; converts provider failures to `MODEL_ERROR`; retries each non-`SUPPORTED` CVE once with repair feedback; honors explicit batch limits. **LLM call:** through `caller`. |
| `result_reason(result)` ([408](cve_component_enrichment.py#L408)) | Classification -> human-readable reason | Joins issues or reports missing facts; explicitly states host applicability is unverified for supported labels. |
| `component_rows(records, classifications)` ([415](cve_component_enrichment.py#L415)) | Records/results -> enriched row list | Creates one row per CVE/context without prematurely grouping distinct CVEs; emits evidence/technical-detail strings and source rows; sorts deterministically. |
| `write_csv(path, rows, columns)` ([453](cve_component_enrichment.py#L453)) | Destination, rows, columns -> `None` | Creates parent directories and writes UTF-8-BOM CSV. **File write:** yes. |
| `positive_int(value)` ([462](cve_component_enrichment.py#L462)) | CLI text -> positive integer | Raises `argparse.ArgumentTypeError` below one. |
| `main()` ([469](cve_component_enrichment.py#L469)) | CLI arguments -> files and console summary | Validates run ID and non-overlapping input/output paths; writes deduplicated CSV and diagnostics; creates Bedrock client only when eligible sources exist; classifies, writes enriched CSV, then writes `data/grouped_by_comp.csv`. It performs no internet evidence lookup or SSH work. |

Example (credentials omitted):

```powershell
python cve_component_enrichment.py findings.csv --batch-size 5 --run-id review-001
```

### `group_cves_by_component.py`

**Purpose.** Post-processing layer imported by `cve_component_enrichment.py` and `app.py`. It groups only rows whose `Product` **and** `Component` match, while keeping list-like columns as ordered distinct ` | `-separated values.

| Function (line) | Behavior |
|---|---|
| `_values(value)` ([17](group_cves_by_component.py#L17)) | Splits a stored ` | ` list, strips items, and drops empties. |
| `group_by_product_and_component(rows)` ([21](group_cves_by_component.py#L21)) | Builds keyed groups, aggregates `LIST_COLUMNS`, deduplicates while preserving order, and sorts by product/component. It does not validate that each concatenated fact applies to every CVE in the grouped row. |
| `write_grouped_csv(path, rows)` ([45](group_cves_by_component.py#L45)) | Creates the directory, writes the `COMPONENT_COLUMNS` contract with a BOM, and returns the `Path`. |

### `component_version_command_agent.py`

**Purpose.** Generates review-only path and version-query templates for enriched component rows. It asks Bedrock what executable/version arguments fit the classified component, then Python constructs tightly limited commands. It never executes them. It depends on `agent_utils.py` and writes a CSV.

**Safety constants** ([lines 16-59](component_version_command_agent.py#L16)): allowed argument tokens, no-argument version scripts, blocked executables, exact tool fields, and a closed Bedrock tool schema. These reduce command-generation risk but are not proof an executable is safe or belongs to the application.

| Function (line) | Behavior |
|---|---|
| `server_shell(operating_system)` ([62](component_version_command_agent.py#L62)) | Maps target OS text to `Windows CMD`, `POSIX shell`, or empty text. It uses the server OS, not the local workstation. |
| `generate_probe(client, row)` ([75](component_version_command_agent.py#L75)) | Serializes the untrusted row, prompts Bedrock for an executable basename and short allowed argument list, forces `return_version_probe`, returns its input, or raises if absent. **LLM call:** yes. |
| `validate_probe(probe)` ([122](component_version_command_agent.py#L122)) | Enforces exact fields/types, maximum three allowlisted arguments, basename-only executable syntax, a blocklist, and restricted no-argument scripts. Empty executable is allowed only with empty arguments. |
| `build_commands(probe, shell)` ([148](component_version_command_agent.py#L148)) | Returns a PATH lookup (`where.exe` or `command -v`) plus a quoted `REPLACE_WITH_CONFIRMED_EXECUTABLE_PATH` version template. It intentionally separates discovery from execution. |
| `read_enriched_csv(input_file)` ([161](component_version_command_agent.py#L161)) | Requires the first eight enrichment columns, reads all rows, and rejects an empty file. |
| `build_command_rows(rows)` ([173](component_version_command_agent.py#L173)) | Skips unsupported classifications/OSes; lazily creates Bedrock client; generates and validates probes; attaches warning notes; captures per-row errors so later rows remain usable. Returns output rows only. |
| `write_command_csv(rows, output_file)` ([217](component_version_command_agent.py#L217)) | Creates parents and writes UTF-8-BOM `OUTPUT_COLUMNS`. |
| `main()` ([226](component_version_command_agent.py#L226)) | Parses input/output, builds rows, writes CSV, and prints counts. |

### `paramiko_ssh_runner.py`

**Purpose.** Standalone example for running one manually reviewed command against one directly reachable SSH host. It is not called by the API, remediation agent, or command-template generator. Constants at [lines 20-34](paramiko_ssh_runner.py#L20) are placeholders for host, user, verified known-hosts file, authentication method, command, optional working directory, timeouts, and output cap.

| Function (line) | Behavior and side effects |
|---|---|
| `execute_command(client, command)` ([38](paramiko_ssh_runner.py#L38)) | Calls Paramiko `exec_command`, closes stdin, drains stdout/stderr to avoid channel blocking, enforces a read deadline and 1 MiB combined cap, and returns `(stdout, stderr, exit_code)`. **Runs a server command:** yes. |
| `main()` ([72](paramiko_ssh_runner.py#L72)) | Rejects unresolved placeholders, validates known-host/key paths, prompts for password/passphrase, requires an absolute remote directory, quotes that directory, uses `RejectPolicy` and explicit verified host keys, connects with agent/key discovery disabled, runs the configured command, prints streams/status, and returns shell success/failure. It has no approval or audit integration. |

### `app.py`

**Purpose.** FastAPI API and optional static React host. It coordinates upload/deduplication, Bedrock enrichment, grouping, selected remediation subprocesses, server-sent status events, result projection, and CSV downloads. `JOBS` and active `PIPELINE_RUNS` are in-memory dictionaries; durable remediation aggregates can reconstruct completed status after restart.

**Key constants/state** ([lines 31-46](app.py#L31)): 25 MiB upload cap, UI/data paths, remediation runner/context paths, FastAPI app, and conditional static asset mount. The configured remediation context path points to `context_gathered/test`.

| Function/route (line) | Behavior |
|---|---|
| `error(message, status=400)` ([49](app.py#L49)) | Returns `{"error": message}` as a `JSONResponse`. |
| `csv_response(rows, columns, filename)` ([53](app.py#L53)) | Builds an in-memory BOM-prefixed CSV download response. |
| `read_enriched_csv(path)` ([66](app.py#L66)) | Enforces all `COMPONENT_COLUMNS`, coerces cells to strings, and rejects empty saved enrichment. |
| `reusable_enrichment_files()` ([82](app.py#L82)) | Scans `data/*.csv`, excludes grouped/selected inputs, keeps only valid enrichment files, and returns newest-first metadata. |
| `grouped_payload(job_id, enriched_rows, source, source_filename)` ([107](app.py#L107)) | Groups rows, updates the in-memory job, writes `grouped_by_comp.csv`, falls back to a run-specific filename if Excel locks the default, and returns both enriched and grouped payloads. |
| `execute_selected_pipeline(run_id, selected_path)` ([141](app.py#L141)) | Background-thread target. Runs `run_grouped_remediation.py` as a subprocess with `--latest-per-component`, test context, `--allow-dummy`, and `--reuse-test-inventory`; captures output and updates run state. **Important:** UI remediation therefore uses explicitly synthetic inventory by default. No timeout is set. |
| `saved_pipeline_run(run_id)` ([183](app.py#L183)) | Validates ID, reads durable aggregate JSON, maps pipeline state to API state, and returns paths/message; malformed/missing files return `None`. |
| `pipeline_run(run_id)` ([220](app.py#L220)) | Returns active in-memory state or recovered durable state. |
| `saved_run_aggregate(run_id)` ([224](app.py#L224)) | Validates ID and returns an aggregate dictionary if readable. |
| `public_remediation_results(aggregate)` ([237](app.py#L237)) | Projects internal run artifacts to UI-safe results, counts verdicts, collects only cited evidence-source metadata, and exposes decision rationale. It does not approve or apply a remedy. |
| `upload_csv(file)` `POST /api/upload` ([310](app.py#L310)) | Requires UTF-8 CSV, `.csv` suffix, nonempty content, and <=25 MiB; writes a temporary file, calls `read_source_file`/`build_records`, deletes the temp file, stores job data in memory, and returns first-row-per-CVE preview plus latest reusable enrichment. |
| `enrich_range(payload)` `POST /api/enrich` ([377](app.py#L377)) | Validates job/start/count, creates Bedrock client only if eligible source text exists, calls classification and row conversion, saves `data/<job>.csv`, groups results, and returns them. This can make LLM calls. |
| `reuse_enrichment(payload)` `POST /api/enrich/reuse` ([420](app.py#L420)) | Restricts selection to currently enumerated basename-only files, reads/group saves an existing enrichment, and returns it without a new LLM call. |
| `start_selected_pipeline(payload)` `POST /api/pipeline-runs` ([439](app.py#L439)) | Validates selected integer indexes, writes only selected grouped rows to a run-specific CSV, creates queued state, and launches a daemon thread. Returns HTTP 202. This is selection, not formal approval. |
| `selected_pipeline_status(run_id)` `GET .../{run_id}` ([477](app.py#L477)) | Returns current/recovered state or 404. |
| `selected_pipeline_events(run_id)` `GET .../events` ([485](app.py#L485)) | Returns an SSE generator that emits changed state once per second until completion/failure. Blocking `time.sleep` runs in the streaming generator. |
| `selected_pipeline_results(run_id)` `GET .../results` ([512](app.py#L512)) | Requires a terminal aggregate and returns `public_remediation_results`; returns 409 while running. |
| `download_csv(job_id, kind)` `GET /api/download/...` ([522](app.py#L522)) | Serves deduplicated, enriched, or grouped in-memory data; validates prerequisite state. |
| `health()` `GET /api/health` ([556](app.py#L556)) | Returns `{"status":"ok"}`; it does not test Bedrock, internet, database, or SSH dependencies. |
| `frontend()` `GET /` ([561](app.py#L561)) | Serves built `ui/dist/index.html` or build instructions. |

Running `python app.py` starts Uvicorn on `127.0.0.1` and `PORT` (default 5000) at [lines 570-573](app.py#L570).

## 4. React UI

### `ui/src/App.jsx`

**Purpose.** Single-page React interface for upload, enrichment, grouping, component selection, live remediation status, and review of recommendation results. It calls only the FastAPI `/api` routes; it does not contact Bedrock, evidence publishers, SSH hosts, or a database directly.

**Constants:** `PAGE_SIZE=10` and a 30-minute browser enrichment timeout at [lines 22-23](ui/src/App.jsx#L22).

| Function/component (line) | Inputs/return and behavior |
|---|---|
| `humanize(value)` ([25](ui/src/App.jsx#L25)) | Returns display text with underscores replaced by spaces, defaulting to `Unknown`. |
| `mergeRemediationResults(current, incoming)` ([29](ui/src/App.jsx#L29)) | Avoids duplicate run IDs, annotates incoming result rows, merges session history, recalculates verdict counts, and preserves the test-context flag. |
| `ClaimList({claims, sources})` ([54](ui/src/App.jsx#L54)) | Renders exact evidence quotes and linked source metadata. Missing URLs remain plain text. |
| `RemedyCard({remedy, sources, recommended})` ([78](ui/src/App.jsx#L78)) | Displays route/version or patch, compatibility, summary, and combined fix/applicability/compatibility citations. It renders a recommendation; it has no execute/approve action. |
| `GuidanceList({title, items, tone})` ([106](ui/src/App.jsx#L106)) | Conditionally renders a titled guidance list. |
| `RemediationResultCard({result})` ([116](ui/src/App.jsx#L116)) | Displays CVE verdict, applicability, context, errors, recommendation/candidates, blockers, missing information, operational notes, conflicts, citations, and validation note. |
| `GroupedTable({columns, rows, selected, setSelected})` ([197](ui/src/App.jsx#L197)) | Paginated selectable grouped table. Nested `toggle(index)` ([205](ui/src/App.jsx#L205)) clones/toggles a `Set`; `toggleAll()` ([214](ui/src/App.jsx#L214)) selects or clears every group. Selection is UI input, not recorded approval. |
| `DataTable({columns, rows, emptyMessage})` ([280](ui/src/App.jsx#L280)) | Generic paginated read-only table for deduplicated/enriched rows. |
| `UploadPanel(...)` ([357](ui/src/App.jsx#L357)) | Drag/drop and file-picker UI. Nested async `upload(file)` ([361](ui/src/App.jsx#L361)) checks `.csv`, posts multipart data to `/api/upload`, handles JSON errors, and updates parent state. Browser checks are repeated server-side. |
| `App()` ([446](ui/src/App.jsx#L446)) | Owns all view/job/run/result state and renders upload, workspace, grouped, or result screens. `activeData` memo selects the current table. |
| First `useEffect` ([475](ui/src/App.jsx#L475)) | Opens an `EventSource` for queued/running pipelines, parses updates, closes at terminal status, reports unreadable/closed streams, and cleans up on dependency change. |
| Second `useEffect` ([498](ui/src/App.jsx#L498)) | Automatically loads results after a new terminal run while on the grouped view, avoiding already merged run IDs. |
| `reset()` ([508](ui/src/App.jsx#L508)) | Clears all session UI state; it does not delete backend files/runs. |
| `setQuickCount(value)` ([524](ui/src/App.jsx#L524)) | Bounds quick row-count selection to available rows. |
| `finishGrouping(result)` ([528](ui/src/App.jsx#L528)) | Stores enriched/grouped response, clears selections/run state, selects enriched tab, and moves to grouping view. |
| `requestPipelineRun()` ([541](ui/src/App.jsx#L541)) | Opens reuse prompt when a compatible prior file exists; otherwise starts fresh enrichment. |
| `runEnrichment(mode)` ([546](ui/src/App.jsx#L546)) | Posts either range selection or reuse request, applies a 30-minute `AbortController` timeout, calls `finishGrouping`, and reports errors. |
| `runSelectedComponents()` ([581](ui/src/App.jsx#L581)) | Posts sorted selected group indexes to `/api/pipeline-runs` and stores queued state. |
| `showRemediationResults()` ([601](ui/src/App.jsx#L601)) | Fetches terminal public results, merges them into current-session history, and switches views. |

Inline JSX callbacks handle drag state, row/page navigation, range bounds, tabs, modal actions, downloads, and dismissing errors; they mutate browser state only.

### Other UI files

| File | Role and important behavior |
|---|---|
| `ui/src/main.jsx` ([lines 1-10](ui/src/main.jsx#L1)) | React entry point; mounts `App` into `#root` inside `React.StrictMode` and imports CSS. |
| `ui/src/styles.css` | Responsive visual styling for all classes used by `App.jsx`; no data or execution logic. |
| `ui/index.html` | Vite HTML shell, metadata, `#root`, and `/src/main.jsx` module script. |
| `ui/vite.config.js` ([lines 1-12](ui/vite.config.js#L1)) | Enables React, runs dev server on 5173, and proxies `/api` to `127.0.0.1:5000`. |
| `ui/package.json` | `dev`/`build` scripts; React, ReactDOM, icons, Vite, and React plugin versions. |
| `ui/package-lock.json` | Generated npm resolution lock; not hand-authored logic. |
| `ui/README.md` | Developer instructions for separate dev servers or a built single application. |

## 5. Vendor evidence engine (`aegis-cve-evidence/src/aegis_evidence`)

### Package and entry-point files

- `src/aegis_evidence/__init__.py` and `src/aegis_evidence/sources/__init__.py` are package markers with no functions.
- `pyproject.toml` defines Python >=3.11, runtime dependencies, `src` package discovery, and console scripts: `aegis-cve-evidence`, `aegis-cve-report`, and `aegis-cve`.

### `models.py`

**Purpose.** Shared input/evidence/output contracts for the deterministic vendor-adapter engine.

| Symbol (line) | Role |
|---|---|
| `CVE_RE` ([9](aegis-cve-evidence/src/aegis_evidence/models.py#L9)) | Requires one `CVE-YYYY-NNNN...` identifier. |
| `cve_id(value)` ([11](aegis-cve-evidence/src/aegis_evidence/models.py#L11)) | Strips/uppercases and validates one CVE; raises `ValueError` otherwise. |
| `Evidence` ([19](aegis-cve-evidence/src/aegis_evidence/models.py#L19)) | Dataclass for publisher, URL, CVE, product, affected/fixed data, remediation, advisory/component/release/date, evidence kind, and notes. `as_dict()` ([34](aegis-cve-evidence/src/aegis_evidence/models.py#L34)) omits `None` fields. |
| `Context` ([39](aegis-cve-evidence/src/aegis_evidence/models.py#L39)) | Adapter input: CVE/vendor plus optional product, OS, description, CVE.org references, and installed version. |
| `result(...)` ([49](aegis-cve-evidence/src/aegis_evidence/models.py#L49)) | Deduplicates evidence by a compound key, parses several date formats for newest-first order, and returns status, coverage, source list/errors, evidence dictionaries, timestamp, and notes. Empty evidence becomes `no_verified_remediation_found`, not “not affected.” |

### `http.py`

**Purpose.** Bounded, cached HTTPS retrieval and HTML helpers used by every adapter and CVE registry lookup. `ALLOWED` ([lines 14-24](aegis-cve-evidence/src/aegis_evidence/http.py#L14)) is an exact host allowlist.

| Function/class (line) | Behavior |
|---|---|
| `FetchError` ([29](aegis-cve-evidence/src/aegis_evidence/http.py#L29)) | Retrieval-policy/failure exception. |
| `HTTP.__init__(cache_dir=None, ttl_hours=6, offline=False)` ([34](aegis-cve-evidence/src/aegis_evidence/http.py#L34)) | Uses argument or `AEGIS_CACHE_DIR` (default `.cache/aegis-evidence`), creates it, stores TTL/offline state, and initializes the per-adapter attempted-URL list used by the fallback wrapper. **File-system change:** cache directory creation. |
| `HTTP.get(url, max_bytes=12_000_000)` ([42](aegis-cve-evidence/src/aegis_evidence/http.py#L42)) | Records the attempted URL, requires HTTPS and an exact allowed host, hashes it to a cache filename, uses fresh/offline cache when possible, performs up to three `urlopen` attempts with 18-second timeout, retries 429/5xx/network timeouts, rechecks redirect host, caps bytes, and caches successful bodies. **Internet retrieval/file write:** yes. |
| `HTTP.json(url)` ([76](aegis-cve-evidence/src/aegis_evidence/http.py#L76)) | Fetches and UTF-8-BOM-decodes JSON. |
| `HTTP.document(url)` ([79](aegis-cve-evidence/src/aegis_evidence/http.py#L79)) | Fetches and parses an lxml HTML document with base URL. |
| `clean(value)` ([83](aegis-cve-evidence/src/aegis_evidence/http.py#L83)) | Collapses whitespace in a string or element text. |
| `table_rows(table)` ([89](aegis-cve-evidence/src/aegis_evidence/http.py#L89)) | Returns cleaned table cells; does not expand row/column spans. |
| `section(node, heading)` ([95](aegis-cve-evidence/src/aegis_evidence/http.py#L95)) | Case-insensitively finds an h2-h4 containing a name and concatenates siblings until an equal/higher heading. |

### `registry.py`

| Function (line) | Behavior |
|---|---|
| `cve_record(http, cve)` ([6](aegis-cve-evidence/src/aegis_evidence/registry.py#L6)) | Fetches CVE.org API JSON for discovery and returns `{}` on any exception. Metadata is explicitly not fix proof. |
| `record_context(record)` ([14](aegis-cve-evidence/src/aegis_evidence/registry.py#L14)) | Combines CNA/ADP references, English descriptions, and affected product labels; deduplicates refs/products. |

### `engine.py`

**Purpose.** Adapter registry, vendor routing, and lookup orchestration. `SOURCES` and `ALIASES` at [lines 21-39](aegis-cve-evidence/src/aegis_evidence/engine.py#L21) define implemented publishers and accepted names.

| Function/class (line) | Behavior |
|---|---|
| `select(vendor, description="", product="", os_name="", refs=None, include_related=False)` ([43](aegis-cve-evidence/src/aegis_evidence/engine.py#L43)) | For `auto`, matches alias substrings and reference hosts; for explicit vendor, resolves aliases/exact source names or raises. `include_related` appends automatically indicated publishers without replacing explicit scope. Alias matching is heuristic string matching. |
| `Engine.__init__(http=None)` ([72](aegis-cve-evidence/src/aegis_evidence/engine.py#L72)) | Uses injected HTTP (tests) or creates cached live `HTTP`. |
| `Engine.lookup(...)` ([75](aegis-cve-evidence/src/aegis_evidence/engine.py#L75)) | Validates CVE; gets CVE.org discovery metadata; selects sources; builds `Context`; calls each adapter; captures each exception as a bounded source error; adds scope/gap hints; returns `models.result`. **Evidence retrieval:** yes. No LLM and no system change beyond HTTP cache. `installed_version` is carried in context but adapters generally do not decide applicability from it. |
| `list_sources()` ([105](aegis-cve-evidence/src/aegis_evidence/engine.py#L105)) | Returns adapter names/hosts and alias mapping. |

### `sources/base.py`

`Source` ([line 11](aegis-cve-evidence/src/aegis_evidence/sources/base.py#L11)) is the adapter contract. `__init__(http)` stores the client; `referenced(context)` keeps HTTPS references whose exact hostname is declared by the adapter. Public `search(context)` ([23](aegis-cve-evidence/src/aegis_evidence/sources/base.py#L23)) opens a context-local attempted-URL scope, calls deterministic `_search(context)`, and only on an exception invokes the shared strict LLM fallback. Its `finally` block restores the prior URL-tracking context. Every concrete adapter implements abstract `_search(context)`; normal empty results do not invoke the LLM.

### `llm_fallback.py`

One shared fallback serves every source adapter. `SYSTEM_PROMPT` requires exactly the current `Evidence` fields and forbids prior knowledge, paraphrased remediation, inferred versions, extra keys, and Markdown. `_invoke(system, user)` ([69](aegis-cve-evidence/src/aegis_evidence/llm_fallback.py#L69)) makes one Bedrock, Azure OpenAI, or Anthropic call using existing project settings and an optional `AEGIS_ADAPTER_FALLBACK_MODEL` override. `extract_evidence(http, context, source_name, urls, cause)` ([144](aegis-cve-evidence/src/aegis_evidence/llm_fallback.py#L144)) is the only public operation: it can be disabled with `AEGIS_ADAPTER_LLM_FALLBACK=false`; refetches at most four attempted pages through the existing allowlisted/cache-aware HTTP client; strips active/hidden markup; bounds text; sends URLs plus text and exact output shape; then rejects malformed JSON, more than 20 rows, missing/extra fields, mismatched source/CVE/URL, absent exact CVE, incorrect types, and any factual value not present as an exact page-text excerpt. Valid dictionaries become normal `Evidence` objects with an audit note. Empty or unsafe output raises so `Engine.lookup` reports the original and fallback failures under `source_errors`.

### Vendor adapters

Every adapter below is called by `Engine.lookup`; each retrieves publisher data through `HTTP` and returns evidence records. None installs a package or executes remediation.

#### `sources/apache.py`

Parses consolidated Apache Log4j security entries, discovers Tomcat branch/native/JK security pages, and retains other explicitly referenced Apache security pages. Regex constants at [lines 10-16](aegis-cve-evidence/src/aegis_evidence/sources/apache.py#L10) recognize CVEs, fixed versions, affected labels, page names, severity titles, and versions.

| Method (line) | Logic |
|---|---|
| `Apache._log4j_evidence(doc, url, cve)` ([31](aegis-cve-evidence/src/aegis_evidence/sources/apache.py#L31)) | Finds the CVE heading, collects its section, extracts “Versions affected/fixed,” emits one row per parsed fixed branch, or a no-exact-version row. |
| `_tomcat_urls(references)` ([66](aegis-cve-evidence/src/aegis_evidence/sources/apache.py#L66)) | Normalizes referenced Tomcat security pages, discovers current pages from the index, and falls back to a static page list with a coverage warning if the index fails. |
| `_entry_title(node)` ([89](aegis-cve-evidence/src/aegis_evidence/sources/apache.py#L89)) | Accepts CVE advisory headings/strong paragraphs while excluding incidental cross-references. |
| `_product(url)` ([103](aegis-cve-evidence/src/aegis_evidence/sources/apache.py#L103)) | Maps page path to Tomcat, Native Connector, or JK Connector. |
| `_tomcat_evidence(doc, url, cve, warning)` ([111](aegis-cve-evidence/src/aegis_evidence/sources/apache.py#L111)) | Walks document order by release heading/advisory entry, uses the last CVE in incomplete-fix titles, distinguishes “not a vulnerability,” extracts released fixes/affected text/fix links, and emits branch-scoped evidence. Its nested `emit()` flushes the current entry. |
| `Apache._search(context)` ([181](aegis-cve-evidence/src/aegis_evidence/sources/apache.py#L181)) | Deterministic implementation called by inherited `Source.search`. Chooses Log4j/Tomcat from description/product/references, tolerates some page failures when other evidence exists, then parses other Apache security references. Raises when all relevant Tomcat pages fail. |

#### `sources/ibm.py`

Parses IBM support bulletins whose table/prose layouts vary. Module regexes recognize versions, service/fix packs, APARs, and action verbs.

| Function/method (line) | Logic |
|---|---|
| `_role(label)` ([16](aegis-cve-evidence/src/aegis_evidence/sources/ibm.py#L16)) | Maps flexible table headers to semantic roles such as product, component, lower/upper affected, APAR, pack, action, level, or version. |
| `_table(table)` ([42](aegis-cve-evidence/src/aegis_evidence/sources/ibm.py#L42)) | Searches the first five rows for a recognizable role combination and returns `(role_indexes, data_rows)`. |
| `_cell(cells, roles, role)` ([58](aegis-cve-evidence/src/aegis_evidence/sources/ibm.py#L58)) | Safely reads/cleans a role-addressed cell. |
| `_links(cells, roles, *names, base)` ([63](aegis-cve-evidence/src/aegis_evidence/sources/ibm.py#L63)) | Resolves distinct HTTPS links from named role cells. |
| `_fixed_version(action)` ([75](aegis-cve-evidence/src/aegis_evidence/sources/ibm.py#L75)) | Searches only text following action/fix verbs, preventing an affected version or APAR alone from becoming a fixed version. |
| `_fix_blocks(doc)` ([89](aegis-cve-evidence/src/aegis_evidence/sources/ibm.py#L89)) | Collects sibling nodes beneath remediation/fix/solution headings regardless of heading depth. |
| `_level_product(level, header)` ([107](aegis-cve-evidence/src/aegis_evidence/sources/ibm.py#L107)) | Infers AIX versus VIOS from explicit words/version prefix; otherwise returns `None`. |
| `_level_prefix(level)` ([116](aegis-cve-evidence/src/aegis_evidence/sources/ibm.py#L116)) | Extracts major/minor/TL prefix for matching AIX fileset ranges. |
| `_branch_label(line, title)` ([125](aegis-cve-evidence/src/aegis_evidence/sources/ibm.py#L125)) | Recognizes short product/branch labels but rejects action text and explanatory prose. |
| `_prose_nodes(block)` ([134](aegis-cve-evidence/src/aegis_evidence/sources/ibm.py#L134)) | Yields non-table paragraphs/list items/headings, including nested layout wrappers. |
| `IBM._bulletin_url(reference)` ([152](aegis-cve-evidence/src/aegis_evidence/sources/ibm.py#L152)) | Accepts specific IBM legacy UID and support-page paths and canonicalizes them; rejects bulletin wrapper/other hosts. |
| `IBM._search(context)` ([165](aegis-cve-evidence/src/aegis_evidence/sources/ibm.py#L165)) | Gets IBM URLs from CVE.org references or NVD fallback; requires target CVE on page; parses publish date, fileset ranges, product/action rows, AIX/VIOS pack rows, and older free-form branch fixes; preserves links/APAR notes; deduplicates repeated rows; raises on unrecognized remediation. Public `Source.search` handles any fallback. |

#### `sources/oracle_cpu.py`

| Method (line) | Logic |
|---|---|
| `OracleCPU._search(context)` ([17](aegis-cve-evidence/src/aegis_evidence/sources/oracle_cpu.py#L17)) | Reads Oracle's CVE-to-CPU map including continuation rows; adds referenced CPU fallback; filters Java context; parses CPU risk matrices and “also addresses” relationships. Affected versions are deliberately not fixed versions. It adds a mapping-only row when no matrix match and optionally augments Java rows with release notes. |
| `_jdk_releases(context, cpu_url, cpu_rows)` ([97](aegis-cve-evidence/src/aegis_evidence/sources/oracle_cpu.py#L97)) | Derives CPU month/year, finds corresponding Java Management release page, determines affected major branches, follows Java release notes, requires CPU language, extracts builds/dates, and returns branch-specific CPU releases plus possible latest cumulative candidates. It preserves all affected branches rather than applying inventory selection during collection. |

#### `sources/oracle_linux.py`

`OracleLinux._search(context)` ([14](aegis-cve-evidence/src/aegis_evidence/sources/oracle_linux.py#L14)) opens the official CVE page, requires the CVE in page text, follows ELSA links (including CVE.org references), requires the CVE on the advisory, finds filename tables, and emits each RPM filename as a fixed package by release. Oracle Linux packages do not prove a fix for Rocky or another distribution.

#### `sources/rocky.py`

`Rocky._search(context)` ([14](aegis-cve-evidence/src/aegis_evidence/sources/rocky.py#L14)) pages through Rocky Apollo with `filters.cve` and RPM inclusion; verifies the CVE in summary and detail; selects per-product RPM NVRAs (with a single-product repository fallback); emits fixed-package evidence or an explicit no-RPM row. Maximum ten pages are inspected.

#### `sources/redhat.py`

`RedHat._search(context)` ([15](aegis-cve-evidence/src/aegis_evidence/sources/redhat.py#L15)) first tries the public CVE statement, then pages up to ten CSAF index pages, loads RHSA CSAF documents, maps full product IDs, restricts to the requested CVE and `fixed` product status/vendor-fix remediations, and emits package/product rows. A statement is assessment evidence, not a package fix; RH packages do not prove another distro's fix.

#### `sources/debian.py`

| Function/method (line) | Logic |
|---|---|
| `_role(header)` ([16](aegis-cve-evidence/src/aegis_evidence/sources/debian.py#L16)) | Maps header variants to package/release/status/version/fixed-version/kind/origin roles. |
| `_package(cell)` ([34](aegis-cve-evidence/src/aegis_evidence/sources/debian.py#L34)) | Prefers a source-package link and strips PTS suffix. |
| `_state(value, status)` ([42](aegis-cve-evidence/src/aegis_evidence/sources/debian.py#L42)) | Classifies not-affected, unfixed/unknown, fixed, or unspecified states using conservative negative terms. |
| `Debian._search(context)` ([57](aegis-cve-evidence/src/aegis_evidence/sources/debian.py#L57)) | Requires CVE identity in title/h1; discovers semantic table columns; preserves package/release/status rows; only treats a valid minimum-fix-table value as exact fix; raises on unknown layouts; adds upstream note links without calling them Debian fixes; deduplicates exact rows. |

#### `sources/ubuntu.py`

`Ubuntu._search(context)` ([12](aegis-cve-evidence/src/aegis_evidence/sources/ubuntu.py#L12)) requires target CVE, finds Ubuntu release tables, carries forward blank package cells, extracts a version only from statuses beginning with `Fixed`, and otherwise records the status with no fix claim.

#### `sources/suse.py`

`SUSE._search(context)` ([12](aegis-cve-evidence/src/aegis_evidence/sources/suse.py#L12)) requires target CVE, finds tables headed by “Fixed package version,” and emits product/version update evidence.

#### `sources/postgresql.py`

| Function/method (line) | Logic |
|---|---|
| `_column(header)` ([14](aegis-cve-evidence/src/aegis_evidence/sources/postgresql.py#L14)) | Maps columns to publication, fixed, or affected roles. |
| `PostgreSQL._search(context)` ([30](aegis-cve-evidence/src/aegis_evidence/sources/postgresql.py#L30)) | Requires CVE in title/h1; parses affected/fixed tables with negative fix filtering; otherwise parses older “versions before” prose; raises on unrecognized layouts rather than returning a vague fix. |

#### `sources/openssl.py`

`OpenSSL._search(context)` ([14](aegis-cve-evidence/src/aegis_evidence/sources/openssl.py#L14)) locates an exact CVE anchor in OpenSSL's catalogue, collects text until the next CVE, parses `from X before Y` ranges, and emits per-branch fixed releases. Unmatched prose yields no evidence.

#### `sources/sqlite.py`

`SQLite._search(context)` ([13](aegis-cve-evidence/src/aegis_evidence/sources/sqlite.py#L13)) finds catalogue rows containing the target CVE, optionally parses a version from the second cell, preserves row text as remediation, and warns that distribution/application exposure requires separate proof.

#### `sources/tibco.py`

`TIBCO._search(context)` ([14](aegis-cve-evidence/src/aegis_evidence/sources/tibco.py#L14)) follows only referenced TIBCO advisory/external-article URLs, requires target CVE, extracts environment/systems-affected and resolution/remediation sections, and emits only when resolution text exists.

#### `sources/eclipse.py`

| Method (line) | Logic |
|---|---|
| `_openj9_releases(context)` ([19](aegis-cve-evidence/src/aegis_evidence/sources/eclipse.py#L19)) | Queries GitHub releases, requires target CVE plus resolved-security language, parses `openj9-X` tags and compatibility, and emits fixed OpenJ9 releases. |
| `_semeru_releases(context)` ([50](aegis-cve-evidence/src/aegis_evidence/sources/eclipse.py#L50)) | Parses IBM Semeru branch-fix columns for exact CVE and emits runtime branch releases. |
| `search(context)` ([87](aegis-cve-evidence/src/aegis_evidence/sources/eclipse.py#L87)) | Preserves merged Eclipse OMR PR/commit evidence as a source patch, explicitly not a fixed release; then calls both supplemental release lookups and reports/raises their errors depending on whether other evidence exists. |

### Interfaces around the engine

#### `server.py`

`main()` ([11](aegis-cve-evidence/src/aegis_evidence/server.py#L11)) configures logging from `AEGIS_LOG_LEVEL`, lazily imports MCP, creates one `Engine`, defines three nested MCP tools, and runs stdio transport:

- `get_cve_remediations(...)` calls `Engine.lookup` for explicit/related vendors.
- `detect_cve_sources(...)` calls it with `vendor="auto"`.
- `available_sources()` returns registry metadata.

The tools return evidence; they do not determine embedded-component usage or deploy fixes.

#### `cli.py`

| Function (line) | Behavior |
|---|---|
| `save_response(response, vendor, output_dir=None)` ([13](aegis-cve-evidence/src/aegis_evidence/cli.py#L13)) | Creates `src/output_data`, sanitizes vendor for a filename, and writes formatted JSON. |
| `main()` ([24](aegis-cve-evidence/src/aegis_evidence/cli.py#L24)) | Parses one CVE/vendor and optional context flags, calls `Engine.lookup`, saves/prints result, and prints path to stderr. |

Example:

```powershell
python -m aegis_evidence.cli CVE-2021-44832 Apache --product "Apache Log4j2"
```

#### `batch.py`

| Function (line) | Behavior |
|---|---|
| `rows(path)` ([14](aegis-cve-evidence/src/aegis_evidence/batch.py#L14)) | Streams CSV dictionaries or directly parses the first XLSX sheet XML/shared strings from the ZIP; nested `number(cell)` converts column letters to zero-based indexes. It supports only the assumed `sheet1.xml` layout. |
| `main()` ([49](aegis-cve-evidence/src/aegis_evidence/batch.py#L49)) | Iterates workbook rows, optionally limits count, performs auto-vendor lookups, and flushes one JSON object per line. |

#### `run_all_cves.ps1`

PowerShell batch example ([lines 1-38](aegis-cve-evidence/run_all_cves.ps1#L1)). It requires the local `.venv`, contains a fixed list of CVE/vendor examples, invokes `aegis_evidence.cli` serially, stops on any nonzero exit, and writes through the CLI to `src/output_data`. It is not an all-input discovery mechanism despite its name.

## 6. Context and remediation assessment

### `context_gathered/context_manager.py`

**Purpose.** Standalone Oracle persistence utility for a request/response context JSON object. No other inspected runtime file calls it; the remediation runner reads JSON files directly. It imports `oracledb` and changes a database.

| Function (line) | Inputs/return and behavior |
|---|---|
| `ensure_table(connection)` ([19](aegis-cve-evidence/context_gathered/context_manager.py#L19)) | Checks `user_tables`; creates `CVE_CONTEXT` with identity key, metadata, request/response CLOB JSON checks, and timestamp when absent; tolerates only race-condition ORA-955 after rechecking. **Database DDL:** yes. |
| `load_template(path)` ([48](aegis-cve-evidence/context_gathered/context_manager.py#L48)) | Reads JSON; requires object-shaped `request`/`response`, bounded nonempty request CVE/vendor and platform, and matching response CVE when present; returns normalized payload. |
| `save_context(connection, payload)` ([71](aegis-cve-evidence/context_gathered/context_manager.py#L71)) | Inserts platform/CVE/vendor plus complete request/response JSON CLOBs, returns generated ID, and commits. **Database write:** yes. |
| `get_context(connection, context_id)` ([92](aegis-cve-evidence/context_gathered/context_manager.py#L92)) | Selects one row, decodes CLOB JSON, returns a dictionary with timestamp, or `None`. Nested `decode` handles LOB `.read()`. |
| `main()` ([111](aegis-cve-evidence/context_gathered/context_manager.py#L111)) | Loads template and Oracle settings, connects, creates table, inserts, and prints saved record. Environment variables: `ORACLE23AI_PASSWORD`, `ORACLE23AI_USER`, `ORACLE23AI_HOST`, `ORACLE23AI_PORT`, `ORACLE23AI_SERVICE`. **Security finding:** source line 15 contains a hard-coded password fallback; its value is intentionally not reproduced here and should be removed/rotated. |

This module stores supplied context; it does not gather that context from a server.

### Stored context field structures

The following JSON files are data/templates, not executable logic. Per the requested documentation scope, their fields are explained once.

#### `context_gathered/context_template.json`

- Top level: `platform_name`, `request`, `response`.
- `request`: dummy marker, request ID, operation, CVE, vendor, target server/access method, requested application/component, and `collect` field names.
- `response`: dummy marker, request/CVE/status/time; `server` identity/OS/architecture; `application` identity/version/path/status; `components` with vendor/distribution/version/path/relationship and command-evidence entries; `missing_context`; warnings.
- All included command outputs are explicitly dummy. A PATH result does not prove the application uses that runtime.

#### `context_gathered/test_inventory_profiles.json`

Maps each product group to synthetic `application_version`, installation path, default/product-specific installed versions, component path, package lineage, runtime, and verification method. These values drive demonstrations only.

#### `context_gathered/test/<slug>/cves/*.context.json`

- `request`: `is_dummy`, request ID, operation, CVE, vendor, product group, synthetic context kind.
- `response.server`: hostnames, IPs, OS names, architecture.
- `response.application`: application/product names, install path, collection status.
- `response.components[]`: name/kind/product, synthetic installed version/runtime/path/lineage/verification method, collection status, application relationship, and optional feature configuration.
- `missing_context` and warnings explicitly label test-only inventory.

#### Product bundles and manifests

- `test/<slug>/product_context.json`: schema/context kind, product group, product/component/OS/host lists, synthetic inventory defaults, and CVE entries referencing individual context files.
- `test/manifest.json`: generation/source metadata and product groups with counts, source rows, bundle path, and CVE descriptors.
- `test/product_context.json`: combined product bundles and a synthetic-use warning.
- `context_gathered/product_context.json`: generated product group metadata, publisher/runtime-check policy, inventory labels, and CVE references. Stored paths in these files are absolute paths from the machine that generated them and may not exist on the current machine.

### `remediation/create_test_contexts.py`

**Purpose.** Converts a generated manifest/context set into clearly labelled synthetic inventory fixtures. It writes data only; it does not contact hosts or models.

| Function (line) | Behavior |
|---|---|
| `load(path)` ([13](aegis-cve-evidence/remediation/create_test_contexts.py#L13)) | Reads UTF-8-BOM JSON. |
| `main()` ([17](aegis-cve-evidence/remediation/create_test_contexts.py#L17)) | Loads manifest/profiles; requires a profile per product group; creates per-CVE request/response fixtures with synthetic markers, architecture, installed versions, lineage, relationship and two Log4j feature-specific configurations; writes product bundles, test manifest, combined product context, and a count summary. It deliberately excludes vulnerability/fix/advisory facts from inventory context. |

### `remediation/remedition_agent.py`

The filename intentionally uses `remedition`, and callers preserve that spelling. This is the structured LLM assessment agent. It reads context plus evidence, requests a decision, verifies schema/citations/safety invariants, and saves an audit snapshot. It performs no SSH, patching, package changes, or database writes.

#### Models and important blocks

- `Claim` ([18](aegis-cve-evidence/remediation/remedition_agent.py#L18)): exact `evidence_id` and nonempty quote; extra fields forbidden.
- `Remedy` ([25](aegis-cve-evidence/remediation/remedition_agent.py#L25)): limited route, target/patch, summary, compatibility, and separate fix/applicability/compatibility citations.
- `Decision` ([37](aegis-cve-evidence/remediation/remedition_agent.py#L37)): limited verdict/applicability, optional selected remedy, candidates, claims, blockers, summaries, notes/conflicts/missing/operational guidance.
- `CitationValidationError` ([53](aegis-cve-evidence/remediation/remedition_agent.py#L53)); its `__init__` ([56](aegis-cve-evidence/remediation/remedition_agent.py#L56)) records failed ID/quote/reason and formats an error.

| Function/method (line) | Behavior |
|---|---|
| `load_config(path)` ([78](aegis-cve-evidence/remediation/remedition_agent.py#L78)) | Reads JSON, chooses `LLM_PROVIDER`, restricts Bedrock/Azure, validates positive size limits, loads prompt relative to config, and rejects empty prompt. |
| `required(value, name)` ([96](aegis-cve-evidence/remediation/remedition_agent.py#L96)) | Requires non-placeholder nonempty text. |
| `LLMClient.__init__(config)` ([104](aegis-cve-evidence/remediation/remedition_agent.py#L104)) | Builds Bedrock `converse` client from model/region/credentials/profile or Azure client from endpoint/version/deployment/key and validates configurable token/role names. |
| `LLMClient.generate(messages, prompt)` ([148](aegis-cve-evidence/remediation/remedition_agent.py#L148)) | Calls Bedrock Converse or Azure chat completion; returns `(text, usage, stop_reason)`, rejects no Azure choices/refusal. **LLM call:** yes. |
| `read_json(path)` ([170](aegis-cve-evidence/remediation/remedition_agent.py#L170)) | Reads UTF-8-BOM JSON. |
| `prepare(context, evidence)` ([174](aegis-cve-evidence/remediation/remedition_agent.py#L174)) | Requires context response and matching context/evidence CVE; accepts `evidence` or `advisories` array; assigns `EV-NNN` IDs while preserving every source field; returns assessment package plus metadata. |
| `contains_dummy(value)` ([198](aegis-cve-evidence/remediation/remedition_agent.py#L198)) | Recursively detects any dictionary with `is_dummy: true`. |
| `normalize_test_context_for_assessment(context)` ([204](aegis-cve-evidence/remediation/remedition_agent.py#L204)) | Recursively removes fixture-only keys/warnings and maps test status markers to ordinary verified/complete values for the LLM view. Original context remains in audit hashes/snapshot and drives `is_dummy`. Nested `normalize` performs traversal. |
| `validate_decision(decision, package)` ([243](aegis-cve-evidence/remediation/remedition_agent.py#L243)) | Requires matching CVE; recursively collects all source strings; verifies every cited ID/exact substring and minimum quote length; requires fix identifiers in fix quotes; enforces verdict/remedy/applicability/compatibility/blocker rules. Nested `text_values` flattens strings. This validates traceability/structure, not semantic correctness. |
| `downgrade_invalid_citations(decision, package)` ([290](aegis-cve-evidence/remediation/remedition_agent.py#L290)) | Removes unsupported top-level claims and entire remedies containing a bad citation; forces `INSUFFICIENT_EVIDENCE`/`UNKNOWN`, clears selected remedy, adds safety note, and revalidates Pydantic collections. Nested helpers flatten and test support. |
| `assess(package, client, config)` ([333](aegis-cve-evidence/remediation/remedition_agent.py#L333)) | Rejects oversized input rather than truncating; sends package plus JSON schema; accepts only normal stop reasons; strips optional fences; Pydantic-validates and calls `validate_decision`; performs one bounded repair request. On the second failure it can conservatively downgrade compatibility or citations; other failures raise. **LLM calls:** one or two. |
| `run_agent(context, evidence, client, config, allow_dummy=False)` ([394](aegis-cve-evidence/remediation/remedition_agent.py#L394)) | Prepares input, blocks dummy data unless explicitly allowed, uses normalized test view when allowed, assesses, and returns audit result with `execution_ready: false`, hashes, model/provider/time/usage, original input snapshot, and validation limitation. |
| `main()` ([413](aegis-cve-evidence/remediation/remedition_agent.py#L413)) | Parses context file/stdin, evidence/output/config/provider overrides and dummy option; optionally appends test-context prompt rules; prevents output overwriting protected inputs; constructs client; runs agent; atomically replaces output via `.tmp`; prints decision/path. **Visible defect:** default config is `agent_config.json`, but the repository file is `agent_configs.json`; normal grouped caller passes the correct path explicitly. |

### `remediation/remediation_prompt.txt`

System prompt loaded by `load_config`. It defines trust boundaries, inventory completeness, source authority/scope/freshness, applicability, ecosystem-aware version interpretation, candidate routes, selection rules, verdict semantics, exact-citation limits, compact output, and the explicit prohibition on execution/deployment claims. It also states that the agent has no deterministic package comparator.

### `remediation/agent_configs.json`

Selects `bedrock` by default, names the prompt, sets 10,000 output tokens and 250,000 input characters, and contains nullable Bedrock/Azure overrides. Actual secrets come from environment variables. Azure supports configurable token parameter and system/developer message role.

### `remediation/run_grouped_remediation.py`

**Purpose.** Batch coordinator from grouped CSV to evidence files, remediation subprocesses, per-CVE reasoning, run summaries, and aggregate JSON. `app.py` launches it.

| Function (line) | Behavior |
|---|---|
| `read_json(path)` ([25](aegis-cve-evidence/remediation/run_grouped_remediation.py#L25)) | UTF-8-BOM JSON read. |
| `write_json(path, value)` ([29](aegis-cve-evidence/remediation/run_grouped_remediation.py#L29)) | Creates parents and writes pretty JSON plus newline. |
| `safe_path_part(value)` ([34](aegis-cve-evidence/remediation/run_grouped_remediation.py#L34)) | Replaces Windows-invalid/control characters, strips trailing dot/space, defaults to `Unidentified`. |
| `load_environment()` ([40](aegis-cve-evidence/remediation/run_grouped_remediation.py#L40)) | Optionally loads root `.env`, removes blank AWS profiles so child processes inherit usable settings. |
| `validate_model_credentials(config_path)` ([52](aegis-cve-evidence/remediation/run_grouped_remediation.py#L52)) | For Bedrock only, builds boto3 session selection and checks that some credentials resolve. It does not call the model or prove authorization/model access. |
| `public_reasoning_record(run_id, product, cve_id, result)` ([82](aegis-cve-evidence/remediation/run_grouped_remediation.py#L82)) | Extracts decision rationale, remedies, model/audit hashes, and validation note into a review-focused record. |
| `apply_test_inventory(items, profiles_path)` ([110](aegis-cve-evidence/remediation/run_grouped_remediation.py#L110)) | Matches product/profile, mutates context with explicitly dummy installed version/path/lineage/runtime/verification/relationship markers. Test only. |
| `apply_context_directory(items, context_dir)` ([157](aegis-cve-evidence/remediation/run_grouped_remediation.py#L157)) | Recursively indexes valid per-CVE context JSON; scores candidate match by product group/product/components; replaces partial context when score >0; records missing contexts and vendor/OS updates. Invalid files are skipped. Nested `score` supplies heuristic matching. |
| `generated_run_id()` ([213](aegis-cve-evidence/remediation/run_grouped_remediation.py#L213)) | UTC timestamp plus UUID suffix. |
| `_split(value)` ([218](aegis-cve-evidence/remediation/run_grouped_remediation.py#L218)) | Ordered distinct split of ` | ` fields. |
| `read_grouped_csv(path)` ([223](aegis-cve-evidence/remediation/run_grouped_remediation.py#L223)) | Requires Product/Component/CVE columns; expands each CVE into an item with partial, non-dummy context and scanner observation metadata. No host collection occurs. |
| `select_items(...)` ([271](aegis-cve-evidence/remediation/run_grouped_remediation.py#L271)) | Applies product/CVE/row filters, deduplicates product+CVE, optionally keeps one per product, attaches matching source rows, and sorts. |
| `cve_sort_key(cve)` ([297](aegis-cve-evidence/remediation/run_grouped_remediation.py#L297)) | Validates and returns numeric `(year, sequence)`. “Latest” means highest identifier, not publication date or severity. |
| `latest_cve_per_component(items)` ([305](aegis-cve-evidence/remediation/run_grouped_remediation.py#L305)) | Keeps highest identifier per product group/component/source-row identity. |
| `fetch_all(items, include_related)` ([320](aegis-cve-evidence/remediation/run_grouped_remediation.py#L320)) | Adds `src` to import path, creates `Engine`, collects installed versions from context, performs direct engine lookup per item, and keys result by product group+CVE. **Internet evidence retrieval:** yes. |
| `main()` ([341](aegis-cve-evidence/remediation/run_grouped_remediation.py#L341)) | Validates mutually exclusive selection/error/dummy options and run ID; reads/selects contexts; optionally applies synthetic inventory; prevents run overwrite; writes initial aggregate; fetches all evidence; for each item writes evidence, launches `remedition_agent.py` via subprocess/stdin, writes result/reasoning/rolling aggregate; supports fetch-only and controlled continuation; finalizes summary/status. It recommends only and never deploys. |

Generated storage under `remediation/runs`:

```text
runs/grouped_remediation_<run-id>.json        aggregate/audit snapshot
runs/<run-id>/run_summary.json                compact per-item paths/status
runs/<run-id>/reasoning_by_cve.json           accumulated public rationale
runs/<run-id>/<safe-product>/<CVE>/
  mcp_evidence.json
  remediation_result.json
  reasoning.json
```

## 7. Experimental internet lookup package

`aegis-cve-evidence/Internet_lookup` is project-owned but is not imported by `app.py`, `run_grouped_remediation.py`, or `aegis_evidence.engine`. It is a second lookup/reconciliation implementation with its own source tiers, LLM extraction, cache, logs, and result schema.

### `Internet_lookup/__init__.py`

Package facade ([lines 1-5](aegis-cve-evidence/Internet_lookup/__init__.py#L1)); re-exports `Config`, `CveRow`, `HostProfile`, `LookupResult`, and `run_fallback`.

### `Internet_lookup/__main__.py`

`main()` ([8](aegis-cve-evidence/Internet_lookup/__main__.py#L8)) parses one CVE, component/type/status, optional host OS/TL/SP/build/packages, cache flag, and search provider; creates models/config; calls `run_fallback`; prints JSON. Package example:

```powershell
cd aegis-cve-evidence
python -m Internet_lookup CVE-2021-44832 --component "Apache Log4j2" --os "IBM AIX 7.2"
```

### `Internet_lookup/config.py`

**Environment:** loads root `.env`; uses `CVE_FALLBACK_LLM_PROVIDER`/`LLM_PROVIDER`, `CVE_FALLBACK_FAST_MODEL`, `CVE_FALLBACK_DEEP_MODEL`, `BEDROCK_MODEL_ID`, Azure deployment variables, and `CVE_FALLBACK_SEARCH`.

| Symbol (line) | Role |
|---|---|
| `_load_project_env()` ([15](aegis-cve-evidence/Internet_lookup/config.py#L15)) | Loads repository `.env` if dotenv exists. |
| `_provider()` ([27](aegis-cve-evidence/Internet_lookup/config.py#L27)) | Chooses fallback provider, then project provider, then Bedrock. |
| `_model(tier)` ([31](aegis-cve-evidence/Internet_lookup/config.py#L31)) | Chooses explicit fast/deep model or provider-specific default. |
| `Config` ([44](aegis-cve-evidence/Internet_lookup/config.py#L44)) | Dataclass containing provider/models, search result limits, per-CVE search/fetch/LLM budgets, parallelism, 240-second deadline, fetch/LLM limits, heartbeat, cache TTL, and output directories. Default search is keyless `direct`. |
| `BudgetExceeded` ([82](aegis-cve-evidence/Internet_lookup/config.py#L82)) | Signals exhausted operation allowance. |
| `Budget.__init__(cfg)` ([89](aegis-cve-evidence/Internet_lookup/config.py#L89)) | Initializes thread-safe search/fetch/LLM counters. |
| `Budget.take(kind)` ([94](aegis-cve-evidence/Internet_lookup/config.py#L94)) | Validates kind through its limit map; atomically rejects or increments. |
| `Budget.left(kind)` ([105](aegis-cve-evidence/Internet_lookup/config.py#L105)) | Returns remaining allowance. |

### `Internet_lookup/models.py`

Dataclasses passed between stages:

- `CveRow` ([10](aegis-cve-evidence/Internet_lookup/models.py#L10)): CVE, component/type, scanner status, arbitrary extra CSV fields.
- `HostProfile` ([19](aegis-cve-evidence/Internet_lookup/models.py#L19)): OS/TL/SP/build/packages; `label()` ([26](aegis-cve-evidence/Internet_lookup/models.py#L26)) joins available OS/TL/SP or returns `unknown host`.
- `SearchHit` ([33](aegis-cve-evidence/Internet_lookup/models.py#L33)): URL/title/snippet/query.
- `Page` ([41](aegis-cve-evidence/Internet_lookup/models.py#L41)): fetch/validation state and text.
- `ExtractedFacts` ([54](aegis-cve-evidence/Internet_lookup/models.py#L54)): one-source descriptions, products, versions, fixes with evidence, stance, CVSS, references, notes.
- `Reconciled` ([72](aegis-cve-evidence/Internet_lookup/models.py#L72)): combined fields/fixes/stances/conflicts.
- `LookupResult` ([86](aegis-cve-evidence/Internet_lookup/models.py#L86)): final status/evidence/options/human-review/stats/log/error; `to_dict()` ([108](aegis-cve-evidence/Internet_lookup/models.py#L108)) calls `asdict`.

### `Internet_lookup/sources.py`

Defines tier-1 publisher/upstream, tier-2 CVE/NVD/CISA, and tier-3 aggregator allowlists; channel plans; source-specific query vocabulary; and exact CVE matching.

| Symbol (line) | Behavior |
|---|---|
| `_host_matches(host, domain)` ([36](aegis-cve-evidence/Internet_lookup/sources.py#L36)) | Exact/subdomain match. |
| `tier_of(url)` ([40](aegis-cve-evidence/Internet_lookup/sources.py#L40)) | Parses URL and returns trust tier only when host and required path prefix match. |
| `other_cve_in_url(url, cve_id)` ([55](aegis-cve-evidence/Internet_lookup/sources.py#L55)) | Returns a different CVE embedded in URL, preventing obvious near-miss fetches. |
| `exact_cve_regex(cve_id)` ([63](aegis-cve-evidence/Internet_lookup/sources.py#L63)) | Builds boundary-aware case-insensitive regex so a longer numeric suffix cannot match. |
| `Plan` ([70](aegis-cve-evidence/Internet_lookup/sources.py#L70)) | Component type, site targets, explanatory note. |
| `_query_term(value, max_chars=100)` ([101](aegis-cve-evidence/Internet_lookup/sources.py#L101)) | Removes quotes/control whitespace, collapses/bounds untrusted CSV text, drops placeholder terms. |
| `_site_intent(site)` ([110](aegis-cve-evidence/Internet_lookup/sources.py#L110)) | Returns publisher-specific evidence keywords or a generic fallback. |
| `heuristic_component_type(component, host_os=None)` ([115](aegis-cve-evidence/Internet_lookup/sources.py#L115)) | Rules IBM/AIX, PostgreSQL, unknown labels, otherwise open source. `host_os` is currently unused. |
| `plan_for(component_type)` ([129](aegis-cve-evidence/Internet_lookup/sources.py#L129)) | Selects known channel plan or `other`. |
| `build_queries(cve_id, component, plan, host_label, context_term=None)` ([140](aegis-cve-evidence/Internet_lookup/sources.py#L140)) | Builds broad advisory and remediation queries plus IBM-specific and source-intent site queries; quotes sanitized product/detail/host; case-insensitively deduplicates. Built-in open-source plan yields six searches. |

### `Internet_lookup/search.py`

| Class/function (line) | Behavior |
|---|---|
| `SearchProvider.search(...)` ([16-20](aegis-cve-evidence/Internet_lookup/search.py#L16)) | Abstract-by-convention interface; raises `NotImplementedError`. |
| `DirectCveSearch` ([23](aegis-cve-evidence/Internet_lookup/search.py#L23)) | Contains canonical URL templates. `__init__` stores logger; `search` ([46](aegis-cve-evidence/Internet_lookup/search.py#L46)) extracts CVE and optional site, returns canonical URLs for NVD/CVE API or the requested known publisher. It is deterministic discovery, not a general internet search. |
| `AnthropicWebSearch` ([64](aegis-cve-evidence/Internet_lookup/search.py#L64)) | Stores LLM/config/logger; `search` ([71](aegis-cve-evidence/Internet_lookup/search.py#L71)) requires direct Anthropic provider, consumes LLM budget, calls the Anthropic web-search tool once, extracts result blocks, logs token usage. |
| `BraveSearch` ([108](aegis-cve-evidence/Internet_lookup/search.py#L108)) | Reads `BRAVE_API_KEY`; `search` ([116](aegis-cve-evidence/Internet_lookup/search.py#L116)) calls Brave REST with query/count/timeouts and maps web results. |
| `make_search(cfg, llm, log)` ([135](aegis-cve-evidence/Internet_lookup/search.py#L135)) | Constructs `direct`, `brave`, or `anthropic`; rejects unknown values. |

### `Internet_lookup/fetch.py`

| Function/class (line) | Behavior |
|---|---|
| `html_to_text(html)` ([17](aegis-cve-evidence/Internet_lookup/fetch.py#L17)) | Uses BeautifulSoup when available to remove script/style/noscript/SVG and extract title/text; regex fallback otherwise; normalizes whitespace. |
| `window_around(text, cve_id, max_chars)` ([34](aegis-cve-evidence/Internet_lookup/fetch.py#L34)) | Returns full short text, first window when CVE absent, or a window around first exact CVE to bound LLM input. |
| `Fetcher.__init__(cfg, log, budget)` ([46](aegis-cve-evidence/Internet_lookup/fetch.py#L46)) | Stores dependencies. |
| `Fetcher.fetch(url, via="search")` ([49](aegis-cve-evidence/Internet_lookup/fetch.py#L49)) | Rejects non-allowlisted URL, consumes fetch budget, GETs with UA/stream/timeouts/redirects, rechecks final allowlist, caps bytes/elapsed collection, decodes and converts HTML, and returns a success/failure `Page` instead of raising request errors. |

### `Internet_lookup/llm.py`

| Function/method (line) | Behavior |
|---|---|
| `parse_json(text)` ([19](aegis-cve-evidence/Internet_lookup/llm.py#L19)) | Strips optional code fences/chatter by selecting first-to-last braces and JSON-decodes; malformed/truncated JSON raises. |
| `LLM.__init__(cfg, log, budget)` ([30](aegis-cve-evidence/Internet_lookup/llm.py#L30)) | Stores configuration/logger/budget, lazy client, lock, token counters. |
| `LLM.client` ([38](aegis-cve-evidence/Internet_lookup/llm.py#L38)) | Lazily builds Anthropic, Bedrock, or Azure client using project environment, timeouts, retries, explicit credentials/profile, and provider validation. |
| `record_usage(...)` ([81](aegis-cve-evidence/Internet_lookup/llm.py#L81)) | Atomically adds tokens and logs purpose/model/count/duration. |
| `complete(tier, system, user, max_tokens, purpose)` ([87](aegis-cve-evidence/Internet_lookup/llm.py#L87)) | Consumes LLM budget; selects fast/deep model; calls provider-specific API; extracts text/token counts; always clears activity; records usage; returns text. **LLM call:** yes. |

### `Internet_lookup/steps.py`

Prompt constants require page-only extraction, compact arrays, exact evidence snippets, source-limited reconciliation, and conservative host mapping.

| Function (line) | Behavior |
|---|---|
| `_norm(s)` ([17](aegis-cve-evidence/Internet_lookup/steps.py#L17)) | Lowercase whitespace normalization for provenance checks. |
| `_short(url)` ([21](aegis-cve-evidence/Internet_lookup/steps.py#L21)) | Short log label. |
| `extract_facts(llm, cfg, log, page, cve_id)` ([54](aegis-cve-evidence/Internet_lookup/steps.py#L54)) | Windows page text, prompts fast model, parses JSON into `ExtractedFacts`, filters types/stance/URLs, and calls provenance validation. **LLM call:** yes. |
| `_num(v)` ([84](aegis-cve-evidence/Internet_lookup/steps.py#L84)) | Safe optional float conversion. |
| `_verify_provenance(f, page_text, log, tag)` ([91](aegis-cve-evidence/Internet_lookup/steps.py#L91)) | Drops each fix/stance whose exact normalized snippet is absent and CVSS number absent from page. It does not independently prove correct interpretation/branch scope. |
| `reconcile(all_facts)` ([117](aegis-cve-evidence/Internet_lookup/steps.py#L117)) | Sorts by tier, selects first descriptions/products, deduplicates affected/fixed data, prioritizes tier 2 for severity, records conflicts/unresolved same-tier differences, and derives summary stance. |
| `llm_resolve(llm, log, rec, cve_id)` ([197](aegis-cve-evidence/Internet_lookup/steps.py#L197)) | Asks deep model to resolve remaining CVSS conflicts; applies only numeric recognized fields. **LLM call:** yes. |
| `deterministic_options(rec)` ([233](aegis-cve-evidence/Internet_lookup/steps.py#L233)) | Creates up to three low-confidence, host-unverified upgrades from sourced fixes or one `no_fix` option. “No fix found” is not a vendor no-fix claim. |
| `map_and_rank(...)` ([249](aegis-cve-evidence/Internet_lookup/steps.py#L249)) | Sends reconciled facts/host to deep model, caps options, validates enums, removes URLs never retrieved, lowers confidence without citations, and forces unverified applicability without a host. **LLM call:** yes. |
| `classify_component(...)` ([285](aegis-cve-evidence/Internet_lookup/steps.py#L285)) | Fast-model classification into four allowed types with fallback to `other`. |

### `Internet_lookup/runlog.py`

`StepOutcome.__init__` ([21](aegis-cve-evidence/Internet_lookup/runlog.py#L21)) initializes a mutable summary. `RunLogger` creates a unique JSONL log and console progress channel:

- `__init__` ([26](aegis-cve-evidence/Internet_lookup/runlog.py#L26)) creates log directory/file and state locks.
- `elapsed()` ([43](aegis-cve-evidence/Internet_lookup/runlog.py#L43)) returns run seconds.
- `_emit(...)` ([46](aegis-cve-evidence/Internet_lookup/runlog.py#L46)) writes/flushes structured JSON and optional console line under lock.
- `info`/`warn` ([67](aegis-cve-evidence/Internet_lookup/runlog.py#L67)) are level wrappers.
- `activity`/`clear_activity` ([73](aegis-cve-evidence/Internet_lookup/runlog.py#L73)) maintain current waits.
- `_heartbeat(...)` ([82](aegis-cve-evidence/Internet_lookup/runlog.py#L82)) periodically logs running/stuck status; it does not cancel work.
- `step(...)` ([93](aegis-cve-evidence/Internet_lookup/runlog.py#L93)) context manager increments step, starts daemon heartbeat, logs success/error, stops heartbeat, and re-raises errors.
- `close()` ([114](aegis-cve-evidence/Internet_lookup/runlog.py#L114)) best-effort closes the log.

### `Internet_lookup/pipeline.py`

`FallbackRun` is the orchestrator. Its `__init__` ([27](aegis-cve-evidence/Internet_lookup/pipeline.py#L27)) wires row/host/evidence/config, logger, budgets, provider/fetcher or test doubles, start time, and all intermediate collections.

| Method (line) | Behavior |
|---|---|
| `expired()` ([53](aegis-cve-evidence/Internet_lookup/pipeline.py#L53)) | Compares wall time with run deadline, records one degradation warning, and prevents new costly stages. It does not cancel an in-flight request. |
| `guarded(name, detail, fn)` ([62](aegis-cve-evidence/Internet_lookup/pipeline.py#L62)) | Runs a logged step; records budget/other failures and returns `None` so the pipeline can degrade. |
| `run()` ([75](aegis-cve-evidence/Internet_lookup/pipeline.py#L75)) | Catches unexpected orchestration errors, always emits a result, closes log. |
| `_run()` ([84](aegis-cve-evidence/Internet_lookup/pipeline.py#L84)) | Ordered intake/cache/context/plan/query/search/fetch/validate/extract/follow/reconcile/map flow with deadline checks. |
| `_intake(s)` ([106](aegis-cve-evidence/Internet_lookup/pipeline.py#L106)) | Logs scanner status and missing fields; it does not fill them. |
| `_cache_path()` ([113](aegis-cve-evidence/Internet_lookup/pipeline.py#L113)) | Builds sanitized key from CVE/component/host. Provider/model/config are not in the key. |
| `_cache_lookup(s)` ([118](aegis-cve-evidence/Internet_lookup/pipeline.py#L118)) | Reads fresh JSON into `LookupResult`, marks cache hit. |
| `_build_context(s)` ([129](aegis-cve-evidence/Internet_lookup/pipeline.py#L129)) | Logs supplied component/type/host. |
| `_plan_sources(s)` ([133](aegis-cve-evidence/Internet_lookup/pipeline.py#L133)) | Uses heuristic, otherwise LLM classification with `other` fallback; selects plan. |
| `_build_queries(s)` ([146](aegis-cve-evidence/Internet_lookup/pipeline.py#L146)) | Pulls CSV component/affected-symbol context, calls `build_queries`, logs each. |
| `_search(s)` ([158](aegis-cve-evidence/Internet_lookup/pipeline.py#L158)) | Enforces deadline/search budget, stops after two consecutive failures, filters non-allowlisted/other-CVE/duplicate hits, ranks by tier, caps candidates. |
| `_tier_mix(urls)` ([205](aegis-cve-evidence/Internet_lookup/pipeline.py#L205)) | Counts T1/T2/T3 URLs for logs. |
| `_fetch_many(urls, via)` ([213](aegis-cve-evidence/Internet_lookup/pipeline.py#L213)) | Parallel ordered fetch map with per-page logs. |
| `_fetch_pages(s)` ([223](aegis-cve-evidence/Internet_lookup/pipeline.py#L223)) | Fetches candidates and appends every success/failure page. |
| `_validate_hits(s)` ([228](aegis-cve-evidence/Internet_lookup/pipeline.py#L228)) | Accepts search pages only when text contains exact CVE; records rejections. |
| `_extract_one(page)` ([244](aegis-cve-evidence/Internet_lookup/pipeline.py#L244)) | Calls fact extraction, logs facts, captures budget/model/JSON failures. |
| `_extract_pages(pages)` ([258](aegis-cve-evidence/Internet_lookup/pipeline.py#L258)) | Parallel extraction and fact accumulation. |
| `_extract_all(s)` ([264](aegis-cve-evidence/Internet_lookup/pipeline.py#L264)) | Extracts all validated pages and summarizes counts. |
| `_follow_references(s)` ([268](aegis-cve-evidence/Internet_lookup/pipeline.py#L268)) | Takes bounded new tier-1/2 references from extracted facts, fetches them, trusts successful pages as coming from validated sources even without target CVE text, then extracts. |
| `_reconcile(s)` ([291](aegis-cve-evidence/Internet_lookup/pipeline.py#L291)) | Runs deterministic reconcile and optional LLM conflict resolution. |
| `_map_and_rank(s)` ([302](aegis-cve-evidence/Internet_lookup/pipeline.py#L302)) | Uses conservative no-fact outcome; otherwise LLM mapping with deterministic fallback and error/degradation record. |
| `_build_result()` ([321](aegis-cve-evidence/Internet_lookup/pipeline.py#L321)) | Builds human-review reasons, status, complete source fetch/validation list, usage/stats/log/error. |
| `_emit_step()` ([361](aegis-cve-evidence/Internet_lookup/pipeline.py#L361)) | Returns cached result or writes run JSON; caches only `ok`/`partial`; returns an error result if emission fails. **File writes:** results/cache. |
| `run_fallback(...)` ([385](aegis-cve-evidence/Internet_lookup/pipeline.py#L385)) | Public API; normalizes/validates CVE and constructs `FallbackRun`, with injectable LLM/search/fetcher for tests. |

### `Internet_lookup/tests_related_files/test_internet_lookup_from_csv.py`

Executable live harness plus offline tests. It adds the parent of `Internet_lookup` to `sys.path`, reads project CSV fields into lookup models, checks CVE API connectivity, runs bounded live lookups, and writes ignored `artifacts/cache`, `logs`, `results`, and `latest_csv_lookup.json`.

| Function/class (line) | Behavior |
|---|---|
| `_normalized` / `_get` ([45](aegis-cve-evidence/Internet_lookup/tests_related_files/test_internet_lookup_from_csv.py#L45)) | Normalize headers and retrieve alias values. |
| `CsvLookupInput` ([58](aegis-cve-evidence/Internet_lookup/tests_related_files/test_internet_lookup_from_csv.py#L58)) | Row number, `CveRow`, optional host. |
| `load_csv_inputs(path)` ([64](aegis-cve-evidence/Internet_lookup/tests_related_files/test_internet_lookup_from_csv.py#L64)) | Expands each row/CVE, maps product/component/status/OS, and preserves nonempty original fields. |
| `connectivity_check(cve_id, timeout_s=15)` ([95](aegis-cve-evidence/Internet_lookup/tests_related_files/test_internet_lookup_from_csv.py#L95)) | GETs CVE API and verifies target ID in body; returns structured result rather than raising request errors. |
| `choose_inputs(...)` ([110](aegis-cve-evidence/Internet_lookup/tests_related_files/test_internet_lookup_from_csv.py#L110)) | Filters CVE/row and caps selection. |
| `run_live(args)` ([120](aegis-cve-evidence/Internet_lookup/tests_related_files/test_internet_lookup_from_csv.py#L120)) | Runs preflight and lookup(s), configures artifact directories, writes/prints full results, returns success only for `ok`/`partial`. |
| `build_parser()` / `main()` ([157](aegis-cve-evidence/Internet_lookup/tests_related_files/test_internet_lookup_from_csv.py#L157)) | CLI contract and positive-limit enforcement. |
| Five `test_*` functions ([176-284](aegis-cve-evidence/Internet_lookup/tests_related_files/test_internet_lookup_from_csv.py#L176)) | Cover CSV mapping, keyless URL discovery, specific/sanitized/bounded queries, IBM vocabulary, and an offline fake end-to-end validated source/fix. Tests do not prove live publisher/LLM availability. |

## 8. Tests

Tests use `unittest` or pytest with fake HTTP/LLM data where applicable. Passing tests demonstrate the coded transformations and guards under fixtures, not live publisher stability, host compatibility, or deployability.

### `test_group_cves_by_component.py`

- `classification(...)` ([18](test_group_cves_by_component.py#L18)) builds a validated-classification-shaped fixture.
- `GroupingTests.enriched_row(...)` ([34](test_group_cves_by_component.py#L34)) builds an enriched CSV row.
- `test_enrichment_keeps_one_row_per_cve_before_grouping` ([39](test_group_cves_by_component.py#L39)) protects per-CVE enrichment granularity.
- `test_same_component_under_different_products_is_not_combined` ([63](test_group_cves_by_component.py#L63)) verifies compound grouping key.
- `test_writer_creates_grouped_csv` ([73](test_group_cves_by_component.py#L73)) verifies output creation/content.
- `test_enrich_endpoint_persists_run_and_grouped_files` ([83](test_group_cves_by_component.py#L83)) exercises FastAPI enrichment persistence with mocks.
- `test_reuse_endpoint_groups_saved_enrichment_file` ([107](test_group_cves_by_component.py#L107)) covers saved-file reuse.
- `test_selected_pipeline_writes_only_checked_component_rows` ([134](test_group_cves_by_component.py#L134)) covers selected-index CSV scoping.
- `test_selected_pipeline_passes_per_cve_context_directory_to_runner` ([170](test_group_cves_by_component.py#L170)) checks subprocess context flags.
- `test_grouping_uses_run_specific_file_when_default_is_locked` ([193](test_group_cves_by_component.py#L193)) covers Windows file-lock fallback.
- `test_pipeline_events_stream_terminal_status_once` ([217](test_group_cves_by_component.py#L217)) covers terminal SSE behavior.
- `test_pipeline_status_recovers_saved_run_after_restart` ([236](test_group_cves_by_component.py#L236)) covers durable aggregate recovery.
- `test_remediation_results_endpoint_returns_public_reasoning` ([260](test_group_cves_by_component.py#L260)) covers the UI projection/cited sources.

### `aegis-cve-evidence/tests/test_cli.py`

`CLITests.test_save_response_uses_safe_cve_and_vendor_filename` ([10](aegis-cve-evidence/tests/test_cli.py#L10)) verifies sanitized JSON output naming.

### `aegis-cve-evidence/tests/test_evidence.py`

`FakeHTTP` ([16](aegis-cve-evidence/tests/test_evidence.py#L16)) stores fixture documents/JSON; `document()` and `json()` return them by URL. `EvidenceTests` covers:

| Test (line) | Contract protected |
|---|---|
| `test_eclipse_omr_patch_is_relevant_but_not_a_released_version` ([29](aegis-cve-evidence/tests/test_evidence.py#L29)) | Source patch is not promoted to fixed release. |
| `test_eclipse_adds_openj9_and_semeru_fixed_releases` ([40](aegis-cve-evidence/tests/test_evidence.py#L40)) | Supplemental runtime release extraction. |
| `test_apache_log4j_extracts_branch_specific_fixed_versions` ([59](aegis-cve-evidence/tests/test_evidence.py#L59)) | Multiple Log4j fixed branches remain distinct. |
| `test_ibm_aix_service_pack_column_is_not_apar` ([71](aegis-cve-evidence/tests/test_evidence.py#L71)) | Correct IBM semantic column roles. |
| `test_ibm_multiple_application_branches_preserved` ([83](aegis-cve-evidence/tests/test_evidence.py#L83)) | Branch-specific fixes are not collapsed. |
| `test_ibm_explanatory_aix_level_is_not_a_fix_branch` ([94](aegis-cve-evidence/tests/test_evidence.py#L94)) | Prose label is not misclassified as fix. |
| `test_ibm_mq_freeform_branch_fix_and_allowlisting` ([108](aegis-cve-evidence/tests/test_evidence.py#L108)) | Free-form MQ fix and links. |
| `test_oracle_does_not_turn_affected_into_fixed` ([119](aegis-cve-evidence/tests/test_evidence.py#L119)) | CPU affected versions stay non-fix. |
| `test_oracle_mapping_continuation_has_distinct_product_cpu` ([130](aegis-cve-evidence/tests/test_evidence.py#L130)) | Oracle continuation rows retain product/CPU. |
| `test_oracle_cpu_joins_jdk_release_notes_without_inventing_graalvm_fix` ([144](aegis-cve-evidence/tests/test_evidence.py#L144)) | Java release cross-reference scope. |
| `test_oracle_cpu_keeps_all_release_notes_when_inventory_branch_is_unaffected` ([172](aegis-cve-evidence/tests/test_evidence.py#L172)) | Collection does not prematurely filter branches. |
| `test_oracle_also_addressed_is_explicitly_linked_to_primary_patch` ([205](aegis-cve-evidence/tests/test_evidence.py#L205)) | “Also addressed” provenance retained. |
| `test_rocky_filters_cve_and_preserves_release_packages` ([214](aegis-cve-evidence/tests/test_evidence.py#L214)) | Exact CVE and RPM preservation. |
| `test_redhat_csaf_uses_fixed_product_id` ([226](aegis-cve-evidence/tests/test_evidence.py#L226)) | Only fixed CSAF products become fixes. |
| `test_ubuntu_not_affected_never_claimed_fixed` ([242](aegis-cve-evidence/tests/test_evidence.py#L242)) | Non-fixed status safety. |
| `test_sqlite_multiple_cves_in_one_upstream_row` ([251](aegis-cve-evidence/tests/test_evidence.py#L251)) | Requested CVE row handling. |
| `test_explicit_vendor_stays_scoped` ([257](aegis-cve-evidence/tests/test_evidence.py#L257)) | Explicit vendor does not silently expand unless requested. |

### `aegis-cve-evidence/tests/test_grouped_input.py`

Each top-level function is a pytest test:

- `test_remediation_reads_grouped_csv_directly` ([13](aegis-cve-evidence/tests/test_grouped_input.py#L13)): grouped CSV expansion and partial context.
- `test_selection_keeps_one_cve_across_components_of_same_product` ([41](aegis-cve-evidence/tests/test_grouped_input.py#L41)): one-per-product selection.
- `test_latest_cve_per_component_uses_year_then_numeric_sequence` ([67](aegis-cve-evidence/tests/test_grouped_input.py#L67)): numeric CVE ordering.
- `test_product_names_are_safe_for_windows_directories` ([87](aegis-cve-evidence/tests/test_grouped_input.py#L87)): path sanitization.
- `test_reasoning_record_is_linked_to_run_and_cve` ([92](aegis-cve-evidence/tests/test_grouped_input.py#L92)): audit identity.
- `test_previous_test_version_is_reused_and_labelled_dummy` ([116](aegis-cve-evidence/tests/test_grouped_input.py#L116)) and `test_java_se_previous_version_is_8u401` ([142](aegis-cve-evidence/tests/test_grouped_input.py#L142)): explicit synthetic profile reuse.
- `test_environment_loader_discards_blank_aws_profile` ([157](aegis-cve-evidence/tests/test_grouped_input.py#L157)): boto profile safety.
- `test_context_directory_replaces_partial_context_with_matching_cve_fixture` ([167](aegis-cve-evidence/tests/test_grouped_input.py#L167)): context match replacement.
- `test_context_directory_reports_selected_cve_without_fixture` ([198](aegis-cve-evidence/tests/test_grouped_input.py#L198)): missing-context reporting.

### `aegis-cve-evidence/tests/test_remediation_schema.py`

- `test_claim_accepts_short_exact_component_quote` ([14](aegis-cve-evidence/tests/test_remediation_schema.py#L14)) protects legitimate short quotes.
- `citation_package()` ([19](aegis-cve-evidence/tests/test_remediation_schema.py#L19)) creates a minimal evidence package fixture.
- `invalid_citation_decision()` ([31](aegis-cve-evidence/tests/test_remediation_schema.py#L31)) creates a decision containing a bad quote.
- `test_citation_error_identifies_non_verbatim_quote` ([58](aegis-cve-evidence/tests/test_remediation_schema.py#L58)) checks exact-substring failure details.
- `test_second_bad_citation_is_safely_downgraded` ([69](aegis-cve-evidence/tests/test_remediation_schema.py#L69)) verifies conservative second-attempt behavior.
- `test_test_context_is_normalized_for_reasoning_but_preserved_for_audit` ([95](aegis-cve-evidence/tests/test_remediation_schema.py#L95)) verifies LLM view versus original snapshot separation.

### Nested helpers and test-only callables

The main file sections above describe the public functions and methods. The following locally defined functions and test doubles also contain executable logic and are listed explicitly so they are not mistaken for separate workflow stages:

| File and callable | Parameters/return and exact role |
|---|---|
| `app.py`: `events()` ([489](app.py#L489)) | Captures `run_id`; repeatedly calls `pipeline_run`, JSON-serializes changed state, yields SSE frames, stops on terminal state, emits an error frame if the run disappears, and sleeps one second between checks. It returns a generator; it neither runs remediation nor stores data itself. |
| `cve_component_enrichment.py`: `attempt(batch, feedback=None)` ([370](cve_component_enrichment.py#L370)) | Closure over the configured caller/client/token limit/diagnostics. It calls the model wrapper and `interpret_response`, records sanitized attempt metadata, and converts any batch exception into per-CVE `MODEL_ERROR` results. This is the first-call and retry path used by `classify_cves`. |
| `context_gathered/context_manager.py`: `decode(value)` ([102](aegis-cve-evidence/context_gathered/context_manager.py#L102)) | Reads an Oracle LOB when necessary, JSON-decodes strings/bytes, or returns an already-decoded value; used only while constructing `get_context`'s result. |
| `Internet_lookup/pipeline.py`: `one(u)` ([214](aegis-cve-evidence/Internet_lookup/pipeline.py#L214)) | Fetch-worker closure used by `_fetch_many`; calls the injected fetcher, logs URL/status/size/duration, and returns one `Page`. `ThreadPoolExecutor.map` preserves input order. |
| `remediation/remedition_agent.py`: `normalize(value, key=None)` ([216](aegis-cve-evidence/remediation/remedition_agent.py#L216)) | Recursively builds the LLM-facing test context, removing `is_dummy`/`context_kind`, fixture-only warnings, and synthetic marker wording. The original audit context is not mutated. |
| `remediation/remedition_agent.py`: `text_values(value)` ([246](aegis-cve-evidence/remediation/remedition_agent.py#L246)) | Recursive string flattener local to `validate_decision`; converts nested evidence `source_data` to a list for exact-substring citation checks. |
| `remediation/remedition_agent.py`: `text_values(value)` ([297](aegis-cve-evidence/remediation/remedition_agent.py#L297)) | Equivalent local flattener used by the safety-downgrade path. It is separately defined and has no side effects. |
| `remediation/remedition_agent.py`: `supported(claim)` and `remedy_supported(remedy)` ([308-314](aegis-cve-evidence/remediation/remedition_agent.py#L308)) | `supported` requires a three-character quote occurring in the referenced source. `remedy_supported` requires every fix/applicability/compatibility claim to pass. They decide what can survive `downgrade_invalid_citations`; they do not establish semantic correctness. |
| `remediation/run_grouped_remediation.py`: `score(candidate)` ([183](aegis-cve-evidence/remediation/run_grouped_remediation.py#L183)) | Scores a per-CVE context candidate: exact product-group match is weighted 4, product occurrence 2, and each component occurrence 1. `apply_context_directory` chooses `max`; score zero is treated as missing context. |
| `src/aegis_evidence/batch.py`: `number(cell)` ([28](aegis-cve-evidence/src/aegis_evidence/batch.py#L28)) | Converts an XLSX cell reference's column letters to a zero-based numeric index so the ZIP/XML fallback reader can rebuild sparse rows. |
| `src/aegis_evidence/models.py`: `sort_date(e)` ([54](aegis-cve-evidence/src/aegis_evidence/models.py#L54)) | Normalizes three human date formats or an ISO prefix to `YYYY-MM-DD`; returns empty text for unrecognized dates. It is the evidence ordering key inside `result`. |
| `sources/apache.py`: `emit()` ([120](aegis-cve-evidence/src/aegis_evidence/sources/apache.py#L120)) | Flushes the currently accumulated Tomcat security-page entry only when its final CVE equals the requested CVE; distinguishes negative assessments, extracts branch fixes/affected text, attaches release/fix-link notes, and appends `Evidence` rows to the enclosing list. |
| `sources/debian.py`: `value(role)` ([84](aegis-cve-evidence/src/aegis_evidence/sources/debian.py#L84)) | Safely reads and cleans the current row cell assigned to a semantic Debian table role; returns empty text when the column is absent/out of range. |
| `sources/oracle_cpu.py`: `releases(page_url, latest)` ([123](aegis-cve-evidence/src/aegis_evidence/sources/oracle_cpu.py#L123)) | Fetches an Oracle Java release index and matching release notes, filters to affected major branches, requires CPU wording, parses release date, and appends release-note `Evidence`. `latest` changes the note/association semantics used by the outer method. **Internet retrieval:** yes. |
| `sources/postgresql.py`: `field(role)` ([57](aegis-cve-evidence/src/aegis_evidence/sources/postgresql.py#L57)) | Safely reads the current PostgreSQL table cell mapped to a semantic role; returns empty text for missing/out-of-range columns. |

Test-only support callables do not participate in a production run:

- `GroupingTests` ([32](test_group_cves_by_component.py#L32)) is the root `unittest.TestCase`. Its `enriched_row(...)` fixture helper is described above. Local `DeferredThread.__init__` stores the requested target/args and `DeferredThread.start()` intentionally does nothing, preventing a background process during the selection test ([135-141](test_group_cves_by_component.py#L135)). `locked_first_write(path, rows)` records attempted names, raises `PermissionError` for the default grouped filename, and returns the fallback path ([199](test_group_cves_by_component.py#L199)).
- The five internet-lookup tests are `test_load_csv_inputs_maps_project_columns`, `test_direct_discovery_needs_no_api_key`, `test_build_queries_are_specific_bounded_and_sanitized`, `test_build_queries_adds_ibm_fix_vocabulary`, and `test_pipeline_returns_validated_source_and_evidence` ([176-280](aegis-cve-evidence/Internet_lookup/tests_related_files/test_internet_lookup_from_csv.py#L176)). In them, `QuietLog.info` discards logs; `FakeSearch.search` returns one controlled hit; `FakeFetcher.fetch` returns one controlled valid `Page`; `FakeLlm.__init__` creates a real `Budget`; and `FakeLlm.complete` consumes that budget and returns fixed extraction/ranking JSON. These isolate orchestration from the network and real models.
- `CLITests` and `CLITests.test_save_response_uses_safe_cve_and_vendor_filename` are the class and method named in the CLI-test section. `EvidenceTests` is the adapter-test `unittest.TestCase`; `FakeHTTP.__init__` stores fixture maps and `FakeHTTP.document`/`FakeHTTP.json` retrieve them by URL ([16-24](aegis-cve-evidence/tests/test_evidence.py#L16)).
- In `test_remediation_schema.py`, local `FakeClient.__init__` creates a call list and `FakeClient.generate(messages, prompt)` records each request and returns the deliberately invalid decision JSON plus empty usage and `stop` ([70-76](aegis-cve-evidence/tests/test_remediation_schema.py#L70)). This verifies retry and conservative downgrade behavior without an LLM.

## 9. Configuration, documentation, and artifact files

### Configuration/manifests

| File | Purpose |
|---|---|
| `.env.example` | Non-secret template for Bedrock/Azure, optional NVD key, API port, and the adapter fallback controls `AEGIS_ADAPTER_LLM_FALLBACK`/`AEGIS_ADAPTER_FALLBACK_MODEL`. The Azure endpoint is a concrete example endpoint but key is blank. |
| `.gitignore` | Excludes secrets, local environments, caches, frontend build/dependencies, remediation/evidence/test artifacts, and editor/OS files. |
| `requirements.txt` | Root FastAPI, LLM, evidence/MCP, parsing, inventory, SSH/database, and test dependencies. |
| `aegis-cve-evidence/pyproject.toml` | Installable evidence package metadata/dependencies/scripts. `Internet_lookup` sits outside the configured `src` package tree, so it is runnable from the project directory but not included by that package discovery rule. |
| `package-lock.json` | Root generated npm lock with no packages; the actual UI lock is under `ui`. |
| `aegis-cve-evidence/README.md` | User-facing evidence-engine setup, sources, boundaries, tests, and remediation bridge description. Documentation, not runtime behavior. |
| `aegis-cve-evidence/remediation/README.md` | Remediation workflow/operator guidance. Documentation, not enforcement except where corresponding code validates it. |
| `PROJECT_DOCUMENTATION.md` | Older reference that describes a previous `/MCP` and database layout no longer present in the current file inventory. It must not be treated as current implementation evidence. |

### CSV/JSON artifact schemas

| Files/pattern | Fields and origin |
|---|---|
| `deduplicated_cves.csv` | `CVE ID`, JSON `Descriptions`, JSON `Contexts`, and `Source Rows`; written by classifier CLI. |
| `component_version_commands.csv`, `component_version_commands_upd.csv` | Enrichment fields plus version target, executable, server shell, path/version command templates, expected result, notes, and status. They are stored outputs, not executed commands. |
| `classification_diagnostics.json` | Input path, normalized records, skipped rows, raw/error attempt metadata, and final classifications. May contain source text/model output and should be handled as audit data. |
| `data/<job-or-run>.csv` | Enriched rows following `COMPONENT_COLUMNS`. |
| `data/grouped_by_comp*.csv` | Product+component grouped rows; run-specific suffix is used if default is locked. |
| `data/selected_components_ui-*.csv` | Only UI-selected grouped rows passed to remediation. |
| `data/my-run-001.csv` and other named CSVs | Saved run/enrichment samples using the same enriched/grouped contracts. |
| `aegis-cve-evidence/src/output_data/*.json` | CLI evidence-engine responses keyed by CVE/vendor. Generated and ignored. |
| `aegis-cve-evidence/Internet_lookup/{cache,logs,results}` or test `artifacts/` | Experimental lookup cache JSON, JSONL step logs, and result JSON. Generated and ignored where configured. |

The enriched `COMPONENT_COLUMNS` are: `Application`, `Product`, `Component`, `Description`, `CVE IDs`, `Operating System`, `Technical Details`, `Evidence`, `Affected Symbol`, `Source Path`, `Component Kind`, `Classification Status`, `Classification Reason`, and `Source Rows`.

## 10. Detailed callable internals and call map

This section expands the earlier file-by-file reference. Each entry identifies important calls made inside the callable and then explains its code blocks in execution order. Calls to ordinary constructors and formatting helpers are included when they affect validation, persistence, network access, or control flow. A call relationship shows what the code invokes; it does not imply that the called operation succeeded or proved vulnerability applicability.

### 10.1 Root utility, enrichment, grouping, command, and SSH functions

#### `agent_utils.py`

- `clean(value)` calls `isinstance`, `isoformat`, `str`, and `strip`. Its first block returns `""` for `None`; the second converts date/time-like objects through `isoformat`; the final fallback stringifies and trims everything else. This gives CSV/prompt code one predictable textual boundary without interpreting the value.
- `normalize_name(value)` calls `clean`, replaces underscores/hyphens, lowercases, splits, and rejoins. The replacement block makes common header styles equivalent; the split/join block collapses whitespace. It is used only for tolerant name matching, not fuzzy content matching.
- `get_value(row, *names)` calls `normalize_name` for requested names and each row key, then `clean` for the selected value. It first builds the normalized target-name set; it then scans in source order and returns the first matching value. If none match it returns `""`, allowing callers to distinguish missing text without catching an exception.
- `create_bedrock_client()` calls `boto3.Session`, botocore `Config`, `session.client`, and `print`; failures become a contextual `RuntimeError`. The credential block prefers explicit access/secret/session values, otherwise a nonblank profile, otherwise the default AWS chain. The client block configures connect/read timeouts and retry policy. The final diagnostic prints the credential source but not the secret. Creating a client checks local resolution only; it does not make a model request.
- `invoke_bedrock(client, body, purpose)` calls `json.dumps`, `client.invoke_model`, response-body `read`, and `json.loads`, timing with `time.monotonic`. The request block serializes the Anthropic-style body and logs purpose/model timing. The success block parses the returned JSON. The exception block inspects botocore error codes/messages to add configuration guidance, then re-raises a `RuntimeError` without silently returning an empty classification.

#### `cve_component_enrichment.py`

- `clean(value)`, `normalized(value)`, and `header_key(value)` form a three-stage normalization chain. `clean` stringifies/trims; `normalized` calls it, applies Unicode NFKC, collapses whitespace, and case-folds; `header_key` additionally maps `_` and `-` to spaces. The separation matters: evidence quotes retain original text while comparisons use normalized text.
- `meaningful(value)` calls `normalized` and rejects membership in `EMPTY`. Its single decision block treats blank and configured sentinel values as absent without rejecting legitimate zero-like values merely because they are falsey.
- `get_value(row, *aliases)` calls `header_key`, `meaningful`, and `clean`. It normalizes aliases once, scans row items, and returns the first meaningful alias match. It does not merge conflicting aliases.
- `object_schema(properties)` calls `list(properties)` and returns a JSON Schema object with `required` set to every property and `additionalProperties: false`. This is reused while constructing the Bedrock tool schema, ensuring structural completeness before semantic evidence checks.
- `read_source_file(path, sheet_name)` calls `Path`, `csv.DictReader` for CSV, or `openpyxl.load_workbook` for XLSX. The first block validates existence/extension. The CSV block uses UTF-8 with BOM support, rejects missing/duplicate headers and surplus columns, and materializes rows. The XLSX block chooses the requested/active sheet, reads values in read-only/data-only mode, cleans headers, zips each row, and closes the workbook in `finally`. The final block rejects an empty dataset. It reads only; it makes no LLM or internet call.
- `build_records(rows)` calls `get_value`, `CVE_PATTERN.findall`, `meaningful`, and the normalization helpers. The intake block ignores fully empty rows and records why rows with no recognized CVE are skipped. The expansion block creates one record per distinct CVE, preserving every observation and application/OS context. The source block assigns stable `rowN:colN` IDs to meaningful description-like cells. The final cross-record block marks source text shared by multiple CVEs, preventing it from being treated as unambiguous per-CVE evidence.
- `classification_prompt(records, retry_feedback)` calls `json.dumps`. Its instruction block establishes the trust boundary and classification rules; the data block serializes only requested records; an optional repair block includes prior validated results and narrowly scoped feedback. It returns text and performs no model call itself.
- `classify_batch(client, records, max_tokens, retry_feedback)` calls `classification_prompt` and `invoke_bedrock`. It builds the provider body with forced `CLASSIFICATION_TOOL`, temperature zero, configured token cap, and the prompt; then delegates the network/model request. It returns the raw provider response so validation remains a separate step.
- `require_keys(value, keys)` calls `isinstance` and compares key sets exactly. It rejects missing and extra keys, which stops a model response from smuggling unvalidated fields into later logic.
- `empty_result(cve_id)` constructs the conservative result shape. It initializes every fact to an empty label/evidence pair, kind `unknown`, status `NEEDS_ENRICHMENT`, and an empty issue list. Other paths mutate this known-safe base instead of building ad-hoc error objects.
- `validate_fact(value, sources)` calls `require_keys`, `meaningful`, `normalized`, `re.search`, and `re.escape`. The schema block checks the `{label,evidence}` shape and element types. The empty-label block requires no evidence. For a nonempty label, the evidence loop verifies each source ID, exact normalized quote occurrence, and word-bounded label occurrence inside that quote. It deduplicates accepted citations and returns `(fact, error)` rather than raising, enabling partial classification. This establishes textual grounding only.
- `set_status(result)` inspects populated product/component facts and issue categories. Evidence mismatch or conflict wins first; both core facts produce `SUPPORTED`; one produces `PARTIAL`; none produces `NEEDS_ENRICHMENT`. The function mutates and returns the same mapping so callers can compose it after validation.
- `validate_classification(item, record)` calls `empty_result`, `require_keys`, `validate_fact`, `normalized`, and `set_status`. It validates the outer exact schema and CVE identity, builds a source-ID map from the record, validates all four facts independently, and accumulates issues instead of discarding supported fields. It then enforces the component-kind enum and the rule that a protocol alone cannot become a version-bearing product. The last block derives status.
- `interpret_response(response, records)` calls `require_keys`, `validate_classification`, and `empty_result`. It first detects incomplete/truncated output, locates the specifically named tool-use block, and validates its item container. It groups candidates by normalized CVE, then for each requested record rejects zero or multiple candidates conservatively; exactly one candidate goes to `validate_classification`. Unrequested CVEs never become output rows.
- `merge_retry(previous, repaired)` calls `normalized` and `set_status`. It copies the first validated result, merges unique retry issues, and examines each fact. Empty repaired facts cannot erase prior support; matching repaired facts may add citations; conflicting nonempty labels preserve the prior fact and add `CONFLICTING_EVIDENCE`. Kind is replaced only when the repaired value is useful. The final status is recalculated from the merged evidence.
- `classify_cves(...)` calls `empty_result`, its local `attempt`, the injectable `caller` (normally `classify_batch`), `interpret_response`, and `merge_retry`. The eligibility block separates missing descriptions and descriptions shared across CVEs from model-eligible records. The local `attempt` block calls the provider, records diagnostics, and converts a whole-call failure into one `MODEL_ERROR` per CVE. The batching block honors `max_batches`; each non-`SUPPORTED` result receives exactly one single-CVE repair attempt. It returns a result for every input CVE, including unprocessed/error cases.
- `result_reason(result)` joins existing issues first. If there are none, it lists missing core facts; otherwise it returns the explicit warning that labels are supported by source text while host applicability remains unverified. It is display/audit text, not a new validation step.
- `component_rows(records, classifications)` calls `result_reason`, `dict.fromkeys`, and `sorted`. The observation loop creates one row per CVE/context observation. It renders fact evidence and technical details as strings while preserving empty values, then merges only duplicate output rows by collecting multi-valued columns. The final block joins/deduplicates collected values and sorts deterministically. It does not group different CVEs into one component row.
- `write_csv(path, rows, columns)` calls `Path.mkdir`, `Path.open`, and `csv.DictWriter`. It creates only the parent directory, writes a UTF-8 BOM/header, and emits rows in the explicit column order. I/O errors propagate to the caller.
- `positive_int(value)` calls `int` and raises `argparse.ArgumentTypeError` if the value is below one. This moves batch-limit validation into argument parsing.
- `main()` calls `read_source_file`, `build_records`, `write_csv`, `create_bedrock_client`, `classify_cves`, `component_rows`, and `write_grouped_csv`. Argument/path validation runs first, including run-ID shape and input/output collision checks. Ingestion and deduplicated output happen before any LLM creation. A client is created only if at least one record has eligible source text. The persistence block writes diagnostics, enrichment, and grouped CSVs, then prints status totals. Exceptions are allowed to fail the CLI rather than being reported as successful empty output.

#### `group_cves_by_component.py`

- `_values(value)` stringifies, splits on `|`, trims, and discards empty pieces. It is the canonical decoder for previously joined multi-value CSV fields.
- `group_by_product_and_component(rows)` calls `_values`, `dict.fromkeys`, and `sorted`. It keys groups by the exact trimmed `(Product, Component)` pair, creates collection lists for every output column, and appends split values from each row. It then deduplicates each column without changing first-seen order, joins values with ` | `, and sorts case-insensitively. The compound key prevents same-named components under different products from merging.
- `write_grouped_csv(path, rows)` calls `group_by_product_and_component`, creates the parent, and writes `GROUPED_COLUMNS` through `csv.DictWriter`. It returns the grouped rows so API callers can persist and respond from the same transformation.

#### `component_version_command_agent.py`

- `server_shell(operating_system)` lowercases the OS and checks configured Windows markers with `any`; it returns `powershell` or `posix`. This only chooses template syntax—it does not connect to a host.
- `generate_probe(client, row)` calls `json.dumps` and `invoke_bedrock`. The prompt block embeds an untrusted JSON record and strict rules prohibiting package managers, invented paths, arbitrary scripts, or remediation. The response block requires exactly one `return_version_probe` tool block and extracts it; missing/multiple/wrong blocks raise `ValueError`. It returns an untrusted candidate that must still pass `validate_probe`.
- `validate_probe(probe)` calls `re.sub`, `re.fullmatch`, `isinstance`, and set membership checks. It strips/normalizes the executable basename, rejects paths/metacharacters/shell syntax, validates argument-list type/count and every allowed argument, and permits no-argument execution only for an explicit script allowlist. Notes and expected-result fields are length/shape constrained. The output is a cleaned probe dictionary, not a command execution.
- `build_commands(probe, shell)` joins the validated executable and quoted/allowed arguments. It then builds PATH-discovery and confirmed-path templates in PowerShell or POSIX syntax. Empty executable produces blank commands. The placeholder requires a human or separate collector to insert a reviewed path.
- `read_enriched_csv(input_file)` calls `csv.DictReader`, verifies the required enrichment columns as a set, materializes rows, and rejects an empty file. It does not trust positional column order.
- `build_command_rows(rows)` calls `create_bedrock_client` lazily, `get_value`, `server_shell`, `generate_probe`, `validate_probe`, and `build_commands`. It deduplicates work by relevant row identity. Non-`SUPPORTED` classifications are copied into an output row with a skipped status. Supported rows trigger model generation and local validation; exceptions become per-row error statuses rather than aborting all rows. Successful rows contain discovery templates and explanatory notes only.
- `write_command_csv(rows, output_file)` creates the destination parent and writes the fixed command-output schema with a UTF-8 BOM. It makes no remote call.
- `main()` parses paths, calls `read_enriched_csv`, `build_command_rows`, and `write_command_csv`, then counts statuses for console output. Its default filenames are resolved relative to the script directory. It never calls `paramiko_ssh_runner.py`.

#### `paramiko_ssh_runner.py`

- `execute_command(client, command)` calls Paramiko `exec_command`, channel readiness/receive methods, `recv_exit_status`, and `time.sleep`. It immediately closes stdin and shuts down writing, then drains stdout and stderr incrementally to avoid pipe deadlock. The timeout block closes streams/channel and raises `TimeoutError`. The terminal block decodes collected bytes and raises `RuntimeError` on a nonzero exit status; otherwise it returns `(stdout, stderr)`. The function will execute whatever reviewed string its caller supplies.
- `main()` calls `getpass`, `paramiko.SSHClient`, host-key loading/policy methods, `connect`, `shlex.quote`, and `execute_command`. It first validates the known-hosts file, optional key, and remote-directory shape; it prompts for a password only when no key is configured. The connection block rejects unknown host keys. The command block optionally prefixes a quoted `cd`, executes the configured command, prints output, and closes the client in `finally`. This is a standalone operator utility, not an approval/deployment integration.

### 10.2 FastAPI orchestration functions (`app.py`)

- `error(message, status)` calls `JSONResponse` and centralizes the API's `{"error": ...}` envelope. It performs no logging or exception mapping by itself.
- `csv_response(rows, columns, filename)` calls `io.StringIO`, `csv.DictWriter`, and FastAPI `Response`. It writes an in-memory BOM-prefixed CSV and sets content type plus attachment name. It does not persist a new file.
- `read_enriched_csv(path)` calls `Path.open` and `csv.DictReader`. The header block compares against all `COMPONENT_COLUMNS`; the row block coerces each expected cell to text; the final block rejects zero rows. This prevents reuse of an arbitrary CSV with a coincidentally similar filename.
- `reusable_enrichment_files()` calls `DATA_DIR.glob`, `read_enriched_csv`, `stat`, and timestamp formatting. It returns early if the directory is absent, excludes grouped/selected files by prefix, and ignores any candidate that fails schema/read validation. Valid metadata is sorted newest-first. It reads local files only.
- `grouped_payload(job_id, enriched_rows, source, source_filename)` calls `group_by_product_and_component` and `write_grouped_csv`. It computes grouped rows, stores both forms in `JOBS`, then tries the stable grouped filename. A Windows `PermissionError` triggers a run-specific filename and warning. The response block returns data and provenance consistently with what was stored.
- `execute_selected_pipeline(run_id, selected_path)` calls `subprocess.run`, timestamp functions, and artifact-file checks. It marks the in-memory run `running`, constructs an explicit runner command including test context and dummy flags, and waits synchronously in the background thread. On exit zero it requires the combined aggregate to exist before marking completion; nonzero/missing output becomes failure with the final process line. Any unexpected exception is caught into failed state. It captures stdout/stderr and has no timeout/cancellation.
- `saved_pipeline_run(run_id)` calls `re.fullmatch`, `read_text`, and `json.loads`. It rejects unsafe IDs, locates the expected aggregate, and returns `None` for absent/malformed data. The mapping block derives completed/failed status from aggregate text and resolves artifact paths, allowing terminal state recovery after process restart.
- `pipeline_run(run_id)` first checks the in-memory `PIPELINE_RUNS` dictionary, then calls `saved_pipeline_run`. Running/queued state is therefore not durable, while terminal aggregate state can be reconstructed.
- `saved_run_aggregate(run_id)` repeats the strict run-ID/path check, parses JSON, and requires a dictionary. Unlike `saved_pipeline_run`, it returns the aggregate content used to build public results.
- `public_remediation_results(aggregate)` calls nested dictionary accessors, `enumerate`, `any`, and collection operations. The outer block iterates run results and derives context labels/test flags. The citation block gathers IDs referenced by supporting claims and every candidate/recommended remedy; the evidence block exposes metadata only for those cited records. The projection block selects public decision, blockers, conflicts, operational guidance, paths, and errors. Finally it totals verdicts and test-context usage. It neither reruns validation nor exposes arbitrary raw model/provider data.
- `upload_csv(file)` calls `UploadFile.read`, UTF-8 `decode`, `read_source_file`, `build_records`, `reusable_enrichment_files`, and temporary-file APIs. Guard blocks reject missing file, wrong suffix, empty/oversized bytes, and non-UTF-8 content. Because the shared reader accepts paths, decoded content is written to a named temporary CSV and always deleted in `finally`. The job block creates a random ID, builds a first-observation preview per CVE, stores records/skips/source rows in memory, and returns reuse metadata. No classification occurs yet.
- `enrich_range(payload)` calls `create_bedrock_client`, `classify_cves`, `component_rows`, `write_csv`, and `grouped_payload`. It validates the job and integer range without accepting booleans as integers. It slices unique records, creates a client only when eligible source text is present, classifies, and saves a run-specific enriched CSV. Grouping/persistence runs last; exceptions become API error responses rather than partial success.
- `reuse_enrichment(payload)` calls `reusable_enrichment_files`, `read_enriched_csv`, and `grouped_payload`. It validates the job and requires the requested basename to occur in the server-generated reusable list, preventing arbitrary path reads. It then groups the stored rows without an LLM call.
- `start_selected_pipeline(payload)` calls `write_csv`, `Thread(...).start`, timestamp/UUID helpers, and `JSONResponse`. It validates the job, list type, integer indexes, bounds, and nonempty deduplicated selection. It writes only selected grouped rows, creates queued state with explicit test-context metadata, launches a daemon thread targeting `execute_selected_pipeline`, and returns HTTP 202. This records selection, not approval.
- `selected_pipeline_status(run_id)` calls `pipeline_run`; it returns recovered/current state or the shared 404 error envelope.
- `selected_pipeline_events(run_id)` calls `pipeline_run` and `StreamingResponse`. Its nested `events()` generator serializes only changed states, sleeps one second, stops after completed/failed, and emits a terminal error event if state disappears. The route sets no-cache/proxy-buffering headers. This is status transport, not execution.
- `selected_pipeline_results(run_id)` calls `saved_run_aggregate` and `public_remediation_results`. It requires a terminal aggregate, returns 409 while nonterminal, and never reads raw results directly from the UI's request.
- `download_csv(job_id, kind)` calls `csv_response` after checking the in-memory job and kind-specific prerequisite. Deduplicated, enriched, and grouped downloads use distinct columns/filenames; unknown kinds return 404. Restarted processes cannot recover these in-memory job downloads.
- `health()` returns a static process-level status. It deliberately makes no dependency calls.
- `frontend()` calls `FileResponse` only when the built index exists; otherwise it returns build instructions. Static assets are mounted separately at module initialization.

### 10.3 React callables (`ui/src/App.jsx`)

- `humanize(value)` calls `String` and `replaceAll`; it supplies `Unknown` for falsey input and replaces underscores for display. It does not change underlying API values.
- `mergeRemediationResults(current, incoming)` uses array `includes`, `map`, spread, and `reduce`. It first deduplicates whole runs by run ID, annotates incoming result rows with that ID, concatenates history, recomputes verdict totals from all rows, and propagates whether any run used test context. It returns new state rather than mutating React state.
- `ClaimList({claims, sources})` returns `null` for no claims; otherwise `map` resolves each claim's source by evidence ID and renders its exact quote plus a safe new-tab source link when available. It displays already-projected data and performs no validation.
- `RemedyCard({remedy, sources, recommended})` returns `null` for no remedy, chooses target version before patch ID, concatenates the three support arrays, calls `humanize`, and renders a nested `ClaimList`. CSS state distinguishes a recommended remedy but does not confer approval.
- `GuidanceList({title, items, tone})` guards empty lists, maps strings to list items, and selects a tone class. It is presentation-only.
- `RemediationResultCard({result})` combines component/application/OS labels, calls `humanize`, `RemedyCard`, `GuidanceList`, and `ClaimList`, and conditionally renders verdict, context, candidates, recommendation, claims, blockers, conflicts, missing information, operational notes, validation notes, and process errors. Its blocks expose uncertainty explicitly; no button applies a fix.
- `GroupedTable(...)` calls `useState`, pagination math, `slice`, and its nested selection functions. `toggle(index)` clones the current `Set` before adding/removing one absolute row index. `toggleAll()` replaces selection with either an empty set or all row indexes. The render block translates visible indexes back to absolute indexes so selection survives paging; checkbox click propagation is stopped to avoid double toggles.
- `DataTable(...)` calls `useState`, pagination math, `slice`, and array `map`. It bounds the active page, renders a single empty row when appropriate, and uses functional state updates for previous/next navigation. It has no selection or data mutation.
- `UploadPanel(...)` calls `useRef`, `useState`, `FormData`, `fetch`, and parent callbacks. Its nested `upload(file)` rejects absent/non-CSV names client-side, toggles busy/error state, posts multipart data to `/api/upload`, parses the JSON error/success envelope, calls `onUploaded`, and clears busy state in `finally`. Drag/drop and file-input handlers only feed a `File` into this function; server-side size/content validation remains authoritative.
- `App()` calls React state/effect/memo hooks, browser `EventSource`, `fetch`, `AbortController`, and all view components. State declarations separate dataset, grouping, selection, pipeline, results, pagination, and error state. `activeData` memo chooses original versus enriched table data. The first effect opens SSE only for queued/running runs, parses status, closes on terminal/error/unmount, and reports unreadable frames. The second effect loads results once per terminal run ID.
- `reset()` invokes state setters to restore the initial workspace and clears prior selections/results/errors. It does not delete server files or cancel an already running backend subprocess.
- `setQuickCount(value)` clamps a numeric preset or `all` to the currently available range before updating count.
- `finishGrouping(result)` stores enriched and grouped response data, carries source provenance, clears prior selection/run, selects the enriched tab, and switches to grouped view.
- `requestPipelineRun()` checks `dataset.existing_enrichment`; it either opens the reuse prompt or calls `runEnrichment("fresh")`. The name refers to the UI's next workflow action—it does not yet start remediation.
- `runEnrichment(mode)` calls `fetch`, `AbortController`, timeout APIs, and `finishGrouping`. It clears prompt/error, starts a 30-minute client timeout, chooses `/api/enrich/reuse` or `/api/enrich` and builds the corresponding JSON body, parses the response, and reports server/abort errors. `finally` always clears timeout and busy state; aborting the browser request does not guarantee cancellation of server-side model work.
- `runSelectedComponents()` returns if selection is empty, sorts absolute indexes, posts them to `/api/pipeline-runs`, parses the response, and stores queued run state. It reports errors but does not retry or represent the selection as formal approval.
- `showRemediationResults()` requires a run ID, fetches its public results endpoint, calls `mergeRemediationResults` through a functional setter, and changes to the results view. `finally` clears loading state. It cannot retrieve nonterminal results because the backend returns 409.

### 10.4 Evidence engine internals (`aegis_evidence`)

#### Shared models, HTTP, registry, and orchestration

- `models.cve_id(value)` calls `strip`, `upper`, and `CVE_RE.fullmatch`. It normalizes first, then rejects anything other than one complete CVE identifier. This prevents path fragments or multiple IDs from flowing into URL construction.
- `Evidence.as_dict()` calls `dataclasses.asdict` and filters only `None` values. Empty strings/lists remain visible, preserving the difference between explicitly empty data and an absent optional field.
- `models.result(cve, vendor, evidence, errors, searched, hints)` uses a compound dictionary key to deduplicate identical evidence claims, then calls local `sort_date` and `Evidence.as_dict`. `sort_date` tries three publisher date formats and an ISO prefix, returning empty text when unknown. The ordering block sorts newest-first with source/product tie-breakers. The response block marks evidence/no-evidence status and partial coverage whenever adapter errors exist. It never converts no evidence into “not affected.”
- `HTTP.__init__(cache_dir, ttl_hours, offline)` calls `Path` and `mkdir`. It chooses an explicit path or `AEGIS_CACHE_DIR`, records cache TTL/offline behavior, creates the cache directory, and initializes `requested_urls` as a `ContextVar` containing a URL tuple. This is request-context-local attempt metadata used by `Source.search` to identify pages eligible for layout fallback; it is not evidence itself, and concurrent MCP lookups do not share its values.
- `HTTP.get(url, max_bytes)` first extends the context-local `requested_urls` tuple, then calls `urlparse`, SHA-256, `Request`, `urlopen`, cache file APIs, and retry sleeps. Recording before validation/fetch means a deterministic adapter exception still exposes the attempted link to the fallback wrapper. The policy block requires HTTPS plus an exact allowlisted hostname. The cache block hashes the full URL, returns fresh bytes, and permits stale bytes only in offline mode. The request loop makes at most three attempts, revalidates the final redirect hostname, reads at most `max_bytes + 1`, rejects oversize data, and atomically treats only successful bodies as cacheable. Retryable HTTP/network errors back off; final errors become `FetchError`.
- `HTTP.json(url)` calls `HTTP.get`, UTF-8-BOM decoding, and `json.loads`; parsing errors propagate as source failures. `HTTP.document(url)` calls `HTTP.get` and `lxml.html.fromstring` with the URL as base, enabling relative-link resolution.
- `http.clean(value)` distinguishes lxml elements from ordinary values, joins descendant text or string words, and collapses whitespace. `table_rows(table)` calls it for every `th`/`td` in each `tr`, returning a rectangular-looking list without interpreting spans. `section(node, heading)` finds a matching h2-h4, then walks siblings until an equal/higher heading; it calls `clean` and returns joined section text.
- `registry.cve_record(http, cve)` calls `http.json` on the CVE.org API and catches all exceptions to return `{}`. This keeps evidence lookup running when discovery metadata is unavailable, at the cost of incomplete automatic routing.
- `registry.record_context(record)` calls nested `get`, extends CNA/ADP references, English descriptions, and affected products, then order-deduplicates them. It returns discovery hints only; downstream adapters remain responsible for fix evidence.
- `engine.select(...)` calls alias maps, string matching, URL-host inspection, and may recursively call itself for `include_related`. In `auto` mode it builds a lowercase context string and discovers publishers from aliases/reference domains; if nothing matches it uses the broad configured list. Explicit mode resolves one alias/source or raises. `include_related` appends auto-discovered publishers while preserving explicit scope and order.
- `Engine.__init__(http)` stores the injected test client or calls `HTTP()`. Dependency injection lets adapter tests avoid network/cache behavior.
- `Engine.lookup(...)` calls `cve_id`, `cve_record`, `record_context`, `select`, each selected `Source.search`, and `models.result`. It validates identity, enriches missing description/product/reference hints from CVE.org, constructs one immutable `Context`, and invokes adapters independently. Each adapter exception is captured with its source rather than aborting other sources. The final hints describe broad auto scope and obvious OS/vendor mismatch; they are warnings, not applicability decisions.
- `list_sources()` serializes the `SOURCES` name/host declarations plus `ALIASES`. It performs no probe or live availability test.

#### Evidence interfaces and entry points

- `Source.__init__(http)` stores the shared HTTP dependency. `Source.referenced(context)` calls `urlparse` and keeps only HTTPS references whose exact hostname appears in the adapter’s `hosts`; it does not follow arbitrary CNA links.
- `Source.search(context)` is the public, common wrapper. It starts an empty context-local attempted-URL scope (while retaining list support for injected test clients), calls the concrete adapter's `_search(context)`, and immediately returns deterministic evidence—including a legitimate empty list—when no exception occurs. On an exception only, it combines that scope's attempted URLs with adapter-owned references, order-deduplicates them, logs the parser failure, and calls `llm_fallback.extract_evidence`. If fallback also fails it raises one `RuntimeError` containing both causes, which `Engine.lookup` converts into `source_errors`. Its `finally` block resets the context token, restoring any outer scope without leaking state. This wrapper does not call an LLM merely because an adapter found no evidence.
- Abstract `Source._search(context)` raises `NotImplementedError`. Each adapter implements this deterministic parser while inheriting the stable public `search` contract.
- `llm_fallback._invoke(system, user)` selects the provider named by `LLM_PROVIDER`. Bedrock builds a boto3 session/runtime client and calls `converse` with a 5,000-token cap; it deliberately omits `temperature` because current Bedrock models can reject that parameter as deprecated. Azure creates `AzureOpenAI` and calls JSON-mode chat completions; Anthropic creates its client and calls `messages.create`; those branches request temperature zero. All clients use bounded retries/timeouts. The code explicitly requires a Bedrock model or Azure deployment; missing/invalid credentials, endpoints, provider responses, or network access fail through the provider SDK. It returns only response text and rejects unsupported providers or incomplete stop reasons. This is the only model-call function in the adapter fallback.
- `llm_fallback.extract_evidence(http, context, source_name, urls, cause)` first checks the feature flag, order-deduplicates and caps input at four links, and refetches them through the same `HTTP.get` policy. It parses HTML, deletes `script`, `style`, `noscript`, and `svg`, and converts visible content to collapsed text. For a page longer than 12,000 characters it selects a bounded window beginning up to 2,000 characters before the exact target CVE, falling back to the page beginning only when the CVE is absent; this keeps the relevant section of large real advisory catalogues. It requires at least one readable page, then sends the parser error, CVE, source identity, URLs, page excerpts, and an exact JSON schema to `_invoke`. After stripping an optional JSON fence, it requires a top-level object containing only `evidence`; no more than 20 items; and exactly the 13 `Evidence` keys per item. It then verifies source, CVE, URL ownership, types, presence of the exact CVE on that page, and exact collapsed-text grounding for every populated factual field and note. Only then does it construct `Evidence`, adding a fallback audit note. This validation proves textual support in the fetched page; it does not prove that the model interpreted the page correctly, that the fix applies to a host, or that application compatibility is safe.
- `cli.save_response(cve, vendor, response, output_dir)` calls `mkdir`, regular-expression sanitization, `json.dumps`, and `write_text`. It converts unsafe vendor characters to underscores and writes `<CVE>_<vendor>.json`; the response is not changed.
- `cli.main()` parses lookup arguments, calls `Engine().lookup`, `save_response`, and `print(json.dumps(...))`. One lookup therefore both writes a JSON artifact and prints the same logical result.
- `batch.rows(path)` selects CSV or a minimal XLSX ZIP/XML reader. CSV delegates to `DictReader`. XLSX reads shared strings and the first sheet; local `number(cell)` converts column letters to zero-based indexes so sparse cells can be reconstructed. Unsupported extensions raise instead of guessing.
- `batch.main()` calls `rows`, creates one `Engine`, loops inputs, calls `Engine.lookup` using recognized columns, and writes/flushed one JSON object per line. Flushing preserves progress on a long batch, but one uncaught row error can still stop the process.
- `server.main()` calls `FastMCP`, constructs one `Engine`, decorates three nested tools, and calls `server.run`. `get_cve_remediations(...)` forwards full lookup arguments to `Engine.lookup`; `detect_cve_sources(...)` calls lookup with `auto` and returns the same evidence-shaped result rather than a source-name-only list; `available_sources()` calls `list_sources`. MCP transports these functions but does not change their trust boundary.
- `run_all_cves.ps1` is script-level logic rather than a function: it resolves project paths, creates the output directory, and pipes a configured input through the installed batch command. PowerShell failure behavior and the called CLI determine whether the run stops.

#### Apache adapter (`sources/apache.py`)

- `Apache._log4j_evidence(doc, url, cve)` calls XPath, `clean`, regex extraction, and `Evidence`. It locates the CVE heading, accumulates siblings until the next peer heading, extracts affected/fixed labels, and emits one evidence row per unique fixed branch. If no exact fixed version is parsed it retains an advisory row with explanatory notes rather than inventing a fix.
- `Apache._tomcat_urls(references)` calls `urlparse`, index-page `HTTP.document`, XPath, `urljoin`, and order-deduplication. It accepts recognized Tomcat security-page references directly; otherwise it may inspect the Tomcat security index to discover branch pages. Discovery failure is returned as a warning string so `search` can decide whether partial output is still useful.
- `Apache._entry_title(node)` calls `clean`, CVE/title regexes, and nested XPath. It recognizes CVE-bearing headings/strong text while rejecting unrelated prose; return is a canonical entry title or `None`.
- `Apache._product(url)` parses the security-page filename/path and maps it to Tomcat, Tomcat Native, JK, or a generic Apache Tomcat label. URL structure, not page prose, supplies this display product.
- `Apache._tomcat_evidence(...)` scans ordered headings/paragraphs/list items and calls `_entry_title`, `_product`, `clean`, and local `emit`. `emit()` flushes only an entry whose last title CVE equals the requested CVE, distinguishes “not a vulnerability” headings, extracts fixed versions only under fix wording, collects affected text and allowlisted commit links, and appends one `Evidence` per branch. State resets at release/entry boundaries prevent details leaking between CVEs.
- `Apache._search(context)` calls `referenced`, `_tomcat_urls`, `HTTP.document`, `_log4j_evidence`, and `_tomcat_evidence`. It chooses Log4j parsing from product/description/reference signals, adds recognized referenced Apache pages, isolates page failures, and raises only when all intended work failed or a required layout cannot be interpreted. Returned rows remain publisher-scoped. Inherited `Source.search` handles any terminal exception.

#### Debian adapter (`sources/debian.py`)

- `_role(header)` normalizes nonletters and tests vocabulary to map a table header to package/release/status/version/fixed-version roles. `_package(cell)` prefers a package link slug and otherwise cleans visible text/PTS suffixes. `_state(value, status)` combines cells and classifies negative/open/fixed states using regexes.
- `Debian._search(context)` calls `HTTP.document`, XPath, `table_rows`-style cleaning, the three helpers, `urljoin`, and `Evidence`. It verifies a CVE heading, walks relevant tables, dynamically discovers semantic columns, and carries forward package names in continuation rows. Local `value(role)` safely reads the current semantic column. Negative states become assessment evidence without a fix; fixed states require version-shaped content before `fixed_version` is populated. If a CVE page exists but no recognized layout appears, it raises instead of silently claiming no fix.

#### Eclipse adapter (`sources/eclipse.py`)

- `_openj9_releases(context)` calls the GitHub releases API through `HTTP.json`, filters release bodies mentioning the CVE, extracts “works with” version text, and emits release evidence. A source patch alone is not treated as a released runtime version.
- `_semeru_releases(context)` calls `HTTP.document` and `table_rows`, finds a header containing CVE/fixed information, filters exact requested CVE rows, and emits branch/release evidence. Unrecognized tables produce no supplemental rows.
- `Eclipse._search(context)` calls `referenced`, `HTTP.document`, `clean`, regexes, and the two supplemental functions. It keeps explicitly referenced Eclipse/OpenJ9 advisory or GitHub issue/commit material, classifies commit IDs as source patches rather than released versions, and then adds verified OpenJ9/Semeru release rows. Supplemental failures are retained in notes; complete inability to produce evidence raises.

#### IBM adapter (`sources/ibm.py`)

- `_role(label)` normalizes a heading and maps it to product/affected/fix/APAR/package/action/link semantic roles. `_table(table)` scans rows until it finds a useful header and returns `(rows, header_index, roles)`. `_cell(cells, roles, role)` safely reads one mapped cell, while `_links(...)` resolves non-fragment links in that cell.
- `_fixed_version(text)` locates fix/action wording, then searches only the relevant trailing fragment for a version. This reduces the risk that an affected version earlier in the sentence is promoted to a fix.
- `_fix_blocks(doc)` finds fix/remediation headings and returns bounded sibling blocks. `_level_product(header, level)` interprets AIX/VIOS level labels into product names. `_level_prefix(level)` extracts a comparable dotted branch prefix. `_branch_label(title, line)` accepts prose as a branch-specific fix only when action wording and version/product context are present. `_prose_nodes(node)` returns the node plus meaningful descendants for free-form bulletins.
- `_bulletin_url(reference)` calls `urlparse`/`parse_qs` and recognizes current IBM support/security paths plus legacy `docview` IDs; it canonicalizes only supported IBM references and returns `None` otherwise.
- `IBM._search(context)` calls CVE.org references, IBM X-Force JSON, `_bulletin_url`, `HTTP.document`, every parsing helper, and `Evidence`. The discovery block gathers unique bulletin URLs. Each bulletin is checked for the target CVE. Structured-table parsing preserves product branches, APAR/package identifiers, filesets, service packs, and links without treating an AIX service-pack column as an APAR. Prose-block parsing uses `_branch_label`/`_fixed_version` conservatively for MQ and other layouts. Duplicate evidence is collapsed by a semantic key. If target pages exist but no known fix structure can be established, it raises/returns assessment-only evidence rather than fabricating a fix.

#### Oracle adapters

- `OracleCPU._search(context)` calls `referenced`, `HTTP.document`, XPath/table parsing, `clean`, and `_jdk_releases`. It gathers CPU pages from references/indexes, identifies exact target-CVE rows including continuation/mapping rows, preserves product/component/affected text and primary-patch relationships, and emits CPU assessment rows. For Oracle Java SE rows it calls `_jdk_releases`; it does not transfer Java fixes to GraalVM or unrelated products.
- `OracleCPU._jdk_releases(context, cpu_url, cpu_rows)` derives the CPU quarter from the URL, extracts affected Java branches from CPU evidence, fetches current/archived release indexes, and calls local `releases(page_url, latest)`. `releases` follows release-note links, keeps only affected major branches, verifies CPU wording in each note, parses a release date, and appends release evidence. The outer function order-deduplicates versions and returns only branch-relevant releases.
- `OracleLinux._search(context)` calls `referenced`, `HTTP.document`, XPath, `urljoin`, `table_rows`, and `Evidence`. It discovers Oracle Linux advisory links, requires the exact CVE in each advisory, parses package/version rows, and emits package-update evidence. Package names ending in source/debug suffixes are handled conservatively; no package-manager command is generated.

#### PostgreSQL and small vendor adapters

- `postgresql._column(header)` normalizes a header and maps affected/fixed/published roles. `PostgreSQL._search(context)` calls `HTTP.document`, XPath, `clean`, `_column`, and `Evidence`. It requires the target CVE in a heading/page, discovers semantic table columns, and uses local `field(role)` for bounds-safe reads. Negative fix text never becomes `fixed_version`; version regexes extract branch fixes and publication metadata. An unrecognized target page raises a layout error.
- `OpenSSL._search(context)` calls `HTTP.document`, XPath, regexes, and `Evidence`. It finds the requested CVE row/anchor, splits affected version ranges, parses fixed releases associated with the row, and emits one row per fixed version. It does not use unrelated rows from the vulnerabilities page.
- `RedHat._search(context)` calls `HTTP.document` for the public CVE page, Red Hat APIs through `HTTP.json`, `section`, and `Evidence`. It first verifies the CVE page, pages search results, fetches CSAF documents, maps product IDs to names, and emits only statuses explicitly listed as fixed plus remediation details. Advisory lookup failures remain source errors at the engine layer.
- `Rocky._search(context)` calls Rocky list/detail JSON endpoints, filters exact CVE entries, walks release/RPM maps, and emits sorted binary package fixes. Product/release filtering uses normalized text and avoids counting source packages as proof for another release.
- `SQLite._search(context)` calls `HTTP.document`, row XPath, `clean`, regexes, and `Evidence`. It accepts a row only when the requested CVE appears among possibly multiple CVEs, extracts the fix/check-in identifier and row description, and emits one upstream row.
- `SUSE._search(context)` calls `HTTP.document`, exact-CVE text checking, `table_rows`, and `Evidence`. It interprets sufficiently populated package rows and preserves their visible remediation fields; page/layout mismatch raises or yields no evidence rather than a generic fix.
- `TIBCO._search(context)` calls `referenced`, `HTTP.document`, `clean`, `section`, and `Evidence`. It processes only explicitly referenced TIBCO pages containing the exact CVE and captures remediation-section text. It does not perform an independent broad TIBCO search.
- `Ubuntu._search(context)` calls `HTTP.document`, exact-CVE checking, `table_rows`, and `Evidence`. It reads package/release/status rows and distinguishes released fixes from `not affected`, `needed`, or other states; only released version text is promoted to a fix.

#### Red Hat-compatible, package, and upstream helper boundaries

- The small module helpers such as `debian._state`, `ibm._branch_label`, and `postgresql._column` are semantic classifiers used only by their containing adapters. They transform publisher labels; none checks an installed host.
- Every adapter returns `Evidence` objects to `Engine.lookup`. The only common outbound network path is `HTTP`, so allowlisting, redirect checks, size limits, retry behavior, and caching apply uniformly. Adapter parsing proves what the retrieved publisher page said according to the implemented layout; it does not prove application compatibility or execute remediation.

### 10.5 Context storage, fixture generation, and remediation assessment internals

#### `context_gathered/context_manager.py`

- `ensure_table(connection)` calls `connection.cursor`, Oracle `execute`, and `fetchone`. It queries the data dictionary for `CVE_CONTEXT`; if absent, it executes the table/identity/CLOB DDL. The cursor context closes resources automatically. It creates schema only—no context record—and does not migrate an existing incompatible table.
- `load_template(path)` calls `Path.open`, `json.load`, and nested `get`. The structure block requires a top-level object with object-valued `request` and `response`. The identity block requires nonblank platform/CVE/vendor values and bounds the platform name. It returns both full payload and extracted index values so `save_context` does not independently reinterpret the JSON.
- `save_context(connection, payload, platform, cve, vendor)` calls `cursor.var`, `setinputsizes`, `execute`, `json.dumps`, and `commit`. It configures Oracle CLOB bindings, inserts the indexed columns plus complete request/response JSON, retrieves the generated ID through a returning variable, commits, and converts the ID to `int`. Failure before commit propagates; no explicit rollback block is present.
- `get_context(connection, context_id)` calls SQL `execute`/`fetchone` and local `decode`. Missing rows return `None`. `decode` reads Oracle LOB objects when necessary and JSON-decodes strings/bytes; already-decoded values pass through. The result reconstructs request/response plus indexed metadata and ISO timestamp. It reads one record and makes no evidence/model call.
- `main()` calls `load_template`, `oracledb.connect`, `ensure_table`, `save_context`, and optionally `get_context`. It parses template/connection arguments, resolves credentials from CLI/environment/default fallback, rejects missing connection values, and uses a connection context. The final console JSON is confirmation/audit output. The checked-in password fallback is an operational security defect, not a feature.

#### `remediation/create_test_contexts.py`

- `load(path)` calls `Path.read_text` and `json.loads`; malformed JSON propagates.
- `main()` calls `load`, `copy.deepcopy`, path creation/writes, and `json.dumps`. It validates the source context/profile/manifest inputs, then loops manifest product groups and CVEs. For each CVE it clones the template, injects request identity and profile-derived server/product/component versions, explicitly marks dummy/test provenance, and writes `<slug>/cves/<CVE>.context.json`. A per-product bundle, root product manifest, and combined context are written afterward. Missing profile values remain missing rather than being synthesized from CVE descriptions. These files are regression fixtures and are never live host collection.

#### `remediation/remedition_agent.py`: configuration and provider calls

- `CitationValidationError.__init__(evidence_id, quote, reason)` stores the three diagnostic fields and calls `ValueError.__init__` with a bounded JSON-escaped quote message. This lets `assess` distinguish citation failures from other structural/semantic validation failures.
- `load_config(path)` calls `read_json`, environment access, and `Path.read_text`. It requires an object, selects only `bedrock` or `azure_openai`, validates positive integer limits, resolves the prompt relative to the config, and loads provider overrides from environment. The returned dictionary contains prompt text; it never validates live credentials.
- `required(settings, key)` reads one value and requires a nonblank string. It is used for mandatory provider settings so an empty environment override cannot silently reach a client constructor.
- `LLMClient.__init__(config)` calls `required`, `boto3.Session`/botocore `Config`, or `AzureOpenAI`. The Bedrock block chooses explicit credentials, a nonblank profile, or the default chain, then creates a runtime client with retry/timeouts. The Azure block validates endpoint/key/deployment/api version and constructs the client. It stores provider settings but makes no request yet.
- `LLMClient.generate(messages, prompt)` calls Bedrock `converse` or Azure `chat.completions.create`. For Bedrock it sends system/user messages, configured inference parameters, joins returned text blocks, extracts usage, and returns `(text, usage, stopReason)`. For Azure it converts the system prompt into the message list, requests JSON output, reads content/usage/finish reason, and returns the same tuple shape. Unknown provider/empty response conditions raise; no validation of the decision occurs here.
- `read_json(path)` calls `Path.read_text` and `json.loads`. It is intentionally small so all file JSON follows UTF-8 parsing behavior.

#### `remediation/remedition_agent.py`: package construction and validation

- `prepare(context, evidence)` calls nested `get`, `isinstance`, and `enumerate`. It requires matching nonblank CVE identity across the context request and evidence response. It requires a list of evidence records, assigns a stable `evidence_id` to each record, and returns a package containing request context, server/application/components inventory, source coverage/errors/notes, and evidence. It reorganizes data; it does not judge applicability.
- `contains_dummy(value)` recursively calls itself over dictionaries/lists. It returns true when any dictionary has `is_dummy` truthy, allowing outer safety fields to reflect fixture provenance even if the marker is nested.
- `normalize_test_context_for_assessment(context)` calls local recursive `normalize`. Dictionary blocks remove `is_dummy` and `context_kind` only from the LLM-facing copy; list blocks remove fixture-only warning strings; string blocks map known marker tokens and replace `synthetic-test` wording. The source context object remains unchanged for hashing/audit and still controls `execution_ready`.
- `validate_decision(decision, package)` uses local recursive `text_values`, exact substring checks, and explicit invariant branches. It first requires the same CVE. `text_values` flattens strings from each evidence record; the source map is indexed by `evidence_id`. It combines top-level and remedy claims, requires every non-workaround remedy to carry a version/patch identifier, and requires that identifier to appear in a fix-support quote. Every claim must use an existing evidence ID, a quote of at least three trimmed characters, and an exact substring of that same record. Verdict blocks then enforce: `FIX_AVAILABLE` means affected + selected non-workaround + `SUPPORTED` compatibility evidence + no blockers/conflicts; other verdicts cannot select a remedy; negative/no-fix verdicts need affirmative claims; `NOT_APPLICABLE` needs `NOT_AFFECTED`; `NEEDS_INPUT` needs a blocker. It raises on failure and has no side effects.
- `downgrade_invalid_citations(decision, package)` is invoked only after one repaired model response still fails with `CitationValidationError`. Local `text_values` flattens evidence and `sources` indexes it. Local `supported(claim)` requires a three-character exact quote in the named record. Local `remedy_supported(remedy)` applies that check to every fix/applicability/compatibility claim; because partial support could change meaning, one invalid claim removes the entire candidate. Top-level claims are filtered individually. The function then forcibly sets verdict `INSUFFICIENT_EVIDENCE`, applicability `UNKNOWN`, and recommendation `None`, adds an idempotent safety note and summary explanation, and reconstructs the Pydantic `Decision` with `model_validate(model_dump())`. It preserves useful valid evidence while guaranteeing no actionable conclusion survives. It does not prove the semantics of retained quotes, and its strict case-sensitive/minimum-length check can discard legitimate differently cased or very short text.
- `assess(package, client, config)` calls `json.dumps`, `Decision.model_json_schema`, `client.generate`, `Decision.model_validate_json`, `validate_decision`, and possibly `downgrade_invalid_citations`. It rejects oversized input instead of truncating evidence. The two-attempt loop sends package+schema, requires a complete model stop reason, strips one surrounding code fence, parses the Pydantic model, and validates invariants. On the first failure it appends the original assistant output plus narrowly tailored repair feedback; Pydantic details are not echoed wholesale because they may contain source text. On the second failure, a compatibility-specific failure is downgraded to a conditional nonselected candidate; a citation failure goes through `downgrade_invalid_citations`; other failures abort. Every returned downgrade is validated again.
- `run_agent(context, evidence, client, config, allow_dummy)` calls `prepare`, `contains_dummy`, optional context normalization, and `assess`. It rejects dummy input unless explicitly allowed. It hashes the exact prompt and normalized package, records retrieval/model metadata and original context snapshot, converts the decision to a dictionary, and hardcodes `execution_ready: false`. The function returns a reproducible assessment record; it performs no file write or remediation.
- `main()` calls `load_config`, `read_json` or stdin JSON loading, `prepare`, `LLMClient`, `run_agent`, temporary `write_text`, and atomic `replace`. Argument validation requires context/evidence sources and protects dummy use. It ensures default output/config paths, invokes the model, writes through a sibling temporary file to avoid a partially written result, and prints the final path. The default singular config-name mismatch is a visible standalone CLI defect; the grouped runner supplies the actual plural file explicitly.

#### `remediation/run_grouped_remediation.py`

- `read_json(path)` and `write_json(path, payload)` wrap UTF-8 JSON parsing/pretty persistence; `write_json` creates parents first. Neither catches malformed JSON/I/O failures.
- `safe_path_part(value)` calls a regular expression to replace Windows-forbidden/control characters, trims trailing space/dot, and supplies a safe fallback. It protects artifact directory names, not arbitrary user-selected output roots.
- `load_environment()` calls dotenv loading, removes blank AWS profile variables, and returns selected environment metadata. Removing blank profiles prevents boto3 from treating an empty profile as a real name.
- `validate_model_credentials(config_path)` calls `read_json`, selects the configured provider, and for Bedrock creates a boto3 session then calls `get_credentials`. Azure validates required configuration/environment strings. This proves configuration/credential resolution only; it does not call the model or test network permission.
- `public_reasoning_record(result)` reads the internal result/decision and builds a compact record containing run/CVE/product identity, verdict/applicability, summaries, evidence-backed claims, blockers/conflicts/missing information, candidates/recommendation, and errors. It excludes hidden reasoning because no hidden chain-of-thought is requested or stored.
- `apply_test_inventory(items, profiles_path)` calls `read_json`, matches product names case-insensitively, and mutates each item context. It reuses profile OS/product/component versions, marks request/response dummy/test provenance, and appends a warning. Missing matches are left partial. This function is explicitly test-only and requires the outer allow-dummy path.
- `apply_context_directory(items, context_dir)` calls `resolve`, recursive glob, `read_json`, CVE regex validation, and local `score`. It indexes valid `*.context.json` by CVE, then scores candidates: product-group exact match weight 4, product membership 2, each component membership 1. `max` chooses the best; score zero or no candidate sets `context_missing`. A match replaces generated partial context and may update vendor/OS. The scoring is identity matching, not freshness or truth validation.
- `generated_run_id()` calls UTC `strftime` and `uuid4` to produce a time-readable collision-resistant ID.
- `_split(value)` splits `|`, trims, filters empties, and order-deduplicates. It decodes grouped CSV cells.
- `read_grouped_csv(path)` calls `csv.DictReader`, `_split`, CVE regex extraction, and sorting. It validates required headers and nonempty product/component/CVE values, then expands each grouped row into one item per distinct CVE while preserving source row and context metadata. It builds a deliberately partial context because the CSV does not establish installation.
- `select_items(items, products, cves, start_row, rows, all_cves)` filters by requested products/CVEs/source-row floor and sorts deterministically. In default mode it keeps the earliest CVE for each product group using a `seen` set; `all_cves` keeps all. Row limiting applies after filtering/sorting.
- `cve_sort_key(cve)` validates the complete ID and returns integer `(year, sequence)`, avoiding lexical mistakes such as sequence `10000` versus `9999`.
- `latest_cve_per_component(items)` calls `cve_sort_key` and keeps the maximum CVE per `(product_group, component)` key; final rows are sorted by original source position. “Latest” is identifier order, not publication date or severity.
- `fetch_all(items)` adds the evidence `src` path, constructs one `Engine`, derives product/OS/description/context version values, and calls `Engine.lookup` for each item. It returns evidence packages in input order. It does not cache at this layer beyond the engine HTTP cache.
- `main()` calls every runner helper, `subprocess.run`, and artifact writers. It parses selection/safety flags, loads and narrows grouped input, optionally chooses latest per component, applies real-directory context and/or explicitly allowed synthetic profiles, and supports a dry-run before model work. Credential validation precedes assessment unless fetch-only. For each selected CVE it creates safe artifact directories, fetches/saves evidence, invokes `remedition_agent.py` as a subprocess with explicit config/context/evidence/output, reads the result, and writes a public reasoning record. Error handling either records and continues or aborts based on `--continue-on-error`. The final block writes per-run aggregate/reasoning JSON with status and paths. No branch executes an install command, approval transition, rollback, or verification scan.

### 10.6 Experimental `Internet_lookup` internals

#### Configuration and data contracts

- `config._load_project_env()` calls `Path(__file__).resolve` and optional `load_dotenv` to locate/load the repository `.env` without overriding existing process variables. Absence of dotenv is tolerated at module import.
- `_provider()` reads fallback-specific provider, then general `LLM_PROVIDER`, then defaults to `bedrock`, and lowercases it. `_model(tier)` checks a tier-specific override and otherwise chooses provider-specific defaults. These functions run while `Config` defaults are constructed, so environment at import/instantiation time affects model choice.
- `Config` is a dataclass block rather than a function. Its fields define search provider, models, query/result/fetch/LLM caps, parallelism, deadline, HTTP/model timeouts, page/input limits, heartbeat thresholds, cache TTL, and artifact directories. These are independent guardrails; increasing one does not remove another.
- `Budget.__init__(cfg)` copies configured limits into counters and creates a lock. `Budget.take(kind)` validates the counter name, enters the lock, raises `BudgetExceeded` when used count reaches the limit, otherwise increments exactly once. `Budget.left(kind)` returns nonnegative remaining capacity under the same lock. This makes parallel fetch/extraction accounting race-safe, but it does not cancel already-started work.
- `HostProfile.label()` joins available OS/TL/SP fields or returns `unknown host`; build/packages are not included in this short label. `LookupResult.to_dict()` calls `dataclasses.asdict`, recursively producing JSON-serializable dictionaries/lists.
- `Plan` is the source-planning dataclass containing `component_type`, bounded site targets, and an explanatory note. It has no methods or side effects; `plan_for` creates it and the pipeline consumes it.
- `__main__.main()` parses CVE/component/status/host/package/cache/search options, constructs `Config`, `CveRow`, and optional `HostProfile`, calls `run_fallback`, and prints `result.to_dict()` as JSON. Package strings are split into a dictionary at the CLI boundary. Exit status is not derived from lookup status in this entry point.

#### Source policy and query construction (`sources.py`)

- `_host_matches(host, domain)` accepts exact host or a dot-delimited subdomain through `endswith`; this avoids suffix tricks such as `evil-example.com` matching `example.com`.
- `tier_of(url)` calls `urlparse`, then scans tier maps. It requires both a matching hostname and configured path prefix, returning 1/2/3 or `None`. This single function gates search hits, redirects, references, and fetch eligibility.
- `other_cve_in_url(url, cve_id)` finds all URL CVE tokens and returns the first one different from the target. It is a fast near-miss guard, not a page-content validator.
- `exact_cve_regex(cve_id)` calls `re.escape` and compiles case-insensitive numeric-boundary lookarounds so a target cannot match a longer CVE sequence.
- `_query_term(value, max_chars)` stringifies untrusted CSV/context text, removes quotes/control whitespace, collapses spaces, rejects known placeholder terms, and truncates at a fixed length. This limits prompt/search injection surface but does not establish that the term is correct.
- `_site_intent(site)` extracts the hostname portion and returns publisher-specific fix/status vocabulary from `SOURCE_QUERY_INTENT`, falling back to generic advisory/fix terms.
- `heuristic_component_type(component, host_os)` lowercases component text and applies ordered keyword rules for IBM/AIX, PostgreSQL, unknown placeholders, or general open source. `host_os` is accepted but not currently used, so host OS cannot alter this heuristic.
- `plan_for(component_type)` looks up `PLANS`; unknown types receive the conservative `other` plan with bounded sites and explanatory note.
- `build_queries(cve_id, component, plan, host_label, context_term)` calls `_query_term` and `_site_intent`. It normalizes the CVE, sanitizes product/detail/host, builds a broad affected-version query and a remediation query, optionally adds IBM APAR/iFix vocabulary, then one query per plan site with publisher intent. The final block case-insensitively deduplicates while preserving order. The function creates search text only; it neither searches nor trusts the query terms as evidence.

#### Search, fetch, and model clients

- `SearchProvider.search(query, max_results)` is the interface stub and raises `NotImplementedError`.
- `DirectCveSearch.__init__(log)` stores the logger. `search(...)` extracts exactly one CVE and optional `site:` term, matches that site against canonical `ROUTES`, formats deterministic CVE/NVD/vendor URLs, caps results, and returns `SearchHit` objects. It calls no search API; unsupported sites produce no hit.
- `AnthropicWebSearch.__init__(llm, cfg, log)` stores dependencies. `search(...)` consumes one LLM budget unit, marks activity, calls Anthropic `messages.create` with its web-search tool, parses returned web-search result blocks into hits, records usage/duration, and always clears activity. It requires the direct Anthropic provider because Bedrock/Azure clients do not expose the same tool path here.
- `BraveSearch.__init__(cfg, log)` stores dependencies and reads `BRAVE_API_KEY`. `search(...)` requires the key, marks activity, calls Brave REST with query/count/timeouts, raises on HTTP errors, maps `web.results`, and clears activity in `finally`. Search budget is consumed by the pipeline before this method.
- `make_search(cfg, llm, log)` dispatches `direct`, `brave`, or `anthropic`; an unknown configured value raises early.
- `html_to_text(html)` tries BeautifulSoup, removes script/style/noscript/SVG nodes, preserves title plus visible text, and collapses blank lines/whitespace. If BeautifulSoup is unavailable/fails, regex stripping supplies a less precise fallback.
- `window_around(text, cve_id, max_chars)` calls `exact_cve_regex`. Short text passes through; absent CVE returns the beginning; present CVE returns a bounded window centered near the first exact occurrence. This controls LLM input size without claiming the rest of the page is irrelevant.
- `Fetcher.__init__(cfg, log, budget)` stores dependencies. `fetch(url, via)` calls `tier_of`, `Budget.take`, `requests.get`, streamed iteration, content-type handling, and `html_to_text`. It rejects nonallowlisted URLs before network access, logs activity, follows redirects but rechecks the final URL tier, caps bytes and elapsed streaming time, decodes JSON/text/HTML, and returns a `Page(ok=True)` on success. Every exception becomes `Page(ok=False,error=...)`; activity is cleared in `finally`, so parallel pipeline work can continue.
- `parse_json(text)` trims text, removes one code fence, finds the outermost braces when chatter surrounds JSON, and calls `json.loads`. Missing braces/malformed JSON raises; it does not repair truncated structures.
- `LLM.__init__(cfg, log, budget)` stores dependencies, initializes lazy client/token counters, and creates a lock. `LLM.client` lazily constructs exactly one Anthropic, Bedrock, or Azure client. The Bedrock block carefully strips quoted environment values, chooses explicit/profile/default credentials, configures retries/timeouts, and raises contextual credential errors. Unsupported provider raises.
- `LLM.record_usage(...)` updates aggregate token counters under lock and logs model/purpose/tokens/duration/tag. `LLM.complete(...)` consumes one LLM-call budget, chooses fast/deep model, marks activity, calls the provider-specific API, extracts text/input/output tokens, records usage, and clears activity in `finally`. It returns raw text; JSON/schema/provenance validation belongs to `steps.py`.

#### Extraction, reconciliation, and ranking (`steps.py`)

- `_norm(s)` lowercases and collapses whitespace for exact-ish provenance comparison. `_short(url)` strips scheme/common prefix for log labels.
- `extract_facts(llm, cfg, log, page, cve_id)` calls `window_around`, `LLM.complete`, `parse_json`, `_num`, and `_verify_provenance`. It sends only bounded page text with the extraction schema/rules, coerces expected fields into an `ExtractedFacts` object, keeps only HTTP(S) references and recognized types, and then removes unsupported values. It is one-source extraction, not reconciliation.
- `_num(v)` returns `None` for absent/unparseable values and otherwise `float(v)`, preventing one bad CVSS string from failing the whole page.
- `_verify_provenance(facts, page_text, log, tag)` normalizes page/evidence snippets. For every fixed-version item it retains only entries whose evidence snippet occurs in the page; unsupported stance evidence clears the stance; CVSS values absent from source text are removed. It logs each removal. This proves snippet presence, not correct interpretation.
- `reconcile(all_facts)` sorts facts by source tier and creates `Reconciled`. It chooses the first nonempty description/product from strongest sources, order-deduplicates affected versions and fixes, records source-tagged stances, and prefers tier-2 CVSS fields. Divergent same-priority values are added to `conflicts`/`unresolved`; it does not average scores or merge incompatible fixes.
- `llm_resolve(llm, log, rec, cve_id)` calls the deep model only for unresolved conflicts, parses its JSON, and applies only recognized numeric CVSS fields. Explanations are logged; invalid/unrecognized outputs leave deterministic reconciliation unchanged.
- `deterministic_options(rec)` converts at most three sourced fixes into low-confidence, host-unverified upgrade options with their retrieved URL; no fixes produce one `no_fix` option explicitly phrased as “not found in retrieved evidence.”
- `map_and_rank(llm, log, rec, row, host, pages)` sends reconciled facts plus scanner/host context to the deep model, parses options, caps count, validates enum-like fields, and filters source URLs to actually retrieved pages. Options lacking citations are downgraded; absent host forces `applicable_to_host: unverified`. It returns `(options, needs_human, reason)` and never produces execution commands.
- `classify_component(llm, component)` calls the fast model and `parse_json`, returning one of the allowed component types or `other`. Pipeline exception handling supplies the fallback if the call fails.

#### Logging and orchestration

- `StepOutcome.__init__()` initializes `ok=True` and empty detail. `RunLogger.__init__` creates the log directory/file, timestamps a unique JSONL filename, stores heartbeat thresholds, and initializes locks/activity state.
- `RunLogger.elapsed()` subtracts start time. `_emit(level, msg, **data)` builds a timestamped structured record, writes and flushes JSON under lock, and optionally prints a compact console line. `info`/`warn` are thin level wrappers.
- `activity(text, tag)` and `clear_activity(tag)` mutate the current-activity map under lock. `_heartbeat(stop, name, t0)` waits in intervals, emits heartbeat/stuck records containing current activities, and exits when the event is set; it observes but never cancels work.
- `step(name, detail)` is a context manager. It logs start, launches a daemon heartbeat thread, yields `StepOutcome`, logs done on normal exit, logs/re-raises exceptions on failure, then signals heartbeat stop and clears activities in `finally`. `close()` best-effort closes the JSONL handle.
- `FallbackRun.__init__(...)` calls `RunLogger`, `Budget`, `LLM`, `make_search`, and `Fetcher` unless dependencies are injected. It records deadline/start state and initializes pages/facts/options/errors/degradation/result collections. Injection is what makes the offline end-to-end test possible.
- `expired()` compares elapsed wall time with `deadline_s`; on first expiry it appends/logs one degradation warning and returns true. It gates future stages but cannot terminate a request already in progress.
- `guarded(name, detail, fn)` wraps a callable in `RunLogger.step`. Success returns its value. `BudgetExceeded` adds degradation and returns `None`; other exceptions add a typed error and return `None`. This is the pipeline’s “partial result instead of total abort” boundary.
- `run()` calls `_run` and always calls `_emit_step`; unexpected orchestration exceptions are recorded, and the logger closes in `finally`. Thus a best-effort `LookupResult` is returned even after many stage failures.
- `_run()` calls the stages in order through `guarded`: intake, cache, context, planning, queries, search, fetch, hit validation, extraction, reference follow-up, reconciliation, mapping. It checks cache early and returns on a hit; deadline/empty-result checks skip later expensive stages without fabricating evidence.
- `_intake(s)` logs scanner status, missing row fields, and supplied MCP-evidence keys. `_build_context(s)` logs supplied component/type/host only. Neither enriches or validates the values.
- `_cache_path()` calls regex sanitization and combines CVE/component/host label. `_cache_lookup(s)` checks existence and age, loads JSON into `LookupResult`, marks cache hit, and returns it; stale/malformed cache falls through via the guarded error path. Provider/model/query configuration is not part of the key.
- `_plan_sources(s)` calls `heuristic_component_type`, optional `classify_component`, and `plan_for`. A known heuristic avoids an LLM call; unknown text uses the model, with logged `other` fallback on failure. It stores the plan and logs sites/note.
- `_build_queries(s)` reads optional `csv_component`/`affected_symbol` details, calls `build_queries`, stores output, and logs every bounded query.
- `_search(s)` loops queries while deadline/budget allow, calls `Budget.take("searches")` then provider `search`, and stops after two consecutive provider failures. It filters hits through `tier_of`, `other_cve_in_url`, and URL deduplication, retaining better metadata for duplicates. The final sort prioritizes lower tier number and caps candidate pages; `_tier_mix` counts T1/T2/T3 for logs.
- `_fetch_many(urls, via)` uses `ThreadPoolExecutor.map` over local `one(u)`. `one` calls `Fetcher.fetch` and logs timing/status/size. Map preserves URL order even though work runs in parallel. `_fetch_pages(s)` extends all pages, including failures, and logs success totals.
- `_validate_hits(s)` compiles `exact_cve_regex` and marks only successful search pages containing the target CVE as validated; rejected pages remain in the source audit list. `_extract_one(page)` calls `extract_facts`, logs counts, and records budget/model/JSON errors as page-specific errors. `_extract_pages(pages)` runs `_extract_one` in parallel, filters `None`, and extends facts; `_extract_all` applies it to validated search pages.
- `_follow_references(s)` gathers bounded new tier-1/2 references from already extracted facts, rejecting duplicates/other-CVE URLs. It fetches them, appends page audit records, and treats successful followed pages as validated provenance from a target-CVE source before extraction, even if they do not repeat the CVE. This supports linked release notes but is a weaker gate than initial-page exact-CVE validation.
- `_reconcile(s)` calls deterministic `reconcile`, logs counts, and calls `llm_resolve` only when unresolved conflicts and budget/deadline allow. Failure retains deterministic data and logs degradation.
- `_map_and_rank(s)` returns a needs-human no-fact outcome when reconciliation is empty. Otherwise it calls `map_and_rank`; any failure falls back to `deterministic_options`, records degradation/error, and requires human review.
- `_build_result()` derives `ok`, `partial`, or `insufficient_evidence` from facts/options/errors/degradation, builds human-review reasons, serializes every page’s tier/fetch/validation/error state, and includes token/budget/timing/log metadata. An option does not make the result executable.
- `_emit_step()` returns an already cached result immediately; otherwise it enters a logged emit step, calls `_build_result`, writes a unique result JSON, and writes cache only for `ok`/`partial`. Write failures return an error-shaped `LookupResult` rather than losing all in-memory findings.
- `run_fallback(...)` normalizes and regex-validates the CVE before constructing `FallbackRun`. Invalid identity returns an immediate error result; valid input receives default `Config` and optional injected dependencies, then calls `.run()`.

### 10.7 Test harness and test-function internals

Tests call production functions with fixtures/mocks and assert observable contracts. They do not establish live internet/model/database/SSH availability.

#### Root `test_group_cves_by_component.py`

- `classification(cve, product, component)` constructs the exact classification dictionary expected by `component_rows`, including source-backed fact shapes and `SUPPORTED` status. It makes no production call.
- `GroupingTests.enriched_row(...)` returns one complete `COMPONENT_COLUMNS` row used by grouping/API tests. Defaults make each test override only the identity relevant to that contract.
- `test_enrichment_keeps_one_row_per_cve_before_grouping` calls `component_rows` with two CVE records and asserts two enrichment rows before calling `group_by_product_and_component` and asserting their later merge. It protects the boundary between per-CVE evidence and component presentation.
- `test_same_component_under_different_products_is_not_combined` calls `group_by_product_and_component` on two fixture rows and asserts two groups, proving the key includes product.
- `test_writer_creates_grouped_csv` uses `TemporaryDirectory`, calls `write_grouped_csv`, then reads with `csv.DictReader` and checks header/content. It verifies serialization, not concurrent file safety.
- `test_enrich_endpoint_persists_run_and_grouped_files` seeds `JOBS`, patches model classification and `DATA_DIR`, posts through `TestClient`, and checks HTTP payload, run-specific enriched CSV, default grouped CSV, and in-memory job state. Provider behavior is mocked.
- `test_reuse_endpoint_groups_saved_enrichment_file` writes a valid enrichment fixture, patches `DATA_DIR`, posts the reuse route, and asserts source provenance/group output. It proves allowed saved-file reuse without an LLM.
- `test_selected_pipeline_writes_only_checked_component_rows` defines `DeferredThread`; its constructor stores target/args and `start()` deliberately does nothing. The test posts one selected index, reads the selected CSV, and verifies only that row was written while removing queued state afterward.
- `test_selected_pipeline_passes_per_cve_context_directory_to_runner` patches `subprocess.run`, calls `execute_selected_pipeline`, and inspects the generated command for context/dummy/latest flags and absence of `--all-cves`. It does not launch the runner.
- `test_grouping_uses_run_specific_file_when_default_is_locked` defines `locked_first_write`, which records names and raises `PermissionError` only for `grouped_by_comp.csv`. Calling `grouped_payload` must retry a run-specific name and return the warning.
- `test_pipeline_events_stream_terminal_status_once` patches pipeline state/sleep, consumes the streaming body, and asserts one terminal SSE state. It tests generator termination, not proxy behavior.
- `test_pipeline_status_recovers_saved_run_after_restart` writes a combined aggregate under a temporary run directory, clears active memory, calls the status route, and checks reconstructed terminal paths/state.
- `test_remediation_results_endpoint_returns_public_reasoning` builds an aggregate with cited/uncited evidence, calls the results route, and asserts projection, verdict counts, and citation-scoped sources. It protects against exposing irrelevant raw evidence.

#### Internet CSV/live harness

- `_normalized(value)` trims/lowercases and collapses header punctuation/spacing. `_get(row, *aliases)` builds a normalized key map and returns the first nonempty alias value. They provide tolerant CSV column access without semantic inference.
- `CsvLookupInput` is the harness dataclass binding an original CSV row number to its `CveRow` and optional `HostProfile`; it carries provenance between `load_csv_inputs`, `choose_inputs`, and `run_live` without behavior of its own.
- `load_csv_inputs(path)` calls `csv.DictReader`, `_get`, CVE regex extraction, `CveRow`, and optional `HostProfile`. It validates headers/rows, expands each row into one input per CVE, maps project product/component/status/OS fields, and stores remaining nonempty columns in `extra` for audit/query context.
- `connectivity_check(cve_id, timeout_s)` calls `requests.get` against the CVE API, checks HTTP success and target ID occurrence, and returns a structured `{ok,status,error}`-style dictionary. It catches request failures so the live harness can print a diagnostic. It tests one endpoint, not all lookup publishers/models.
- `choose_inputs(items, cve, row_number, limit)` applies optional exact CVE and source-row filters, then slices to the positive limit. It preserves CSV order.
- `run_live(args)` calls the loader, selector, connectivity check, `Config`, and `run_fallback`. It creates test artifact directories, runs each selected input with configured provider/search/cache, serializes complete results, writes `latest_csv_lookup.json`, prints summaries, and returns success only when every result status is `ok` or `partial`. It can make real network and LLM calls.
- `build_parser()` defines CSV/CVE/row/limit/provider/search/cache/timeout options. `main()` parses them, rejects limits below one, and delegates to `run_live`.
- `test_load_csv_inputs_maps_project_columns` writes one temporary CSV, calls `load_csv_inputs`, and asserts CVE/product/detail/OS mappings. `test_direct_discovery_needs_no_api_key` uses `QuietLog.info` as a no-op, calls `DirectCveSearch.search`, and asserts the canonical NVD URL without network access.
- `test_build_queries_are_specific_bounded_and_sanitized` calls `plan_for` and `build_queries`, then asserts count, source-specific vocabulary, quote/control-character sanitization, and deterministic ordering. `test_build_queries_adds_ibm_fix_vocabulary` checks IBM APAR/iFix and site intent.
- `test_pipeline_returns_validated_source_and_evidence` injects `FakeSearch.search` (one controlled hit), `FakeFetcher.fetch` (one successful tier-1 `Page`), and `FakeLlm.complete` (budget-consuming extraction/ranking JSON) into `run_fallback`. It asserts exact-CVE validation, fixed-version propagation, and retained source URL while avoiding live services.
- `Internet_lookup/tests_related_files/test_mcp_adapter_llm_fallback.py` is a standalone real-source runner and pytest-compatible contract test for the MCP adapter fallback. `ForcedLayoutFailureAdapter.__init__` stores the runtime source name/URLs and derives allowed reference hosts; `_search` retrieves every supplied link through `HTTP` and deliberately raises so inherited `Source.search` invokes the shared fallback. `run_live(cve, source, urls, product)` validates the variable CVE, constructs the adapter/context, calls the configured real model, catches failures into the normal `source_errors` array, and returns `models.result`. Its CLI requires `--cve`, `--source`, and one or more `--url` values, with an optional product hint; it prints the MCP envelope and exits nonzero on errors. `test_real_source_runner_preserves_mcp_contract` remains offline by injecting controlled text for a real Apache publisher URL and mocking only `_invoke`; it verifies one fallback call and the resulting URL/CVE/fix fields.

#### Evidence-engine tests

- `CLITests.test_save_response_uses_safe_cve_and_vendor_filename` creates a temporary directory, calls `save_response` with unsafe vendor characters, and asserts the sanitized filename/content. It tests filesystem naming only.
- `EvidenceTests` is the evidence adapter `unittest.TestCase`. `FakeHTTP.__init__` stores URL-to-document/JSON fixture maps. `document(url)` and `json(url)` index those maps, deliberately failing on unexpected requests; this verifies which URLs an adapter attempts.
- `test_eclipse_omr_patch_is_relevant_but_not_a_released_version` calls `Eclipse.search` with fixture commit evidence and asserts patch provenance without `fixed_version`. `test_eclipse_adds_openj9_and_semeru_fixed_releases` adds release fixtures and asserts supplemental released versions.
- `test_apache_log4j_extracts_branch_specific_fixed_versions` parses fixture HTML through `Apache.search` and asserts distinct fixed branches rather than one collapsed version.
- The IBM tests call `IBM.search` with purpose-built bulletin tables/prose: `test_ibm_aix_service_pack_column_is_not_apar` checks role mapping; `test_ibm_multiple_application_branches_preserved` checks branch separation; `test_ibm_explanatory_aix_level_is_not_a_fix_branch` checks conservative prose classification; `test_ibm_mq_freeform_branch_fix_and_allowlisting` checks free-form fix parsing and allowed links.
- `test_oracle_does_not_turn_affected_into_fixed` calls `OracleCPU.search` and asserts CPU affected-version cells remain non-fixes. `test_oracle_mapping_continuation_has_distinct_product_cpu` verifies continuation-row state. `test_oracle_cpu_joins_jdk_release_notes_without_inventing_graalvm_fix` and `test_oracle_cpu_keeps_all_release_notes_when_inventory_branch_is_unaffected` supply CPU/release-note fixtures and assert branch-relevant releases without invented GraalVM transfer or premature inventory filtering. `test_oracle_also_addressed_is_explicitly_linked_to_primary_patch` checks that relationship remains provenance rather than an independent inferred fix.
- `test_rocky_filters_cve_and_preserves_release_packages`, `test_redhat_csaf_uses_fixed_product_id`, `test_ubuntu_not_affected_never_claimed_fixed`, and `test_sqlite_multiple_cves_in_one_upstream_row` each call the named adapter and assert its highest-risk status/filter transformation. `test_explicit_vendor_stays_scoped` calls `Engine.lookup`/routing with fakes and asserts explicit scope does not silently broaden.
- `test_adapter_llm_fallback.py` isolates the shared wrapper and model boundary. `FakeHTTP.get` records and returns one controlled publisher page; `BrokenSource._search` fetches it and then raises a layout error; `HealthySource._search` returns deterministic evidence; and `EmptySource._search` returns a legitimate empty result. `fallback_response(**updates)` creates a complete 13-field model-shaped item. `test_adapter_failure_uses_one_fallback_and_preserves_mcp_evidence_shape` monkeypatches `_invoke`, checks that one call occurs after the parser exception, checks the prompt's exact field list, and passes the returned `Evidence` through `models.result` to prove the normal MCP envelope is retained. The parametrized `test_normal_adapter_result_never_calls_fallback` proves both nonempty and empty deterministic results bypass the LLM. `test_fallback_rejects_a_model_field_not_found_verbatim_on_page` proves a hallucinated fixed version is rejected. `test_disabled_fallback_preserves_adapter_failure_as_source_error` proves the feature flag leaves failure reporting conservative. `test_bedrock_fallback_omits_deprecated_temperature` fakes the boto3 runtime and protects compatibility with Bedrock models that reject `temperature` in Converse requests.

#### Grouped-runner and remediation-schema tests

- `test_remediation_reads_grouped_csv_directly` writes grouped input, calls `read_grouped_csv`, and checks per-CVE expansion plus deliberately missing inventory. `test_selection_keeps_one_cve_across_components_of_same_product` calls `select_items` and asserts one default product representative.
- `test_latest_cve_per_component_uses_year_then_numeric_sequence` calls `latest_cve_per_component` and protects numeric `cve_sort_key` behavior. `test_product_names_are_safe_for_windows_directories` calls `safe_path_part` and asserts forbidden characters/trailing syntax are removed.
- `test_reasoning_record_is_linked_to_run_and_cve` calls `public_reasoning_record` and asserts audit identity. `test_previous_test_version_is_reused_and_labelled_dummy` and `test_java_se_previous_version_is_8u401` call `apply_test_inventory` and assert reused versions plus dummy labeling. `test_environment_loader_discards_blank_aws_profile` patches environment/dotenv and calls `load_environment` to protect boto profile handling.
- `test_context_directory_replaces_partial_context_with_matching_cve_fixture` writes competing context fixtures, calls `apply_context_directory`, and asserts the scored matching context replaces partial data. `test_context_directory_reports_selected_cve_without_fixture` asserts the missing list/flag without fabricating context.
- `citation_package()` and `invalid_citation_decision()` construct minimal evidence and deliberately misquoted decision dictionaries. `test_claim_accepts_short_exact_component_quote` validates only the `Claim` model’s minimum-length schema; it does not pass that claim through the stricter three-character `validate_decision` rule.
- `test_citation_error_identifies_non_verbatim_quote` calls `validate_decision`, catches `CitationValidationError`, and checks its evidence ID/quote/reason. `test_second_bad_citation_is_safely_downgraded` injects local `FakeClient.generate`, which records both messages and returns the same invalid JSON twice; it calls `assess` and asserts repair feedback, `INSUFFICIENT_EVIDENCE`, no recommendation/candidates/claims, and final revalidation.
- `test_test_context_is_normalized_for_reasoning_but_preserved_for_audit` calls `run_agent` with a capturing fake client. It asserts fixture markers are absent from the LLM package but remain in the stored audit snapshot and keep execution non-ready.

#### Anonymous callbacks and comprehensions

Python comprehensions/lambdas and React inline callbacks are intentionally not assigned independent workflow identities. In Python they perform local ordering, flattening, filtering, and dictionary/list construction described in their containing callable. In React, inline drag, click, page, close, and `map`/`reduce` callbacks only dispatch to the named state/network functions above or render rows. None creates a hidden model call, server command, evidence retrieval, approval, or remediation action.

## 11. Representative execution flows

### 11.1 Browser-driven current workflow

1. `UploadPanel.upload` posts a UTF-8 CSV to `upload_csv`.
2. `read_source_file` and `build_records` extract one record per CVE; the API retains one original preview row and keeps all observations inside records.
3. User selects a contiguous range. `enrich_range` calls Bedrock classification when unique source descriptions exist.
4. `validate_fact` confirms labels/quotes against scanner text. This is label grounding, not host affectedness.
5. `component_rows` writes run enrichment; `grouped_payload` groups product+component and writes grouped CSV.
6. User checks groups and starts a pipeline. `start_selected_pipeline` writes only those rows.
7. The current API command explicitly passes `context_gathered/test`, `--allow-dummy`, and `--reuse-test-inventory`; therefore this browser path assesses synthetic inventory, not a live host.
8. `run_grouped_remediation` expands selected CVEs, selects the highest CVE ID per component, loads test context, fetches vendor evidence with `Engine`, and runs the LLM assessment subprocess.
9. `validate_decision` enforces exact evidence IDs/quotes and fix/compatibility verdict invariants. The saved result says `execution_ready: false`.
10. SSE reports completion; the UI renders evidence, blockers, candidates, and recommendations for human review. There is no approval commit or deployment action.

### 11.2 Direct evidence lookup

1. CLI/MCP passes CVE/vendor/product/OS.
2. `Engine.lookup` validates CVE and retrieves CVE.org metadata for references/product hints.
3. `select` chooses explicit or heuristic adapters.
4. Each adapter fetches only allowlisted HTTPS sources, verifies CVE/page structure, and emits scoped `Evidence`.
5. `result` deduplicates/sorts and reports errors/coverage. A missing fix remains `no_verified_remediation_found`, not proof of safety.

### 11.3 Standalone command discovery and SSH

1. `component_version_command_agent.py` reads supported enrichment rows and asks Bedrock for a restricted version probe.
2. Python validates and writes PATH/version **templates** with a confirmed-path placeholder.
3. Separately, an operator may edit `paramiko_ssh_runner.py` constants and manually execute one reviewed command. No code connects the generated CSV to the runner, records approval, or turns its output into context JSON.

### 11.4 Experimental internet lookup

1. Caller supplies `CveRow` and optional `HostProfile`.
2. Pipeline plans source-aware queries; default direct search converts sites to canonical URLs.
3. Fetcher downloads allowlisted pages; exact CVE gate rejects unrelated pages.
4. LLM extracts facts; exact snippet checks drop unsupported fix/stance claims.
5. Rules reconcile data; optional LLM resolves limited conflicts and ranks conservative options.
6. Result/cache/log JSON is written. This flow is not wired into the production FastAPI/remediation runner.

## 12. Project-level limitations and human-control boundaries

### Context and identity

- No integrated production host-context collector exists. JSON context can be manually supplied/stored, and synthetic fixtures exist.
- UI remediation deliberately uses test inventory. It must not be represented as a production compatibility assessment.
- A discovered executable or version does not prove application ownership, runtime linkage, feature enablement, or vulnerability applicability.
- Grouped CSV values concatenate multiple CVE observations; downstream expansion assigns group product/component context to each CVE and may require per-CVE review.

### Evidence

- Publisher HTML/API parsers depend on current external layouts. Several intentionally raise source errors for unknown layouts; others may return no evidence.
- CVE.org/NVD/reference presence is discovery, not fix proof. Cross-vendor fixes are not automatically transferable.
- HTTP cache may be up to six hours old; the experimental cache defaults to seven days and does not include provider/model/config in its key.
- `Engine.lookup` catches adapter errors and returns partial coverage; consumers must inspect `source_errors` and notes.
- `record_context` silently returns no metadata after registry failure, so source discovery may be incomplete.
- The layout fallback runs only after a deterministic adapter exception, not after a normal empty result. Its exact-text checks reduce unsupported claims but do not prove semantic correctness or applicability. If the publisher cannot be refetched, the provider is unavailable, or output fails schema/provenance checks, the adapter remains a source error rather than silently accepting model text.

### Assessment and compatibility

- Exact citation checks prove that quoted strings occur in supplied records. They do not prove the quote was interpreted correctly, that a version range comparison is correct, or that a remedy supports the installed application.
- The remediation prompt explicitly has no deterministic package/version comparator. Ecosystem epochs, backports, service packs, suffixes, and branch rules remain evidence/judgment dependent.
- `validate_model_credentials` proves only that boto3 resolves credentials, not that network/model permissions work.
- LLM output can fail/truncate/misclassify. The code retries once and sometimes downgrades, but human review remains required.

### Approval and deployment

- Selecting a component in the UI is not a formal approval. No approver identity, timestamped approval decision, segregation-of-duties rule, ticket integration, or cryptographic signature is stored.
- No remediation install command is generated by the assessment agent, and no recommendation is sent to SSH/package managers. `execution_ready` is hardcoded `False`.
- `paramiko_ssh_runner.py` can change a remote system if an operator replaces `COMMAND` with a mutating command; its safety comes from manual review and host-key checking, not an approval workflow.
- Rollback, maintenance windows, deployment orchestration, post-change validation, and scan closure are not implemented.

### Service/operational issues

- `JOBS` and active run state are process memory; uploads disappear on restart. Completed remediation aggregates can be recovered, but queued/running work is not supervised durably.
- The background subprocess has no timeout/cancellation and captures all stdout/stderr in memory.
- API routes have no authentication/authorization in inspected code. The default listener is loopback, but deployment configuration could change exposure.
- `/api/health` checks only process responsiveness.
- The Oracle context utility contains a hard-coded password fallback in source; remove it, rotate the credential, and use secret management.
- Stored context manifests contain stale absolute paths from another workspace; current code may fail if those paths are used without regeneration/replacement.
- `remedition_agent.py` has a singular default config filename that does not match the checked-in plural filename; grouped execution avoids this by passing `--config`.
- A nested `.venv` exists under `src/aegis_evidence`; it is installed third-party code and should not be treated as or committed with application source.

## 13. Human input required

Human or external-system input is required to:

1. Supply trustworthy scanner data and resolve ambiguous/missing classifications.
2. Collect and verify real host/application inventory, ownership, linkage, enabled features, architecture, and package lineage.
3. Review source errors, publisher scope, branch/version semantics, and stale/conflicting evidence.
4. Confirm that any candidate remedy is vendor-supported for the actual application and environment.
5. Approve a change through an external change-management process (not implemented here).
6. Create/run deployment and rollback procedures (not implemented here).
7. Verify the post-change state and rescan.

## 14. Files inspected

### Project-owned executable source

- Root: `agent_utils.py`, `app.py`, `component_version_command_agent.py`, `config.py`, `cve_component_enrichment.py`, `group_cves_by_component.py`, `paramiko_ssh_runner.py`, `test_group_cves_by_component.py`.
- UI: `ui/src/App.jsx`, `ui/src/main.jsx`, `ui/src/styles.css`, `ui/index.html`, `ui/vite.config.js`.
- Evidence engine: `aegis-cve-evidence/src/aegis_evidence/{__init__,batch,cli,engine,http,llm_fallback,models,registry,server}.py` and every file under `sources/`.
- Remediation/context: `context_gathered/context_manager.py`, `remediation/create_test_contexts.py`, `remediation/remedition_agent.py`, `remediation/run_grouped_remediation.py`, `run_all_cves.ps1`.
- Experimental lookup: every Python file under `aegis-cve-evidence/Internet_lookup`, including its CSV test harness.
- Tests: every Python file under `aegis-cve-evidence/tests`.

### Configuration, prompts, documentation, and representative data

- `.env.example`, `.gitignore`, root and UI `package*.json`, `requirements.txt`, `aegis-cve-evidence/pyproject.toml`, both READMEs, `remediation/agent_configs.json`, `remediation/remediation_prompt.txt`, `context_template.json`, `test_inventory_profiles.json`.
- Representative per-CVE test context, product bundle, test manifest, combined context, enrichment/grouped/selected CSV headers, diagnostics/evidence/remediation artifact structures.
- Existing `PROJECT_DOCUMENTATION.md` was inspected for comparison but not used as proof where it disagrees with current files.

### Not inspected or not verifiable from source alone

- Root `.env` secret values are intentionally not reproduced or audited in this document.
- Third-party code under `.venv`, `node_modules`, Python packages, AWS/Azure/MCP/Oracle/SSH server implementations, and publisher services were not source-reviewed.
- Git internals, caches, compiled frontend output, bytecode, and generated run outputs were excluded.
- Every repetitive stored CVE fixture was not individually expanded; its shared fields/schema are documented above, per request.
- Live correctness/availability of every external publisher, Bedrock/Azure model, Oracle database, SSH target, and optional `aegis_core` module cannot be verified from static inspection.
- No `aegis_core/aegis_core` source directory was present in the inspected file inventory, so the optional synchronization path in root `config.py` could not be inspected.
