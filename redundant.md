# Removed code and schema elements

Every function, column, file or option removed by the 2026-10-20 change
("collection_id as the single collection identity; CVE_RUN / CVE_EVIDENCE; synthetic
inventory removed") is listed here before it was deleted. References were checked with a
repository-wide search (`*.py`, `*.ps1`, `*.ts/tsx`, `*.json`, `*.yaml`, `*.md`, excluding
`.venv`, `node_modules` and saved run artifacts under `remediation/runs/`).

## Schema: CVE_CONTEXT

### aegis-cve-evidence/context_gathered/host_context_db.py
* **Element Removed**: `gather_run_id` column (`COLUMNS`, the `rows_from_report` value, and the
  `import-<collection_id>` fallback for imported reports).
* **Reason for Removal**: Redundant tracking layer. `collection_id` already identifies one
  collection of one host. `gather_run_id` only tagged which hosts one `gatherer.py`
  invocation visited; no query, view, index or report read it. Run tracking now lives in
  `CVE_RUN` (one row per remediation run), which references `collection_id`.
* **Impact Verification**: The only readers were `host_context_db.py` itself and three
  assertions in `tests/test_host_context_db.py` (updated). `CVE_CONTEXT_LATEST` selects by
  `collection_id`/`collected_at`, not `gather_run_id`. An existing table is migrated in place
  by `ensure_table` (`ALTER TABLE CVE_CONTEXT DROP COLUMN gather_run_id`); stored rows are kept.

### aegis-cve-evidence/context_gathered/gatherer.py
* **Element Removed**: generation of `gather_run_id` in `main()` and the `gather_run_id` key in
  each JSON report.
* **Reason for Removal**: Its only consumer was the dropped column above.
* **Impact Verification**: `summary.json` and the per-host report keep every other field. Old
  reports that still contain the key load unchanged (unknown keys are ignored and kept in
  `raw_report`). `uuid` stays imported: it is still used for command markers.

## Synthetic inventory

### aegis-cve-evidence/context_gathered/build_synthetic_inventory.py
* **Element Removed**: the whole file (`main()`; writes `inventory/synthetic_test_hosts.yaml`).
* **Reason for Removal**: Synthetic code removal request.
* **Impact Verification**: Not imported anywhere; the only references were its own docstring
  and the generated YAML header.

### aegis-cve-evidence/context_gathered/inventory/disabled/synthetic_test_hosts.yaml
* **Element Removed**: the whole file (generated synthetic AIX/Java hosts, `synthetic: true`).
* **Reason for Removal**: Synthetic code removal request.
* **Impact Verification**: It was already in `inventory/disabled/`, which the app does not load
  (`REMEDIATION_INVENTORY` defaults to `inventory/sterling_rocky8.yaml`). Only
  `tests/test_host_inventory.py` loaded it; its synthetic tests were removed (below).

### aegis-cve-evidence/context_gathered/test_inventory_profiles.json
* **Element Removed**: the whole file (synthetic installed versions per product).
* **Reason for Removal**: Synthetic code removal request.
* **Impact Verification**: Readers were `build_synthetic_inventory.py` (removed),
  `run_grouped_remediation.py` `TEST_INVENTORY_PROFILES`/`apply_test_inventory` (removed),
  `remediation/create_test_contexts.py` (removed) and the default of
  `remedition_agent.py --context` (changed; see below).

### aegis-cve-evidence/context_gathered/host_inventory.py
* **Element Removed**: the `synthetic` file flag and the `_synthetic` host key in
  `load_inventory()` (and its "observed first" sort); the `_synthetic` term in `find_host()`'s
  ranking key; the `SYNTHETIC_TEST_VALUE` / `SYNTHETIC_TEST_INVENTORY` labels and
  `is_dummy=True` branch in `context_for_item()`; the "same synthetic flag" filter on other hosts.
* **Reason for Removal**: Synthetic code removal request; every loaded host is now observed.
* **Impact Verification**: Contexts are now always `OBSERVED_HOST_INVENTORY` with
  `collection_status: OBSERVED` and `is_dummy: false`, exactly what observed hosts already
  produced. Readers of `_synthetic` were `app.py` and `compatibility/context_provider.py`
  (both updated). Saved runs that carry the old synthetic labels are still recognised by
  `app.saved_fix_is_reviewable` through `context_kind`.

### aegis-cve-evidence/remediation/run_grouped_remediation.py
* **Element Removed**: `TEST_INVENTORY_PROFILES`, `apply_test_inventory()`,
  `RemediationOptions.reuse_test_inventory`, the `--reuse-test-inventory` CLI option and its
  `--allow-dummy` validation; the "synthetic" count in the inventory log line.
* **Reason for Removal**: Synthetic code removal request (it overwrote installed versions with
  the synthetic profiles).
* **Impact Verification**: `app.py` never set it (`test_group_cves_by_component.py` asserted it
  was `False`; that assertion was removed). Tests `test_previous_test_version_is_reused_and_labelled_dummy`
  and `test_java_se_previous_version_is_8u401` exercised only this function and were removed.
  `--allow-dummy` is kept: the UI passes it for observed inventory too, where it enables the
  "treat supplied inventory facts as authoritative" prompt section.

### aegis-cve-evidence/remediation/create_test_contexts.py
* **Element Removed**: the whole file (`main()`; wrote synthetic per-CVE contexts).
* **Reason for Removal**: Synthetic code removal request.
* **Impact Verification**: Not imported anywhere. Its default input
  `context_gathered/generated/manifest.json` no longer exists, so it could not run as shipped.

### aegis-cve-evidence/remediation/remedition_agent.py
* **Element Removed**: the default `--context test_inventory_profiles.json` of the standalone CLI.
* **Reason for Removal**: It pointed at the removed synthetic profiles file (and a profiles file is
  not a context document).
* **Impact Verification**: `--context` or `--context-stdin` is now required; the batch runner and
  the UI call the agent in-process and never used this CLI default.

### app.py
* **Element Removed**: the `not host.get("_synthetic")` filter in `observed_inventory_covers()`;
  the "then the generated synthetic test hosts" comment in `execute_selected_pipeline()`.
* **Reason for Removal**: Hosts no longer carry `_synthetic`; all loaded hosts are observed.
* **Impact Verification**: The function's result is unchanged for the shipped inventory (it held
  no synthetic hosts).

### aegis-cve-evidence/compatibility/context_provider.py
* **Element Removed**: `document["_synthetic"]` in `publish_yaml_to_oracle()`.
* **Reason for Removal**: The key no longer exists on loaded hosts.
* **Impact Verification**: Nothing reads `_synthetic` from `HOST_INVENTORY.inventory_json`.

### Tests
* **Element Removed**: `test_synthetic_hosts_replace_per_cve_files_and_stay_labelled`,
  `test_synthetic_matching_is_exact_like_the_old_profile_rule`, the synthetic assertions of
  `test_observed_inventory_wins_over_synthetic_for_the_same_application` (renamed; the
  multi-host assertions stay) and of `test_active_inventory_is_only_the_sterling_file_with_its_java_runtimes`
  (`tests/test_host_inventory.py`); `test_previous_test_version_is_reused_and_labelled_dummy`,
  `test_java_se_previous_version_is_8u401` (`tests/test_grouped_input.py`); the
  `reuse_test_inventory` assertion in `test_group_cves_by_component.py`.
* **Reason for Removal**: They tested only the removed synthetic code.
* **Impact Verification**: The remaining suite passes (see the change log in
  `aegis-cve-evidence/CODE_UNDERSTANDING.md`).

## Restored on 2026-10-21

* `host_inventory.py` `synthetic` file flag / `_synthetic` host key, the observed-first
  ranking, and the `SYNTHETIC_TEST_INVENTORY` / `SYNTHETIC_TEST_VALUE` / `is_dummy` labels;
  the observed-only filter in `app.observed_inventory_covers()`.
* **Reason**: a new hand-written fake inventory (`context_gathered/inventory/fake/`, the UI
  default for now) must stay labelled as fake. The generator, `synthetic_test_hosts.yaml`,
  `test_inventory_profiles.json`, `create_test_contexts.py` and `--reuse-test-inventory`
  stay removed.

## Not removed (kept on purpose)

* `context_gathered/test/` per-CVE context fixtures and `--context-dir`: hand-made `is_dummy`
  fixtures, not the synthetic inventory. Still read by `--context-dir` and by
  `app.saved_fix_is_reviewable` for old saved runs.
* `remedition_agent.normalize_test_context_for_assessment`, `contains_dummy` and
  `--allow-dummy`: agent-level safety handling for `is_dummy` contexts, still reachable through
  `--context-dir` fixtures.
* `remediation/repair_saved_test_runs.py`: a one-time audit fix of already saved runs; it reads
  no synthetic inventory.
