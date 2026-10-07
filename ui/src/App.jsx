import { useEffect, useMemo, useRef, useState } from "react";
import {
  AlertTriangle,
  ArrowRight,
  Check,
  ChevronLeft,
  CircleCheckBig,
  Database,
  Download,
  ExternalLink,
  FileSpreadsheet,
  Info,
  Layers3,
  LoaderCircle,
  Play,
  RefreshCw,
  ShieldCheck,
  UploadCloud,
  Wrench,
} from "lucide-react";

const PAGE_SIZE = 10;
const ENRICHMENT_TIMEOUT_MS = 30 * 60 * 1000;

function humanize(value) {
  return String(value || "Unknown").replaceAll("_", " ");
}

function ClaimList({ claims = [], sources = {} }) {
  if (!claims.length) return null;
  return (
    <div className="claim-list">
      {claims.map((claim, index) => {
        const source = sources[claim.evidence_id] || {};
        return (
          <blockquote key={`${claim.evidence_id}-${index}`}>
            <p>“{claim.quote}”</p>
            <footer>
              <span>{claim.evidence_id}</span>
              {source.url ? (
                <a href={source.url} target="_blank" rel="noreferrer">
                  {source.source || "Evidence source"} <ExternalLink size={12} />
                </a>
              ) : <span>{source.source || "Evidence source unavailable"}</span>}
            </footer>
          </blockquote>
        );
      })}
    </div>
  );
}

function RemedyCard({ remedy, sources, recommended = false }) {
  if (!remedy) return null;
  const identifier = remedy.target_version || remedy.patch_id;
  const claims = [
    ...(remedy.fix_support || []),
    ...(remedy.applicability_support || []),
    ...(remedy.compatibility_support || []),
  ];
  return (
    <article className={`remedy-card ${recommended ? "is-recommended" : ""}`}>
      <div className="remedy-card-heading">
        <div>
          <span>{recommended ? "Recommended remediation" : humanize(remedy.route)}</span>
          <h4>{identifier || humanize(remedy.route)}</h4>
        </div>
        <span className={`compatibility compatibility-${String(remedy.compatibility).toLowerCase()}`}>
          {humanize(remedy.compatibility)}
        </span>
      </div>
      <p>{remedy.summary}</p>
      <details>
        <summary>Supporting evidence ({claims.length})</summary>
        <ClaimList claims={claims} sources={sources} />
      </details>
    </article>
  );
}

function GuidanceList({ title, items, tone = "neutral" }) {
  if (!items?.length) return null;
  return (
    <section className={`guidance guidance-${tone}`}>
      <h4>{title}</h4>
      <ul>{items.map((item, index) => <li key={index}>{item}</li>)}</ul>
    </section>
  );
}

function RemediationResultCard({ result }) {
  const context = [
    ...(result.components || []),
    ...(result.applications || []),
    ...(result.operating_systems || []),
  ];
  return (
    <article className="remediation-result-card">
      <header className="result-card-header">
        <div>
          <div className="result-title-row">
            <h2>{result.cve}</h2>
            <span className={`verdict verdict-${String(result.verdict).toLowerCase()}`}>
              {humanize(result.verdict)}
            </span>
            {result.applicability && (
              <span className="applicability">{humanize(result.applicability)}</span>
            )}
            {result.context_missing && (
              <span className="context-missing">Full context unavailable</span>
            )}
          </div>
          <strong>{result.product}</strong>
          <div className="context-chips">
            {context.filter(Boolean).map((item, index) => <span key={`${item}-${index}`}>{item}</span>)}
          </div>
        </div>
      </header>

      {result.error ? (
        <section className="result-error"><AlertTriangle size={18} /><span>{result.error}</span></section>
      ) : (
        <>
          <section className="assessment-summary">
            <h3>Assessment</h3>
            <p>{result.assessment_summary || "No assessment summary was returned."}</p>
          </section>

          {result.recommended_remediation && (
            <RemedyCard remedy={result.recommended_remediation} sources={result.evidence_sources} recommended />
          )}

          {!!result.candidate_remediations?.length && (
            <section className="candidate-section">
              <h3>Conditional remediation options</h3>
              <p>Confirm compatibility and the missing inventory details before selecting one of these options.</p>
              <div className="remedy-grid">
                {result.candidate_remediations.map((remedy, index) => (
                  <RemedyCard key={index} remedy={remedy} sources={result.evidence_sources} />
                ))}
              </div>
            </section>
          )}

          <div className="guidance-grid">
            {result.context_missing && (
              <GuidanceList
                title="Context status"
                items={["No matching per-CVE context JSON was found. This item used partial CSV context, so a request for more inventory is expected."]}
                tone="warning"
              />
            )}
            <GuidanceList title="Blocked on" items={result.blocked_on} tone="warning" />
            <GuidanceList title="Information needed" items={result.missing_information} tone="info" />
            <GuidanceList title="Operational guidance" items={result.operational_notes} tone="success" />
            <GuidanceList title="Conflicts to review" items={result.conflicts} tone="danger" />
          </div>

          <details className="result-details">
            <summary>Evidence and assessment notes</summary>
            <GuidanceList title="Assessment notes" items={result.assessment_notes} />
            <ClaimList claims={result.supporting_claims} sources={result.evidence_sources} />
            {result.validation_note && <p className="validation-note"><Info size={14} /> {result.validation_note}</p>}
          </details>
        </>
      )}
    </article>
  );
}

function GroupedTable({ columns, rows, selected, setSelected }) {
  const [page, setPage] = useState(1);
  const pages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
  const safePage = Math.min(page, pages);
  const firstIndex = (safePage - 1) * PAGE_SIZE;
  const visibleRows = rows.slice(firstIndex, safePage * PAGE_SIZE);
  const allSelected = rows.length > 0 && selected.size === rows.length;

  function toggle(index) {
    setSelected((current) => {
      const next = new Set(current);
      if (next.has(index)) next.delete(index);
      else next.add(index);
      return next;
    });
  }

  function toggleAll() {
    setSelected(allSelected ? new Set() : new Set(rows.map((_, index) => index)));
  }

  return (
    <>
      <div className="table-shell grouped-table-shell">
        <table>
          <thead>
            <tr>
              <th className="select-column">
                <input
                  type="checkbox"
                  aria-label="Select all component groups"
                  checked={allSelected}
                  onChange={toggleAll}
                />
              </th>
              <th className="row-number">#</th>
              {columns.map((column) => <th key={column}>{column}</th>)}
            </tr>
          </thead>
          <tbody>
            {visibleRows.map((row, visibleIndex) => {
              const index = firstIndex + visibleIndex;
              return (
                <tr
                  key={`${row.Product}-${row.Component}-${index}`}
                  className={selected.has(index) ? "is-selected" : ""}
                  onClick={() => toggle(index)}
                >
                  <td className="select-column">
                    <input
                      type="checkbox"
                      aria-label={`Select ${row.Product || "unknown product"} ${row.Component || "unknown component"}`}
                      checked={selected.has(index)}
                      onClick={(event) => event.stopPropagation()}
                      onChange={() => toggle(index)}
                    />
                  </td>
                  <td className="row-number">{index + 1}</td>
                  {columns.map((column) => (
                    <td key={column} title={String(row[column] ?? "")}>
                      {String(row[column] ?? "") || <span className="empty">-</span>}
                    </td>
                  ))}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {rows.length > PAGE_SIZE && (
        <div className="pagination">
          <span>Rows {firstIndex + 1}-{Math.min(safePage * PAGE_SIZE, rows.length)} of {rows.length}</span>
          <div>
            <button className="button button-secondary button-small" disabled={safePage === 1} onClick={() => setPage(safePage - 1)}>Previous</button>
            <span className="page-count">{safePage} / {pages}</span>
            <button className="button button-secondary button-small" disabled={safePage === pages} onClick={() => setPage(safePage + 1)}>Next</button>
          </div>
        </div>
      )}
    </>
  );
}

function DataTable({ columns, rows, emptyMessage }) {
  const [page, setPage] = useState(1);
  const pages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
  const safePage = Math.min(page, pages);
  const visibleRows = rows.slice(
    (safePage - 1) * PAGE_SIZE,
    safePage * PAGE_SIZE,
  );

  return (
    <>
      <div className="table-shell">
        <table>
          <thead>
            <tr>
              <th className="row-number">#</th>
              {columns.map((column) => (
                <th key={column}>{column}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {visibleRows.length ? (
              visibleRows.map((row, index) => (
                <tr key={`${safePage}-${index}`}>
                  <td className="row-number">
                    {(safePage - 1) * PAGE_SIZE + index + 1}
                  </td>
                  {columns.map((column) => (
                    <td key={column} title={String(row[column] ?? "")}>
                      {String(row[column] ?? "") || <span className="empty">-</span>}
                    </td>
                  ))}
                </tr>
              ))
            ) : (
              <tr>
                <td className="table-empty" colSpan={columns.length + 1}>
                  {emptyMessage}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {rows.length > PAGE_SIZE && (
        <div className="pagination">
          <span>
            Rows {(safePage - 1) * PAGE_SIZE + 1}-
            {Math.min(safePage * PAGE_SIZE, rows.length)} of {rows.length}
          </span>
          <div>
            <button
              className="button button-secondary button-small"
              disabled={safePage === 1}
              onClick={() => setPage((value) => Math.max(1, value - 1))}
            >
              Previous
            </button>
            <span className="page-count">
              {safePage} / {pages}
            </span>
            <button
              className="button button-secondary button-small"
              disabled={safePage === pages}
              onClick={() => setPage((value) => Math.min(pages, value + 1))}
            >
              Next
            </button>
          </div>
        </div>
      )}
    </>
  );
}

function UploadPanel({ onUploaded, setError, uploading, setUploading }) {
  const inputRef = useRef(null);
  const [dragging, setDragging] = useState(false);

  async function upload(file) {
    if (!file) return;
    if (!file.name.toLowerCase().endsWith(".csv")) {
      setError("Choose a CSV file.");
      return;
    }

    setError("");
    setUploading(true);
    const body = new FormData();
    body.append("file", file);

    try {
      const response = await fetch("/api/upload", { method: "POST", body });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || "Upload failed.");
      onUploaded(result);
    } catch (error) {
      setError(error.message);
    } finally {
      setUploading(false);
    }
  }

  return (
    <section className="upload-card">
      <div className="upload-copy">
        <span className="eyebrow">Start a new assessment</span>
        <h1>Prepare a clean CVE dataset for enrichment.</h1>
        <p>
          Upload the scanner export. Duplicate CVEs are removed immediately while
          every original field remains available for review.
        </p>
        <div className="trust-row">
          <span><ShieldCheck size={17} /> CSV only</span>
          <span><Database size={17} /> 25 MB maximum</span>
        </div>
      </div>

      <div
        className={`drop-zone ${dragging ? "is-dragging" : ""}`}
        onDragEnter={(event) => {
          event.preventDefault();
          setDragging(true);
        }}
        onDragOver={(event) => event.preventDefault()}
        onDragLeave={() => setDragging(false)}
        onDrop={(event) => {
          event.preventDefault();
          setDragging(false);
          upload(event.dataTransfer.files[0]);
        }}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".csv,text/csv"
          hidden
          onChange={(event) => upload(event.target.files[0])}
        />
        {uploading ? (
          <>
            <LoaderCircle className="spin" size={30} />
            <strong>Reading and deduplicating...</strong>
            <span>The first unique record for each CVE is retained.</span>
          </>
        ) : (
          <>
            <div className="upload-icon"><UploadCloud size={27} /></div>
            <strong>Drop your CSV here</strong>
            <span>or select it from your computer</span>
            <button
              className="button button-primary"
              onClick={() => inputRef.current?.click()}
            >
              Choose CSV
              <ArrowRight size={17} />
            </button>
          </>
        )}
      </div>
    </section>
  );
}

export default function App() {
  const [dataset, setDataset] = useState(null);
  const [enriched, setEnriched] = useState(null);
  const [grouped, setGrouped] = useState(null);
  const [view, setView] = useState("workspace");
  const [reusePrompt, setReusePrompt] = useState(false);
  const [selectedGroups, setSelectedGroups] = useState(new Set());
  const [pipelineRun, setPipelineRun] = useState(null);
  const [remediationResults, setRemediationResults] = useState(null);
  const [loadingResults, setLoadingResults] = useState(false);
  const [activeTab, setActiveTab] = useState("deduplicated");
  const [start, setStart] = useState(1);
  const [count, setCount] = useState(10);
  const [uploading, setUploading] = useState(false);
  const [enriching, setEnriching] = useState(false);
  const [error, setError] = useState("");

  const available = dataset ? Math.max(1, dataset.unique_count - start + 1) : 1;
  const selectedEnd = dataset
    ? Math.min(dataset.unique_count, start + count - 1)
    : 0;

  const activeData = useMemo(() => {
    if (activeTab === "enriched" && enriched) return enriched;
    return dataset
      ? { columns: dataset.columns, rows: dataset.rows }
      : { columns: [], rows: [] };
  }, [activeTab, dataset, enriched]);

  useEffect(() => {
    if (!pipelineRun || !["queued", "running"].includes(pipelineRun.status)) return undefined;
    let finished = false;
    const events = new EventSource(`/api/pipeline-runs/${pipelineRun.run_id}/events`);
    events.onmessage = (event) => {
      try {
        const next = JSON.parse(event.data);
        setPipelineRun(next);
        if (["completed", "failed"].includes(next.status)) {
          finished = true;
          events.close();
        }
      } catch {
        setError("The pipeline returned an unreadable status update.");
      }
    };
    events.onerror = () => {
      events.close();
      if (!finished) setError("The live pipeline status connection closed unexpectedly.");
    };
    return () => events.close();
  }, [pipelineRun?.run_id]);

  useEffect(() => {
    if (["completed", "failed"].includes(pipelineRun?.status) &&
        view === "grouped" && !remediationResults) {
      showRemediationResults();
    }
  }, [pipelineRun?.status]);

  function reset() {
    setDataset(null);
    setEnriched(null);
    setGrouped(null);
    setView("workspace");
    setReusePrompt(false);
    setSelectedGroups(new Set());
    setPipelineRun(null);
    setRemediationResults(null);
    setLoadingResults(false);
    setActiveTab("deduplicated");
    setStart(1);
    setCount(10);
    setError("");
  }

  function setQuickCount(value) {
    setCount(Math.min(value === "all" ? available : value, available));
  }

  function finishGrouping(result) {
    setEnriched(result);
    setGrouped({
      ...result.grouped,
      source: result.source,
      source_filename: result.source_filename,
    });
    setSelectedGroups(new Set());
    setPipelineRun(null);
    setActiveTab("enriched");
    setView("grouped");
  }

  function requestPipelineRun() {
    if (dataset.existing_enrichment) setReusePrompt(true);
    else runEnrichment("fresh");
  }

  async function runEnrichment(mode) {
    setReusePrompt(false);
    setError("");
    setEnriching(true);
    const controller = new AbortController();
    // The evidence-backed classifier may retry unresolved CVEs individually.
    const timeout = window.setTimeout(
      () => controller.abort(),
      ENRICHMENT_TIMEOUT_MS,
    );
    try {
      const reuse = mode === "reuse";
      const response = await fetch(reuse ? "/api/enrich/reuse" : "/api/enrich", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(reuse
          ? { job_id: dataset.job_id, filename: dataset.existing_enrichment.filename }
          : { job_id: dataset.job_id, start, count }),
        signal: controller.signal,
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || "Enrichment failed.");
      finishGrouping(result);
    } catch (requestError) {
      setError(
        requestError.name === "AbortError"
          ? "Enrichment did not finish within 30 minutes. Try a smaller range."
          : requestError.message,
      );
    } finally {
      window.clearTimeout(timeout);
      setEnriching(false);
    }
  }

  async function runSelectedComponents() {
    if (!selectedGroups.size) return;
    setError("");
    try {
      const response = await fetch("/api/pipeline-runs", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          job_id: dataset.job_id,
          selected_indices: [...selectedGroups].sort((a, b) => a - b),
        }),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || "Could not start the selected components.");
      setPipelineRun(result);
      setRemediationResults(null);
    } catch (runError) {
      setError(runError.message);
    }
  }

  async function showRemediationResults() {
    if (!pipelineRun?.run_id) return;
    setLoadingResults(true);
    setError("");
    try {
      const response = await fetch(`/api/pipeline-runs/${pipelineRun.run_id}/results`);
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || "Could not load remediation results.");
      setRemediationResults(result);
      setView("results");
    } catch (resultError) {
      setError(resultError.message);
    } finally {
      setLoadingResults(false);
    }
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand-mark">AE</div>
        <div className="brand-copy">
          <strong>Aegis Enrichment</strong>
          <span>CVE component workspace</span>
        </div>
        {dataset && (
          <button className="button button-ghost" onClick={reset}>
            <RefreshCw size={16} /> New file
          </button>
        )}
      </header>

      <main>
        {!dataset ? (
          <UploadPanel
            uploading={uploading}
            setUploading={setUploading}
            setError={setError}
            onUploaded={(result) => {
              setDataset(result);
              setCount(Math.min(10, result.unique_count));
            }}
          />
        ) : view === "results" && remediationResults ? (
          <section className="results-workspace">
            <div className="results-heading">
              <div>
                <button className="back-link" onClick={() => setView("grouped")}>
                  <ChevronLeft size={17} /> Back to remediation selection
                </button>
                <span className="eyebrow">Remediation assessment complete</span>
                <h1>Remediation results</h1>
                <p>Review the engine’s evidence-backed reasoning before making any operational change.</p>
                {remediationResults.uses_test_context && (
                  <span className="test-context-badge">Test-context inventory</span>
                )}
              </div>
              <div className="run-identity">
                <span>Run ID</span>
                <code>{remediationResults.run_id}</code>
              </div>
            </div>

            <section className="results-summary">
              <div className="summary-icon"><CircleCheckBig size={24} /></div>
              <div className="summary-metric">
                <span>Assessments</span>
                <strong>{remediationResults.total}</strong>
              </div>
              <div className="summary-metric">
                <span>Fix available</span>
                <strong>{remediationResults.verdict_counts.FIX_AVAILABLE || 0}</strong>
              </div>
              <div className="summary-metric">
                <span>Needs input</span>
                <strong>{remediationResults.verdict_counts.NEEDS_INPUT || 0}</strong>
              </div>
              <div className="summary-metric">
                <span>Not applicable</span>
                <strong>{remediationResults.verdict_counts.NOT_APPLICABLE || 0}</strong>
              </div>
              <div className="summary-metric">
                <span>Other / failed</span>
                <strong>{remediationResults.total -
                  (remediationResults.verdict_counts.FIX_AVAILABLE || 0) -
                  (remediationResults.verdict_counts.NEEDS_INPUT || 0) -
                  (remediationResults.verdict_counts.NOT_APPLICABLE || 0)}</strong>
              </div>
            </section>

            <div className="results-list">
              {remediationResults.results.map((result) => (
                <RemediationResultCard key={`${result.product}-${result.cve}`} result={result} />
              ))}
            </div>
          </section>
        ) : view === "grouped" && grouped ? (
          <section className="grouped-workspace">
            <div className="grouped-heading">
              <div>
                <button className="back-link" onClick={() => setView("workspace")}>
                  <ChevronLeft size={17} /> Back to enrichment
                </button>
                <span className="eyebrow">Pipeline grouping complete</span>
                <h1>Grouped components</h1>
                <p>
                  Showing <strong>{grouped.filename}</strong> built from {grouped.source_filename}.
                  Select only the product/component groups you want the remediation pipeline to process.
                </p>
                {grouped.warning && <p className="file-warning">{grouped.warning}</p>}
              </div>
              <div className="grouped-heading-actions">
                {remediationResults && (
                  <button className="button button-primary" onClick={() => setView("results")}>
                    <Wrench size={16} /> View latest results
                  </button>
                )}
                <a className="button button-secondary" href={`/api/download/${dataset.job_id}/grouped`}>
                  <Download size={16} /> Download grouped CSV
                </a>
              </div>
            </div>

            <section className="selection-panel">
              <div className="selection-panel-copy">
                <div className="step-icon"><Layers3 size={19} /></div>
                <div>
                  <h2>Choose components to run</h2>
                  <p>{selectedGroups.size} of {grouped.rows.length} component groups selected.</p>
                </div>
              </div>
              <button
                className="button button-primary"
                disabled={!selectedGroups.size || ["queued", "running"].includes(pipelineRun?.status)}
                onClick={runSelectedComponents}
              >
                {["queued", "running"].includes(pipelineRun?.status) ? (
                  <><LoaderCircle className="spin" size={18} /> Running selected...</>
                ) : (
                  <><Play size={17} /> Run selected components</>
                )}
              </button>
            </section>

            {pipelineRun && (
              <section className={`run-status run-status-${pipelineRun.status}`} role="status">
                <div>
                  <span className="status-label">Pipeline {pipelineRun.status}</span>
                  <strong>{pipelineRun.run_id}</strong>
                  <p>
                    {pipelineRun.message || `${pipelineRun.selected_count} selected component groups are queued.`}
                  </p>
                </div>
                {pipelineRun.combined_output && (
                  <div className="output-path">
                    <span>Combined output</span>
                    <code>{pipelineRun.combined_output}</code>
                  </div>
                )}
                {["completed", "failed"].includes(pipelineRun.status) && (
                  <button className="button button-primary" disabled={loadingResults} onClick={showRemediationResults}>
                    {loadingResults ? <LoaderCircle className="spin" size={17} /> : <Wrench size={17} />}
                    {loadingResults ? "Loading results..." : "View remediation results"}
                  </button>
                )}
              </section>
            )}

            <section className="data-panel">
              <div className="table-heading">
                <div>
                  <h2>Product and component groups</h2>
                  <p>Every row comes from the current data/grouped_by_comp.csv output.</p>
                </div>
                <span className="record-count">{grouped.rows.length} groups</span>
              </div>
              <GroupedTable
                columns={grouped.columns}
                rows={grouped.rows}
                selected={selectedGroups}
                setSelected={setSelectedGroups}
              />
            </section>
          </section>
        ) : (
          <>
            <section className="workspace-heading">
              <div>
                <span className="eyebrow">Dataset ready</span>
                <h1>{dataset.filename}</h1>
              </div>
              <div className="metric-row">
                <div className="metric">
                  <span>Source rows</span>
                  <strong>{dataset.original_count}</strong>
                </div>
                <div className="metric">
                  <span>Unique CVEs</span>
                  <strong>{dataset.unique_count}</strong>
                </div>
                <div className="metric metric-muted">
                  <span>Duplicates removed</span>
                  <strong>{dataset.duplicate_count}</strong>
                </div>
              </div>
            </section>

            <section className="enrichment-panel">
              <div className="panel-heading">
                <div className="step-icon"><Play size={19} /></div>
                <div>
                  <h2>Select records to enrich</h2>
                  <p>Choose a starting row and the number of unique CVEs to process.</p>
                </div>
              </div>

              <div className="range-controls">
                <label>
                  Start row
                  <input
                    type="number"
                    min="1"
                    max={dataset.unique_count}
                    value={start}
                    onChange={(event) => {
                      const next = Math.min(
                        dataset.unique_count,
                        Math.max(1, Number(event.target.value) || 1),
                      );
                      setStart(next);
                      setCount((current) =>
                        Math.min(current, dataset.unique_count - next + 1),
                      );
                    }}
                  />
                </label>
                <label>
                  Row count
                  <input
                    type="number"
                    min="1"
                    max={available}
                    value={count}
                    onChange={(event) =>
                      setCount(
                        Math.min(available, Math.max(1, Number(event.target.value) || 1)),
                      )
                    }
                  />
                </label>
                <div className="quick-select" aria-label="Quick row count">
                  {[5, 10, 25].map((value) => (
                    <button
                      key={value}
                      className={available >= value && count === value ? "active" : ""}
                      onClick={() => setQuickCount(value)}
                    >
                      {value}
                    </button>
                  ))}
                  <button
                    className={count === available ? "active" : ""}
                    onClick={() => setQuickCount("all")}
                  >
                    All remaining
                  </button>
                </div>
                <div className="selection-summary">
                  <span>Selected range</span>
                  <strong>Rows {start}-{selectedEnd}</strong>
                </div>
                <button
                  className="button button-primary run-button"
                  disabled={enriching}
                  onClick={requestPipelineRun}
                >
                  {enriching ? (
                    <><LoaderCircle className="spin" size={18} /> Running...</>
                  ) : (
                    <><Play size={17} /> Run pipeline</>
                  )}
                </button>
              </div>

              {enriching && (
                <div className="progress-state" role="status">
                  <div className="progress-copy">
                    <LoaderCircle className="spin" size={20} />
                    <div>
                      <strong>Preparing grouped component data</strong>
                      <span>This view will update when every selected record is processed.</span>
                    </div>
                  </div>
                  <div className="progress-track"><span /></div>
                </div>
              )}
            </section>

            <section className="data-panel">
              <div className="data-toolbar">
                <div className="tabs" role="tablist">
                  <button
                    role="tab"
                    aria-selected={activeTab === "deduplicated"}
                    className={activeTab === "deduplicated" ? "active" : ""}
                    onClick={() => setActiveTab("deduplicated")}
                  >
                    <Database size={16} /> Deduplicated
                    <span>{dataset.unique_count}</span>
                  </button>
                  <button
                    role="tab"
                    aria-selected={activeTab === "enriched"}
                    className={activeTab === "enriched" ? "active" : ""}
                    disabled={!enriched}
                    onClick={() => enriched && setActiveTab("enriched")}
                  >
                    {enriched ? <Check size={16} /> : <FileSpreadsheet size={16} />}
                    Enriched
                    {enriched && <span>{enriched.rows.length}</span>}
                  </button>
                </div>

                <a
                  className="button button-secondary"
                  href={`/api/download/${dataset.job_id}/${activeTab}`}
                  aria-disabled={activeTab === "enriched" && !enriched}
                >
                  <Download size={16} /> Download CSV
                </a>
              </div>

              <div className="table-heading">
                <div>
                  <h2>
                    {activeTab === "deduplicated"
                      ? "Unique CVE records"
                      : "Enriched component map"}
                  </h2>
                  <p>
                    {activeTab === "deduplicated"
                      ? "Original dataset fields are retained without component enrichment."
                      : enriched?.source === "saved_enrichment"
                        ? `Loaded from ${enriched.source_filename}.`
                        : `Generated from source rows ${enriched?.start}-${
                            enriched ? enriched.start + enriched.count - 1 : ""
                          }.`}
                  </p>
                </div>
                <span className="record-count">{activeData.rows.length} records</span>
              </div>

              <DataTable
                key={activeTab}
                columns={activeData.columns}
                rows={activeData.rows}
                emptyMessage="No records are available."
              />
            </section>
          </>
        )}

        {reusePrompt && dataset?.existing_enrichment && (
          <div className="modal-backdrop" role="presentation">
            <section className="modal-card" role="dialog" aria-modal="true" aria-labelledby="reuse-title">
              <div className="modal-icon"><FileSpreadsheet size={24} /></div>
              <span className="eyebrow">Saved enrichment found</span>
              <h2 id="reuse-title">Use the previous enrichment data?</h2>
              <p>
                <strong>{dataset.existing_enrichment.filename}</strong> contains {dataset.existing_enrichment.row_count} enriched rows
                and was saved {new Date(dataset.existing_enrichment.modified_at).toLocaleString()}.
              </p>
              <p>You can group that file immediately or run a new enrichment for rows {start}-{selectedEnd}.</p>
              <div className="modal-actions">
                <button className="button button-ghost" onClick={() => setReusePrompt(false)}>Cancel</button>
                <button className="button button-secondary" onClick={() => runEnrichment("fresh")}>Run new enrichment</button>
                <button className="button button-primary" onClick={() => runEnrichment("reuse")}>
                  <Database size={16} /> Use previous data
                </button>
              </div>
            </section>
          </div>
        )}

        {error && (
          <div className="error-banner" role="alert">
            <strong>Unable to continue</strong>
            <span>{error}</span>
            <button onClick={() => setError("")}>Dismiss</button>
          </div>
        )}
      </main>
    </div>
  );
}
