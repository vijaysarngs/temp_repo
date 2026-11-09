import { useEffect, useMemo, useRef, useState } from "react";
import {
  AlertTriangle,
  Check,
  ChevronDown,
  ChevronRight,
  Download,
  FileSpreadsheet,
  LoaderCircle,
  Search,
  Server,
  Sparkles,
  UploadCloud,
} from "lucide-react";

// Context gatherer: every server of the enriched CVE file in the CVE workspace (no separate
// upload), with its CVEs grouped by product. For each server, generate the collection script (context script agent) or download the
// standard one, run it there by hand, and upload what it printed. The upload is stored as that
// server's host context, so it applies to every component on it.

function plural(count, word) {
  return `${count} ${word}${count === 1 ? "" : "s"}`;
}

function shortDate(value) {
  if (!value) return "";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
}

// What the agent put in the downloaded script: probes per component and the token use.
function GeneratedSummary({ data }) {
  const uncovered = data.coverage.filter((item) => !item.probes.length);
  const tokens = data.tokenomics || {};
  return (
    <div className="cg-generated">
      <p>
        <Check size={13} /> Downloaded {data.filename}: {plural(data.probes, "probe")} for{" "}
        {plural(data.coverage.length, "product")}
        {data.fallback_probes ? ` (${data.fallback_probes} fallback)` : ""}
        {data.rejected ? `, ${data.rejected} rejected by validation` : ""}.
        {" "}Tokens: {tokens.input_tokens ?? 0} in / {tokens.output_tokens ?? 0} out
        {tokens.estimated_cost_usd !== undefined ? ` (~$${tokens.estimated_cost_usd})` : ""}.
      </p>
      {data.error && <p className="cg-error"><AlertTriangle size={13} /> Model plan failed ({data.error}); the script uses fallback probes.</p>}
      <details>
        <summary>Probes per product</summary>
        <ul>
          {data.coverage.map((item) => (
            <li key={`${item.product}-${item.component}`}>
              <strong>{item.product}{item.component ? ` / ${item.component}` : ""}</strong>:{" "}
              {item.probes.length ? item.probes.join(", ") : item.not_probeable
                ? `not probeable: ${item.not_probeable}` : "no probe"}
            </li>
          ))}
        </ul>
      </details>
      {!!uncovered.length && <p className="cg-muted">{plural(uncovered.length, "product")} without a probe.</p>}
    </div>
  );
}

function ServerRow({ entry, jobId, open, onToggle, onUploaded, generated, onGenerated }) {
  const input = useRef(null);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState("");
  const [generating, setGenerating] = useState(false);
  // Products the generated script probes (all by default); the standard script is unchanged.
  const [picked, setPicked] = useState(() => new Set(entry.components.map((_, index) => index)));
  const chosen = entry.components.filter((_, index) => picked.has(index));
  const result = entry.upload;

  function togglePick(index) {
    setPicked((current) => {
      const next = new Set(current);
      if (next.has(index)) next.delete(index); else next.add(index);
      return next;
    });
  }

  // The context script agent builds probes for this server's vulnerable components.
  async function generateScript() {
    if (!chosen.length) {
      setFailure("Select at least one product to generate the script for.");
      return;
    }
    setGenerating(true);
    setFailure("");
    try {
      const response = await fetch("/api/context-gatherer/script", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ server: entry.server, components: chosen,
          applications: entry.applications, os: entry.os_hint || entry.os || "" }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "The script could not be generated.");
      const link = document.createElement("a");
      link.href = URL.createObjectURL(new Blob([data.script], { type: "text/x-shellscript" }));
      link.download = data.filename;
      link.click();
      URL.revokeObjectURL(link.href);
      onGenerated(entry.server, data);
    } catch (error) {
      setFailure(error.message);
    } finally {
      setGenerating(false);
    }
  }

  async function upload(file) {
    if (!file) return;
    setBusy(true);
    setFailure("");
    const body = new FormData();
    body.append("file", file);
    body.append("server", entry.server);
    body.append("job_id", jobId || "");
    body.append("applications", entry.applications.join(" | "));
    body.append("components", JSON.stringify(entry.components));
    try {
      const response = await fetch("/api/context-upload", { method: "POST", body });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Upload failed.");
      onUploaded(entry.server, data);
    } catch (error) {
      setFailure(error.message);
    } finally {
      setBusy(false);
      if (input.current) input.current.value = "";
    }
  }

  const covered = entry.covered || result;
  const appliedCount = result?.applied?.filter((item) => item.found.length).length;
  return (
    <article className={`cg-server ${open ? "is-open" : ""}`}>
      <div className="cg-server-head">
        <button type="button" className="cg-server-toggle" onClick={onToggle} aria-expanded={open}>
          {open ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
          <Server size={16} />
          <span className="cg-server-name">{entry.server}</span>
        </button>
        <span className="cg-server-meta">
          {plural(entry.components.length, "product")} · {plural(entry.cves.length, "CVE")}
          {entry.applications.length ? ` · ${entry.applications.join(", ")}` : ""}
        </span>
        <span className={`cg-status ${covered ? "is-covered" : "is-missing"}`}>
          {result ? "Context uploaded" : entry.covered ? "Context on file" : "No context"}
        </span>
        <div className="cg-server-actions">
          <button type="button" className="button button-secondary button-small" disabled={generating || !chosen.length}
            onClick={generateScript} title="Script with probes for the selected products (open the server to choose)">
            {generating ? <LoaderCircle className="spin" size={14} /> : <Sparkles size={14} />}
            {generating ? "Generating…" : chosen.length === entry.components.length
              ? "Generate script" : `Generate script (${chosen.length} of ${entry.components.length})`}
          </button>
          <a className="cg-standard-link"
            href={`/api/context-script?server=${encodeURIComponent(entry.server)}&os=${encodeURIComponent(entry.os_hint || entry.os || "")}`}
            title="The standard allowlist script, without component probes">
            <Download size={13} /> Standard
          </a>
          <button type="button" className="button button-primary button-small" disabled={busy}
            onClick={() => input.current?.click()}>
            {busy ? <LoaderCircle className="spin" size={14} /> : <UploadCloud size={14} />}
            {busy ? "Converting…" : "Upload context"}
          </button>
          <input ref={input} type="file" accept=".txt,text/plain" hidden
            onChange={(event) => upload(event.target.files[0])} />
        </div>
      </div>
      {failure && <p className="cg-error"><AlertTriangle size={13} /> {failure}</p>}
      {generated && <GeneratedSummary data={generated} />}
      {result && (
        <p className="cg-ok">
          <Check size={13} /> Stored {result.hostname}{result.os ? ` (${result.os})` : ""}: {result.components} components
          {appliedCount !== undefined ? `; covers ${appliedCount} of ${entry.components.length} remediated products` : ""}.
          {" "}{result.database?.message}
          {result.warnings?.map((warning) => <span key={warning}> {warning}</span>)}
        </p>
      )}
      {open && (
        <div className="cg-server-body">
          <p className="cg-source">
            {result ? `Uploaded just now; applies to every product below on ${entry.server}.`
              : entry.covered ? `Context on file${entry.os ? ` (${entry.os})` : ""}${entry.collected_at
                ? `, collected ${shortDate(entry.collected_at)}` : ""}: ${plural(entry.context_components, "component")}. Uploading again replaces it.`
                : `No context yet. Download the script, run it on the server as a normal user `
                  + `(${entry.script?.run || "see the comment at the top of the script"}), then upload the .txt it wrote.`}
          </p>
          <p className="cg-muted">
            Tick the products the generated script should probe ({chosen.length} of {entry.components.length} selected).
            The standard script and the upload are not affected.
          </p>
          <table className="cg-table">
            <thead>
              <tr>
                <th className="cg-pick">
                  <input type="checkbox" aria-label="Select every product for the script"
                    checked={chosen.length === entry.components.length}
                    ref={(box) => { if (box) box.indeterminate = chosen.length > 0 && chosen.length < entry.components.length; }}
                    onChange={(event) => setPicked(event.target.checked
                      ? new Set(entry.components.map((_, index) => index)) : new Set())} />
                </th>
                <th>Product</th><th>Components</th><th>CVEs</th><th>In the uploaded context</th>
              </tr>
            </thead>
            <tbody>
              {entry.components.map((component, index) => {
                const applied = result?.applied?.find((item) => item.product === component.product);
                return (
                  <tr key={`${component.product}-${index}`} className={picked.has(index) ? "" : "is-unpicked"}>
                    <td className="cg-pick">
                      <input type="checkbox" checked={picked.has(index)} onChange={() => togglePick(index)}
                        aria-label={`Probe ${component.product} in the generated script`} />
                    </td>
                    <td>{component.product}{component.remediated && <span className="cg-remediated">remediated</span>}</td>
                    <td>{component.names.length ? component.names.join(", ") : <span className="cg-muted">not named</span>}</td>
                    <td className="cg-cves">{component.cves.slice(0, 6).join(", ")}
                      {component.cves.length > 6 ? ` +${component.cves.length - 6}` : ""}</td>
                    <td>
                      {!result ? <span className="cg-muted">{entry.covered ? "on file" : "waiting for upload"}</span>
                        : applied?.found.length ? applied.found.map((found) => (
                          <div key={`${found.name}-${found.path}`} className="cg-found">
                            <Check size={12} /> {found.name} {found.installed_version || "version unknown"}
                            {found.owner ? ` · ${found.owner.replaceAll("_", " ")}` : ""}
                            {found.path ? <small>{found.path}</small> : null}
                          </div>
                        )) : <span className="cg-muted">not in the output (the card will ask for it)</span>}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </article>
  );
}

// Short server key: "web01.corp (10.0.0.1)" and "WEB01" are the same server.
function serverKey(name) {
  return String(name || "").replace(/\s*\(.*\)\s*$/, "").split(".")[0].trim().toLowerCase();
}

// Products that have a remediation result on a server (server key -> set of product names).
function remediatedProducts(results) {
  const found = new Map();
  for (const result of results || []) {
    for (const name of [result.host, ...(result.other_hosts || [])].filter(Boolean)) {
      const key = serverKey(name);
      if (!found.has(key)) found.set(key, new Set());
      found.get(key).add(String(result.product || "").toLowerCase());
    }
  }
  return found;
}

export function ContextGathererView({ results, jobId, sourceName, enrichedKey, onOpenWorkspace }) {
  const [coverage, setCoverage] = useState(null);
  const [failure, setFailure] = useState("");
  const [uploads, setUploads] = useState({});
  // Generated-script summaries per server, kept while rows are filtered out of view.
  const [generatedScripts, setGeneratedScripts] = useState({});
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState("all");
  const [open, setOpen] = useState(() => new Set());

  // Every server of the enriched file with all its CVEs grouped by product, and whether its
  // context is on file (GET /api/jobs/<job>/server-coverage). Reloaded when the file changes.
  useEffect(() => {
    if (!jobId) return undefined;
    let live = true;
    setCoverage(null);
    fetch(`/api/jobs/${encodeURIComponent(jobId)}/server-coverage`)
      .then(async (response) => {
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || "The servers could not be loaded.");
        if (live) setCoverage(data.servers || []);
      })
      .catch((error) => live && setFailure(error.message));
    return () => { live = false; };
  }, [jobId, enrichedKey]);

  const remediated = useMemo(() => remediatedProducts(results?.results), [results]);
  const servers = useMemo(() => (coverage || []).map((entry) => {
    const done = remediated.get(serverKey(entry.server)) || new Set();
    const components = (entry.products || []).map((item) => ({
      ...item, component: item.names.join(", ").slice(0, 120), remediated: done.has(item.product.toLowerCase()),
    })).sort((a, b) => Number(b.remediated) - Number(a.remediated) || b.cves.length - a.cves.length);
    return { ...entry, components, os_hint: entry.os || "", upload: uploads[serverKey(entry.server)] };
  }).sort((a, b) => Number(Boolean(a.covered || a.upload)) - Number(Boolean(b.covered || b.upload))
    || b.cves.length - a.cves.length || a.server.localeCompare(b.server)), [coverage, remediated, uploads]);

  function uploaded(server, result) {
    setUploads((current) => ({ ...current, [serverKey(server)]: result }));
    setOpen((current) => new Set(current).add(server));
  }

  const shown = useMemo(() => {
    const text = query.trim().toLowerCase();
    return servers.filter((entry) => {
      const covered = entry.covered || entry.upload;
      if (filter === "missing" && covered) return false;
      if (filter === "covered" && !covered) return false;
      if (!text) return true;
      return entry.server.toLowerCase().includes(text)
        || entry.components.some((c) => `${c.product} ${c.names.join(" ")}`.toLowerCase().includes(text))
        || entry.cves.some((cve) => cve.toLowerCase().includes(text));
    });
  }, [servers, query, filter]);
  const coveredCount = servers.filter((entry) => entry.covered || entry.upload).length;
  const productCount = new Set(servers.flatMap((entry) => entry.components.map((c) => c.product.toLowerCase()))).size;

  return (
    <section className="cg-page">
      <div className="results-heading">
        <div>
          <span className="eyebrow">Server context</span>
          <h1>Context gatherer</h1>
          <p>Every server in the enriched CVE file, with its CVEs grouped by product. For each server, generate
            the read-only script, run it there by hand, and upload the output. It is stored as that server's
            context and used for every product on it.</p>
        </div>
      </div>

      <div className="cg-script-note">
        <Sparkles size={15} />
        <span><strong>Generate script</strong> builds a script for that server's vulnerable products: the standard
          read-only commands plus checks the agent picks from a fixed read-only catalogue (validated before use).
          <strong> Standard</strong> downloads the fixed script only.</span>
      </div>

      {failure && <p className="cg-error"><AlertTriangle size={14} /> {failure}</p>}

      {!jobId || !enrichedKey ? (
        <div className="cg-empty">
          <FileSpreadsheet size={28} />
          <strong>No enriched CVE file yet</strong>
          <p>Upload the CVE file in the CVE workspace and enrich it. Its servers and their products appear here;
            remediation is not needed first.</p>
          {onOpenWorkspace && (
            <button type="button" className="button button-primary" onClick={onOpenWorkspace}>Open CVE workspace</button>
          )}
        </div>
      ) : (
        <>
          <div className="metric-grid cg-metrics">
            <div className="metric"><span>File</span><strong title={sourceName}>{sourceName || "current upload"}</strong></div>
            <div className="metric"><span>Products</span><strong>{productCount}</strong></div>
            <div className="metric"><span>Servers</span><strong>{servers.length}</strong></div>
            <div className="metric"><span>With context</span><strong>{coveredCount}</strong></div>
            <div className="metric"><span>Missing context</span><strong>{servers.length - coveredCount}</strong></div>
          </div>
          {coverage === null && !failure && <p className="cg-muted"><LoaderCircle className="spin" size={13} /> Loading servers…</p>}
          {coverage !== null && !servers.length && (
            <p className="cg-muted">The enriched file names no server (it has no Hostname or Hosts column).</p>
          )}
          <div className="cg-toolbar">
            <label className="cg-search">
              <Search size={15} />
              <input value={query} onChange={(event) => setQuery(event.target.value)}
                placeholder="Search server, product or CVE" />
            </label>
            <div className="cg-filters" role="group" aria-label="Filter servers">
              {[["all", "All"], ["missing", "Missing context"], ["covered", "With context"]].map(([key, label]) => (
                <button key={key} type="button" className={filter === key ? "is-active" : ""}
                  onClick={() => setFilter(key)}>{label}</button>
              ))}
            </div>
            <span className="cg-count">{plural(shown.length, "server")}</span>
          </div>
          <div className="cg-servers">
            {shown.slice(0, 300).map((entry) => (
              <ServerRow key={entry.server} entry={entry} jobId={jobId} open={open.has(entry.server)} onUploaded={uploaded}
                generated={generatedScripts[serverKey(entry.server)]}
                onGenerated={(server, data) => setGeneratedScripts((current) => ({ ...current, [serverKey(server)]: data }))}
                onToggle={() => setOpen((current) => {
                  const next = new Set(current);
                  if (next.has(entry.server)) next.delete(entry.server); else next.add(entry.server);
                  return next;
                })} />
            ))}
            {shown.length > 300 && <p className="cg-muted">Showing the first 300; search to narrow the list.</p>}
          </div>
        </>
      )}
    </section>
  );
}
