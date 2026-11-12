import { useEffect, useMemo, useRef, useState } from "react";
import {
  AlertTriangle,
  Check,
  ChevronDown,
  ChevronRight,
  FileSpreadsheet,
  LayoutGrid,
  LoaderCircle,
  Monitor,
  Search,
  Sparkles,
  UploadCloud,
} from "lucide-react";

// What the agent put in the generated script: probes per product, so it's visible that this
// is a focused script for the ticked products, not the same thing every time.
function GeneratedSummary({ data }) {
  const uncovered = data.coverage.filter((item) => !item.probes.length);
  return (
    <div className="cg-generated">
      <p>
        <Check size={13} /> Downloaded {data.filename}: {plural(data.probes, "probe")} for{" "}
        {plural(data.coverage.length, "product")}
        {data.fallback_probes ? ` (${data.fallback_probes} fallback)` : ""}
        {data.rejected ? `, ${data.rejected} rejected by validation` : ""}.
      </p>
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

// Context gatherer, by Application+OS: every (application, operating system) pair of the
// enriched CVE file, with its CVEs grouped by product. One context is gathered and uploaded
// per pair -- run on any representative server for that application and OS, not one
// specific host -- and applies to every server the scanner found on that application and OS
// (host_inventory.py scope: application). Replaces the earlier per-server context gatherer:
// context is primary-application-wise now, never server-wise.

function plural(count, word, many = `${word}s`) {
  return `${count} ${count === 1 ? word : many}`;
}

function shortDate(value) {
  if (!value) return "";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
}

function groupKey(application, os) {
  return `${String(application || "").toLowerCase()}::${String(os || "").toLowerCase()}`;
}

function GroupRow({ entry, open, onToggle, onUploaded, generated, onGenerated }) {
  const input = useRef(null);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState("");
  const [generating, setGenerating] = useState(false);
  const [picked, setPicked] = useState(() => new Set(entry.products.map((_, index) => index)));
  const chosen = entry.products.filter((_, index) => picked.has(index));
  const result = entry.upload;

  function togglePick(index) {
    setPicked((current) => {
      const next = new Set(current);
      if (next.has(index)) next.delete(index); else next.add(index);
      return next;
    });
  }

  // The agent builds a focused script for exactly the ticked products (script_agent, no
  // model call) and reports back what it probed, so it's visible this isn't the same file
  // every time.
  async function generateScript() {
    if (!chosen.length) {
      setFailure("Select at least one product to generate the script for.");
      return;
    }
    setGenerating(true);
    setFailure("");
    try {
      const response = await fetch("/api/application-context-gatherer/script", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          application: entry.application, os: entry.os,
          components: chosen.map((p) => ({ product: p.product, component: p.names.join(", "), cves: p.cves })),
        }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "The script could not be generated.");
      const link = document.createElement("a");
      link.href = URL.createObjectURL(new Blob([data.script], { type: "text/x-shellscript" }));
      link.download = data.filename;
      link.click();
      URL.revokeObjectURL(link.href);
      onGenerated(data);
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
    body.append("application", entry.application);
    body.append("os", entry.os);
    try {
      const response = await fetch("/api/application-context-upload", { method: "POST", body });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Upload failed.");
      onUploaded(entry.application, entry.os, data);
    } catch (error) {
      setFailure(error.message);
    } finally {
      setBusy(false);
      if (input.current) input.current.value = "";
    }
  }

  const covered = entry.covered || result;
  return (
    <article className={`cg-server ${open ? "is-open" : ""}`}>
      <div className="cg-server-head">
        <button type="button" className="cg-server-toggle" onClick={onToggle} aria-expanded={open}>
          {open ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
          <Monitor size={15} />
          <span className="cg-server-name">{entry.os}</span>
        </button>
        <span className="cg-server-meta">
          {plural(entry.products.length, "product")} · {plural(entry.cves.length, "CVE")}
          {entry.servers.length ? ` · ${plural(entry.servers.length, "server")}` : ""}
        </span>
        <span className={`cg-status ${covered ? "is-covered" : "is-missing"}`}>
          {result ? "Context uploaded" : entry.covered ? "Context on file" : "No context"}
        </span>
        <div className="cg-server-actions">
          <button type="button" className="button button-secondary button-small" disabled={generating || !chosen.length}
            onClick={generateScript} title="Builds a script with probes for exactly the ticked products below">
            {generating ? <LoaderCircle className="spin" size={14} /> : <Sparkles size={14} />}
            {generating ? "Generating…" : chosen.length === entry.products.length
              ? "Generate script" : `Generate script (${chosen.length} of ${entry.products.length})`}
          </button>
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
          <Check size={13} /> Stored {result.application} on {result.os}: {result.components} components
          {result.measured_os && result.measured_os !== result.os ? ` (script measured ${result.measured_os})` : ""}.
          {result.warnings?.map((warning) => <span key={warning}> {warning}</span>)}
        </p>
      )}
      {open && (
        <div className="cg-server-body">
          <p className="cg-source">
            {result ? `Uploaded just now; applies to every server on ${entry.application} / ${entry.os} below.`
              : entry.covered ? `Context on file${entry.measured_os ? ` (script measured ${entry.measured_os})` : ""}`
                + `${entry.collected_at ? `, collected ${shortDate(entry.collected_at)}` : ""}: `
                + `${plural(entry.context_components, "component")}. Uploading again replaces it.`
                : `No context yet. Generate the script, run it on any one representative server for `
                  + `${entry.application} on ${entry.os} as a normal user, then upload the .txt it wrote.`}
          </p>
          <p className="cg-muted">
            Tick the products the script should probe ({chosen.length} of {entry.products.length} selected).
          </p>
          <table className="cg-table">
            <thead>
              <tr>
                <th className="cg-pick">
                  <input type="checkbox" aria-label="Select every product for the script"
                    checked={chosen.length === entry.products.length}
                    ref={(box) => { if (box) box.indeterminate = chosen.length > 0 && chosen.length < entry.products.length; }}
                    onChange={(event) => setPicked(event.target.checked
                      ? new Set(entry.products.map((_, index) => index)) : new Set())} />
                </th>
                <th>Product</th><th>Components</th><th>CVEs</th><th>In the uploaded context</th>
              </tr>
            </thead>
            <tbody>
              {entry.products.map((product, index) => (
                <tr key={`${product.product}-${index}`}
                  className={`${picked.has(index) ? "" : "is-unpicked"} ${
                    entry.covered ? (product.in_context ? "cg-row-covered" : "cg-row-missing") : ""}`}>
                  <td className="cg-pick">
                    <input type="checkbox" checked={picked.has(index)} onChange={() => togglePick(index)}
                      aria-label={`Probe ${product.product} in the generated script`} />
                  </td>
                  <td>{product.product}</td>
                  <td>{product.names.length ? product.names.join(", ") : <span className="cg-muted">not named</span>}</td>
                  <td className="cg-cves">{product.cves.slice(0, 6).join(", ")}
                    {product.cves.length > 6 ? ` +${product.cves.length - 6}` : ""}</td>
                  <td>
                    {!entry.covered ? <span className="cg-muted">no context uploaded yet</span>
                      : product.in_context ? (
                        <div className="cg-found">
                          <Check size={12} /> {product.context_version || "found, version not captured"}
                        </div>
                      ) : <span className="cg-muted">not in the uploaded context</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {!!entry.servers.length && <p className="cg-muted">Servers in this group: {entry.servers.join(", ")}</p>}
        </div>
      )}
    </article>
  );
}

// One middleware (the scanner's Application): its operating systems, each with its products.
function MiddlewareGroup({ name, entries, open, onToggle, children }) {
  const products = new Set(entries.flatMap((entry) => entry.products.map((p) => p.product.toLowerCase()))).size;
  const cves = new Set(entries.flatMap((entry) => entry.cves)).size;
  const covered = entries.filter((entry) => entry.covered || entry.upload).length;
  return (
    <section className={`cg-middleware ${open ? "is-open" : ""}`}>
      <button type="button" className="cg-middleware-head" onClick={onToggle} aria-expanded={open}>
        {open ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
        <LayoutGrid size={16} />
        <span className="cg-middleware-name">{name}</span>
        <span className="cg-server-meta">
          {plural(entries.length, "operating system")} · {plural(products, "product")} · {plural(cves, "CVE")}
        </span>
        <span className={`cg-status ${covered === entries.length ? "is-covered" : "is-missing"}`}>
          Context {covered} of {entries.length}
        </span>
      </button>
      {open && <div className="cg-middleware-body">{children}</div>}
    </section>
  );
}

export function ApplicationGathererView({ jobId, sourceName, enrichedKey, onOpenWorkspace }) {
  const [coverage, setCoverage] = useState(null);
  const [failure, setFailure] = useState("");
  const [uploads, setUploads] = useState({});
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState("all");
  const [open, setOpen] = useState(() => new Set());
  const [openMiddleware, setOpenMiddleware] = useState(() => new Set());
  // Bumped after a successful upload, so the per-product "in context" highlighting reflects
  // what was just saved, read back from the file itself rather than guessed from the upload.
  const [refresh, setRefresh] = useState(0);
  // Generated-script summaries per group, kept while rows are filtered out of view.
  const [generatedScripts, setGeneratedScripts] = useState({});

  // Every Application+OS group of the enriched file (GET /api/jobs/<job>/application-coverage).
  // Reloaded whole (with a loading state) when the file changes, and quietly refreshed after
  // an upload (refresh) so "in context" reflects what was just saved, without a flash.
  useEffect(() => { setCoverage(null); }, [jobId, enrichedKey]);
  useEffect(() => {
    if (!jobId) return undefined;
    let live = true;
    fetch(`/api/jobs/${encodeURIComponent(jobId)}/application-coverage`)
      .then(async (response) => {
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || "The applications could not be loaded.");
        if (live) setCoverage(data.groups || []);
      })
      .catch((error) => live && setFailure(error.message));
    return () => { live = false; };
  }, [jobId, enrichedKey, refresh]);

  const groups = useMemo(() => (coverage || []).map((entry) => {
    const key = groupKey(entry.application, entry.os);
    return { ...entry, jobId, cves: [...new Set(entry.products.flatMap((p) => p.cves))],
      upload: uploads[key] };
  }).sort((a, b) => Number(Boolean(a.covered || a.upload)) - Number(Boolean(b.covered || b.upload))
    || b.cves.length - a.cves.length || a.application.localeCompare(b.application)), [coverage, jobId, uploads]);

  function uploaded(application, os, result) {
    setUploads((current) => ({ ...current, [groupKey(application, os)]: result }));
    setOpen((current) => new Set(current).add(groupKey(application, os)));
    setRefresh((current) => current + 1);
  }

  const shown = useMemo(() => {
    const text = query.trim().toLowerCase();
    return groups.filter((entry) => {
      const covered = entry.covered || entry.upload;
      if (filter === "missing" && covered) return false;
      if (filter === "covered" && !covered) return false;
      if (!text) return true;
      return entry.application.toLowerCase().includes(text) || entry.os.toLowerCase().includes(text)
        || entry.products.some((p) => `${p.product} ${p.names.join(" ")}`.toLowerCase().includes(text))
        || entry.cves.some((cve) => cve.toLowerCase().includes(text));
    });
  }, [groups, query, filter]);
  // Middleware -> its operating systems (sorted by name) -> products.
  const middleware = useMemo(() => {
    const byName = new Map();
    for (const entry of shown) {
      const name = entry.application;
      if (!byName.has(name.toLowerCase())) byName.set(name.toLowerCase(), { name, entries: [] });
      byName.get(name.toLowerCase()).entries.push(entry);
    }
    return [...byName.values()]
      .map((item) => ({ ...item, entries: item.entries.sort((a, b) => a.os.localeCompare(b.os)) }))
      .sort((a, b) => a.name.localeCompare(b.name));
  }, [shown]);
  const coveredCount = groups.filter((entry) => entry.covered || entry.upload).length;
  const productCount = new Set(groups.flatMap((entry) => entry.products.map((p) => p.product.toLowerCase()))).size;

  return (
    <section className="cg-page">
      <div className="results-heading">
        <div>
          <span className="eyebrow">Application context</span>
          <h1>Context gatherer</h1>
          <p>Every application and operating system pair in the enriched CVE file, with its CVEs grouped by
            product. One context is gathered per pair, on any representative server for it, and applies to
            every server the scanner found on that application and OS -- not one server at a time.</p>
        </div>
      </div>

      <div className="cg-script-note">
        <Sparkles size={15} />
        <span><strong>Generate script</strong> builds a script for exactly the ticked products (no model
          call): the standard read-only commands plus a fixed, validated probe per product, and shows what
          it probed once it's done. Run it on any one server for this application and OS, then upload what it printed.</span>
      </div>

      {failure && <p className="cg-error"><AlertTriangle size={14} /> {failure}</p>}

      {!jobId || !enrichedKey ? (
        <div className="cg-empty">
          <FileSpreadsheet size={28} />
          <strong>No enriched CVE file yet</strong>
          <p>Upload the CVE file in the CVE workspace and enrich it. Its applications and their products
            appear here; remediation is not needed first.</p>
          {onOpenWorkspace && (
            <button type="button" className="button button-primary" onClick={onOpenWorkspace}>Open CVE workspace</button>
          )}
        </div>
      ) : (
        <>
          <div className="metric-grid cg-metrics">
            <div className="metric"><span>File</span><strong title={sourceName}>{sourceName || "current upload"}</strong></div>
            <div className="metric"><span>Products</span><strong>{productCount}</strong></div>
            <div className="metric"><span>Middleware</span><strong>{new Set(groups.map((g) => g.application.toLowerCase())).size}</strong></div>
            <div className="metric"><span>Middleware + OS</span><strong>{groups.length}</strong></div>
            <div className="metric"><span>With context</span><strong>{coveredCount}</strong></div>
            <div className="metric"><span>Missing context</span><strong>{groups.length - coveredCount}</strong></div>
          </div>
          {coverage === null && !failure && <p className="cg-muted"><LoaderCircle className="spin" size={13} /> Loading applications…</p>}
          {coverage !== null && !groups.length && (
            <p className="cg-muted">No row has both an Application and a single, unambiguous Operating System
              value across all its servers.</p>
          )}
          <div className="cg-toolbar">
            <label className="cg-search">
              <Search size={15} />
              <input value={query} onChange={(event) => setQuery(event.target.value)}
                placeholder="Search application, OS, product or CVE" />
            </label>
            <div className="cg-filters" role="group" aria-label="Filter applications">
              {[["all", "All"], ["missing", "Missing context"], ["covered", "With context"]].map(([key, label]) => (
                <button key={key} type="button" className={filter === key ? "is-active" : ""}
                  onClick={() => setFilter(key)}>{label}</button>
              ))}
            </div>
            <span className="cg-count">{plural(middleware.length, "middleware", "middleware")} · {plural(shown.length, "operating system")}</span>
          </div>
          <div className="cg-servers">
            {middleware.map((item) => {
              const id = item.name.toLowerCase();
              // A search opens every matching middleware, so the hits are visible.
              const expanded = openMiddleware.has(id) || Boolean(query.trim());
              return (
                <MiddlewareGroup key={id} name={item.name} entries={item.entries} open={expanded}
                  onToggle={() => setOpenMiddleware((current) => {
                    const next = new Set(current);
                    if (expanded) next.delete(id); else next.add(id);
                    return next;
                  })}>
                  {item.entries.map((entry) => {
                    const key = groupKey(entry.application, entry.os);
                    return (
                      <GroupRow key={key} entry={entry} open={open.has(key)} onUploaded={uploaded}
                        generated={generatedScripts[key]}
                        onGenerated={(data) => setGeneratedScripts((current) => ({ ...current, [key]: data }))}
                        onToggle={() => setOpen((current) => {
                          const next = new Set(current);
                          if (next.has(key)) next.delete(key); else next.add(key);
                          return next;
                        })} />
                    );
                  })}
                </MiddlewareGroup>
              );
            })}
          </div>
        </>
      )}
    </section>
  );
}
