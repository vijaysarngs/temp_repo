import { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  ArrowRight,
  Check,
  ChevronLeft,
  Download,
  FileDiff,
  GitBranch,
  History,
  Layers,
  LoaderCircle,
  Package,
  PackageCheck,
  Search,
  Server,
  ShieldAlert,
  X,
} from "lucide-react";

// Delivery agent (aegis-cve-evidence/delivery/agent.py): every fix of a server, grouped by
// product into one target version, written as a diff folder that can be committed to git.

const UNASSIGNED = "unassigned";
const STRATEGIES = [
  { id: "minimum", label: "Minimum fixed", hint: "The highest first-fixed version: the smallest change that fixes every CVE." },
  { id: "latest", label: "Latest on line", hint: "The newest release on the fixed line, when a source names one." },
];
const STATUS = {
  ready: { label: "Ready", Icon: PackageCheck },
  review: { label: "Review", Icon: AlertTriangle },
  blocked: { label: "Blocked", Icon: ShieldAlert },
};
const STATUS_FILTERS = ["all", "ready", "review", "blocked"];

function serverName(name) {
  return name === UNASSIGNED ? "No server named" : name;
}

async function readJson(response, action) {
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `${action} failed (HTTP ${response.status}).`);
  return data;
}

function entryName(product) {
  return product.installation ? `${product.product} (${product.installation})` : product.product;
}

function deliverText(product) {
  const parts = [];
  if (product.target_version) parts.push(product.target_version);
  if (product.patches?.length) parts.push(product.patches.map((patch) => patch.patch).join(", "));
  return parts.join(" + ") || "—";
}

// The same before → after change the artifact's changes.diff holds, rendered from the plan.
function diffPreview(products) {
  const lines = [];
  for (const product of [...products].sort((a, b) => entryName(a).localeCompare(entryName(b)))) {
    const installed = product.installed_version || "unknown";
    lines.push({ type: " ", text: `"${entryName(product)}":` });
    if (product.target_version && product.target_version !== installed) {
      lines.push({ type: "-", text: `  version: "${installed}"` });
      lines.push({ type: "+", text: `  version: "${product.target_version}"` });
    } else {
      lines.push({ type: " ", text: `  version: "${installed}"` });
    }
    if (product.patches?.length) {
      lines.push({ type: "+", text: `  patches: [${product.patches.map((patch) => `"${patch.patch}"`).join(", ")}]` });
    }
  }
  return lines;
}

function StatusBadge({ status }) {
  const view = STATUS[status] || { label: status, Icon: Package };
  const Icon = view.Icon;
  return <span className={`delivery-status delivery-status-${status}`}><Icon size={12} /> {view.label}</span>;
}

// Every server the scanner found a CVE on (plan.cve_servers), with this server and the
// server the fix was assessed on marked.
function CveServers({ servers, current, assessedOn }) {
  if (!servers?.length) return null;
  const others = servers.length - (servers.some((name) => name.toLowerCase() === current.toLowerCase()) ? 1 : 0);
  return (
    <details className="delivery-cve-servers" onClick={(event) => event.stopPropagation()}>
      <summary>
        <Server size={11} /> Found on {servers.length} server{servers.length === 1 ? "" : "s"}
        {others > 0 && servers.length > 1 ? ` (${others} other${others === 1 ? "" : "s"})` : ""}
      </summary>
      <ul>
        {servers.map((name) => {
          const here = name.toLowerCase() === current.toLowerCase();
          const assessed = assessedOn ? name.toLowerCase() === assessedOn.toLowerCase() : here;
          return (
            <li key={name} className={here ? "is-current" : ""}>
              {name}{here && <em>this server</em>}{assessed && <em className="is-assessed">assessed</em>}
            </li>
          );
        })}
      </ul>
    </details>
  );
}

function ProductRow({ product, cveServers, current }) {
  const [open, setOpen] = useState(false);
  const fixed = product.cves.filter((cve) => cve.fix);
  const changes = product.target_version && product.target_version !== product.installed_version;
  const affected = new Set(fixed.flatMap((cve) => (cveServers?.[cve.cve] || []).map((name) => name.toLowerCase())));
  const elsewhere = [...new Set(fixed.filter((cve) => cve.assessed_elsewhere).map((cve) => cve.assessed_on || "another server"))];
  return (
    <>
      <tr className={`delivery-row${open ? " is-open" : ""}`} onClick={() => setOpen(!open)}>
        <td>
          <strong>{product.product}</strong>
          {product.installation && <small>{product.installation}</small>}
          {product.applications?.length > 0 && <small>Used by {product.applications.join(", ")}</small>}
        </td>
        <td className="delivery-version">
          <span className={product.installed_version ? "" : "is-unknown"}>{product.installed_version || "unknown"}</span>
          <ArrowRight size={13} />
          <strong className={changes || product.patches?.length ? "is-change" : ""}>{deliverText(product)}</strong>
          {product.latest_version && product.latest_version !== product.target_version && (
            <small>newest on line {product.latest_version}</small>
          )}
        </td>
        <td>
          <div className="delivery-cves">
            {fixed.slice(0, 3).map((cve) => <span key={cve.cve} className="cve-pill">{cve.cve}</span>)}
            {fixed.length > 3 && <span className="cve-more">+{fixed.length - 3}</span>}
          </div>
          {affected.size > 1 && <small className="delivery-affected">on {affected.size} servers</small>}
          {elsewhere.length > 0 && <small className="delivery-elsewhere">assessed on {elsewhere.join(", ")}</small>}
        </td>
        <td><StatusBadge status={product.status} /></td>
      </tr>
      {open && (
        <tr className="delivery-detail">
          <td colSpan={4}>
            <div className="delivery-detail-grid">
              <div>
                <h4>CVEs fixed by this update ({fixed.length})</h4>
                <ul className="delivery-cve-list">
                  {fixed.map((cve) => (
                    <li key={cve.cve}>
                      <code>{cve.cve}</code>
                      <span>{cve.fix}</span>
                      <span className={`compatibility compatibility-${String(cve.compatibility).toLowerCase()}`}>
                        {String(cve.compatibility).replaceAll("_", " ")}
                      </span>
                      {cve.assessed_elsewhere && (
                        <span className="delivery-elsewhere">assessed on {cve.assessed_on || "another server"}</span>
                      )}
                      <CveServers servers={cveServers?.[cve.cve]} current={current}
                        assessedOn={cve.assessed_elsewhere ? cve.assessed_on : null} />
                    </li>
                  ))}
                </ul>
              </div>
              <div>
                <h4>Before it ships</h4>
                {product.reasons.length ? (
                  <ul className="delivery-reasons">{product.reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul>
                ) : <p className="delivery-ok"><Check size={13} /> Compatible on this server; nothing to review.</p>}
                {product.minimum_version && product.latest_version && (
                  <p className="delivery-note">Minimum fixed {product.minimum_version} · newest on line {product.latest_version}.</p>
                )}
                {product.package_lineage && <p className="delivery-note">{product.package_lineage}</p>}
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

function ArtifactPanel({ artifact, config, onPushed }) {
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState("");
  const git = artifact.git;

  async function push() {
    setBusy(true);
    setFailure("");
    try {
      const data = await readJson(await fetch(`/api/delivery/artifacts/${artifact.artifact_id}/push`, { method: "POST" }),
        "Git delivery");
      onPushed(data.git);
    } catch (error) {
      setFailure(error.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="delivery-artifact">
      <div className="delivery-artifact-head">
        <div>
          <span className="eyebrow"><FileDiff size={13} /> Artifact ready</span>
          <strong>{serverName(artifact.server)}</strong>
          <small>Strategy {artifact.strategy} · {new Date(artifact.created_at).toLocaleString()}</small>
        </div>
        <div className="delivery-artifact-actions">
          <a className="button button-secondary button-small" href={`/api/delivery/artifacts/${artifact.artifact_id}/download`}>
            <Download size={14} /> Download .zip
          </a>
          <button type="button" className="button button-primary button-small" disabled={busy || Boolean(git) || !config?.git_configured}
            title={config?.git_configured ? "" : "Set AEGIS_DELIVERY_REPO to a local clone of the delivery repository"}
            onClick={push}>
            {busy ? <LoaderCircle className="spin" size={14} /> : <GitBranch size={14} />}
            {git ? (git.pushed ? "Pushed" : "Committed") : config?.push_enabled ? "Commit and push" : "Commit to git"}
          </button>
        </div>
      </div>
      {artifact.files && (
        <ul className="delivery-files">
          {artifact.files.map((file) => <li key={file}><code>{file}</code></li>)}
        </ul>
      )}
      {git && (
        <p className="server-upload-ok delivery-git-ok">
          <Check size={13} /> Branch <code>{git.branch}</code> · commit <code>{String(git.commit).slice(0, 10)}</code>
          {git.pushed ? ` · pushed to ${git.remote}` : " · committed locally (pushing is off: AEGIS_DELIVERY_PUSH)"}
        </p>
      )}
      {!config?.git_configured && !git && (
        <p className="delivery-note">Git is not set up on the API server. Set <code>AEGIS_DELIVERY_REPO</code> to a clone of the
          delivery repository (and <code>AEGIS_DELIVERY_PUSH=1</code> to push); until then, download the .zip.</p>
      )}
      {failure && <p className="server-upload-error"><AlertTriangle size={13} /> {failure}</p>}
    </section>
  );
}

export default function DeliveryView({ runIds, items, scopeLabel, onBack, onMiddleware }) {
  const [strategy, setStrategy] = useState("minimum");
  const [plan, setPlan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [failure, setFailure] = useState("");
  const [selected, setSelected] = useState(null);
  const [statusFilter, setStatusFilter] = useState("all");
  const [query, setQuery] = useState("");
  const [config, setConfig] = useState(null);
  const [artifacts, setArtifacts] = useState({});
  const [history, setHistory] = useState([]);
  const [building, setBuilding] = useState(false);
  const scope = useMemo(() => ({ run_ids: runIds, items: items || null }), [runIds, items]);

  useEffect(() => {
    fetch("/api/delivery/config").then((r) => r.json()).then(setConfig).catch(() => setConfig(null));
    fetch("/api/delivery/artifacts").then((r) => r.json()).then((data) => setHistory(data.artifacts || [])).catch(() => {});
  }, []);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setFailure("");
    fetch("/api/delivery/plan", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ...scope, strategy }),
    })
      .then((response) => readJson(response, "Building the delivery plan"))
      .then((data) => {
        if (cancelled) return;
        setPlan(data);
        setSelected((current) => (data.servers.some((s) => s.server === current) ? current : data.servers[0]?.server || null));
      })
      .catch((error) => !cancelled && setFailure(error.message))
      .finally(() => !cancelled && setLoading(false));
    return () => { cancelled = true; };
  }, [scope, strategy]);

  const [serverQuery, setServerQuery] = useState("");
  const server = plan?.servers.find((entry) => entry.server === selected);
  const assessedCount = plan?.servers.filter((entry) => entry.summary.assessed_here > 0).length || 0;
  const shownServers = useMemo(() => {
    const text = serverQuery.trim().toLowerCase();
    return (plan?.servers || []).filter((entry) => !text || entry.server.toLowerCase().includes(text));
  }, [plan, serverQuery]);
  const products = useMemo(() => {
    const text = query.trim().toLowerCase();
    return (server?.products || []).filter((product) => (statusFilter === "all" || product.status === statusFilter)
      && (!text || [product.product, product.installation, product.installed_version, product.target_version,
        ...product.cves.map((cve) => cve.cve)].some((value) => String(value || "").toLowerCase().includes(text))));
  }, [server, statusFilter, query]);
  const artifact = server ? artifacts[`${server.server}|${strategy}`] : null;
  const serverHistory = history.filter((entry) => server && entry.server === server.server);

  async function build() {
    setBuilding(true);
    setFailure("");
    try {
      const data = await readJson(await fetch("/api/delivery/artifacts", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ...scope, strategy, server: server.server }),
      }), "Building the artifact");
      setArtifacts((current) => ({ ...current, [`${server.server}|${strategy}`]: data }));
      setHistory((current) => [data, ...current]);
    } catch (error) {
      setFailure(error.message);
    } finally {
      setBuilding(false);
    }
  }

  return (
    <section className="delivery-workspace">
      <div className="results-heading">
        <div>
          <button className="back-link" onClick={onBack}><ChevronLeft size={17} /> Back to results</button>
          <span className="eyebrow">Delivery agent</span>
          <h1>Server delivery</h1>
          <p>Every fix for a server, grouped by product into one version update, and packaged as a diff folder
            (before and after versions, <code>changes.diff</code>, manifest) to commit to git.
            {scopeLabel ? ` Built from ${scopeLabel}.` : ""}</p>
        </div>
        <div className="results-heading-side">
        {onMiddleware && (
          <button type="button" className="button button-secondary" onClick={onMiddleware}>
            <Layers size={16} /> Middleware delivery
          </button>
        )}
        <div className="segmented delivery-strategy" role="tablist" aria-label="Target version">
          {STRATEGIES.map((option) => (
            <button key={option.id} role="tab" title={option.hint} aria-selected={strategy === option.id}
              className={strategy === option.id ? "active" : ""} onClick={() => setStrategy(option.id)}>
              {option.label}
            </button>
          ))}
        </div>
        </div>
      </div>

      {failure && <div className="delivery-error"><AlertTriangle size={15} /> {failure}</div>}

      {loading && !plan ? (
        <div className="delivery-loading"><LoaderCircle className="spin" size={20} /> Grouping fixes by server and product…</div>
      ) : plan && !plan.servers.length ? (
        <div className="empty-previous-fixes">No result in these runs has a server or a fix to deliver.</div>
      ) : plan && (
        <div className={`delivery-layout${loading ? " is-loading" : ""}`}>
          <nav className="delivery-servers" aria-label="Servers">
            <span className="delivery-servers-title">
              Servers ({plan.servers.length}{assessedCount < plan.servers.length ? ` · ${assessedCount} assessed` : ""})
            </span>
            {plan.servers.length > 8 && (
              <label className="search-field delivery-server-search">
                <Search size={14} aria-hidden="true" />
                <input type="search" placeholder="Find a server…" value={serverQuery} aria-label="Find a server"
                  onChange={(event) => setServerQuery(event.target.value)} />
                {serverQuery && <button type="button" aria-label="Clear" onClick={() => setServerQuery("")}><X size={12} /></button>}
              </label>
            )}
            {shownServers.length === 0 && <span className="delivery-server-meta">No server matches.</span>}
            {shownServers.map((entry) => (
              <button key={entry.server} type="button" className={`delivery-server${entry.server === selected ? " active" : ""}`}
                onClick={() => setSelected(entry.server)}>
                <span className="delivery-server-name"><Server size={14} /> {serverName(entry.server)}</span>
                <span className="delivery-server-meta">
                  {entry.summary.products} product{entry.summary.products === 1 ? "" : "s"} · {entry.summary.cves_covered} CVE{entry.summary.cves_covered === 1 ? "" : "s"}
                </span>
                {entry.assigned && entry.summary.cves_covered > 0 && (
                  <span className={`delivery-server-origin${entry.summary.assessed_here ? " is-assessed" : ""}`}>
                    {entry.summary.assessed_here
                      ? `assessed here${entry.summary.assessed_elsewhere ? ` · ${entry.summary.assessed_elsewhere} from other servers` : ""}`
                      : "fixes assessed on another server"}
                  </span>
                )}
                <span className="delivery-server-bars" aria-hidden="true">
                  {["ready", "review", "blocked"].map((status) => entry.summary[status] > 0 && (
                    <i key={status} className={`bar-${status}`} style={{ flexGrow: entry.summary[status] }} />
                  ))}
                </span>
              </button>
            ))}
          </nav>

          {server && (
            <div className="delivery-main">
              <div className="delivery-summary">
                {[
                  { label: "Products to update", value: server.summary.products },
                  { label: "CVEs fixed", value: server.summary.cves_covered },
                  { label: "Ready", value: server.summary.ready, tone: "ready" },
                  { label: "Review", value: server.summary.review, tone: "review" },
                  { label: "Blocked", value: server.summary.blocked, tone: "blocked" },
                  { label: "No fix yet", value: server.summary.cves_without_fix, tone: "muted" },
                ].map((metric) => (
                  <div key={metric.label} className={`delivery-metric${metric.tone ? ` tone-${metric.tone}` : ""}`}>
                    <span>{metric.label}</span><strong>{metric.value}</strong>
                  </div>
                ))}
              </div>

              {server.assigned && server.summary.assessed_elsewhere > 0 && (
                <p className="delivery-note delivery-unassigned">
                  {server.summary.assessed_here ? `${server.summary.assessed_elsewhere} of this server's CVE fixes were` : "Every fix here was"}{" "}
                  assessed on another server the scanner found the same CVE on, so they are marked <strong>Review</strong>:
                  this server's own installed version and compatibility were not checked. Collect its context, or run the
                  fix on it, to confirm before shipping.
                </p>
              )}

              {!server.assigned && (
                <p className="delivery-note delivery-unassigned">The scanner named no server for these results. They are delivered
                  together as <code>unassigned</code>; collect each server's context to split them per server.</p>
              )}

              <div className="delivery-panel">
                <div className="delivery-panel-head">
                  <h2><Package size={16} /> Version updates for {serverName(server.server)}</h2>
                  <div className="delivery-tools">
                    <label className="search-field">
                      <Search size={15} aria-hidden="true" />
                      <input type="search" placeholder="Product, version or CVE…" value={query}
                        aria-label="Search products" onChange={(event) => setQuery(event.target.value)} />
                      {query && <button type="button" aria-label="Clear search" onClick={() => setQuery("")}><X size={13} /></button>}
                    </label>
                    <div className="segmented" role="tablist" aria-label="Filter by status">
                      {STATUS_FILTERS.map((status) => (
                        <button key={status} role="tab" aria-selected={statusFilter === status}
                          className={statusFilter === status ? "active" : ""} onClick={() => setStatusFilter(status)}>
                          {status === "all" ? "All" : STATUS[status].label}
                          {status !== "all" ? ` ${server.summary[status]}` : ""}
                        </button>
                      ))}
                    </div>
                  </div>
                </div>
                <div className="table-shell">
                  <table className="delivery-table">
                    <thead><tr><th>Product</th><th>Installed → deliver</th><th>CVEs</th><th>Status</th></tr></thead>
                    <tbody>
                      {products.length ? products.map((product) => (
                        <ProductRow key={`${product.product}|${product.installation || ""}`} product={product}
                          cveServers={plan.cve_servers} current={server.server} />
                      )) : (
                        <tr><td className="table-empty" colSpan={4}>No product matches these filters.</td></tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

              <div className="delivery-split">
                <section className="delivery-panel delivery-diff">
                  <div className="delivery-panel-head">
                    <h2><FileDiff size={16} /> changes.diff preview</h2>
                    <span className="record-count">versions.yaml</span>
                  </div>
                  <pre>{diffPreview(server.products).map((line, index) => (
                    <span key={index} className={`diff-${line.type === "+" ? "add" : line.type === "-" ? "del" : "ctx"}`}>
                      {line.type} {line.text}{"\n"}
                    </span>
                  ))}</pre>
                </section>

                <div className="delivery-side">
                  <section className="delivery-panel delivery-build">
                    <h2><GitBranch size={16} /> Package for git</h2>
                    <p>Writes <code>{server.server.toLowerCase()}/&lt;artifact id&gt;/</code> with
                      README, manifest, before/after versions and the diff. Committing uses its own branch, so no checkout is touched.</p>
                    <button type="button" className="button button-primary" disabled={building || !server.products.length} onClick={build}>
                      {building ? <LoaderCircle className="spin" size={16} /> : <FileDiff size={16} />}
                      {building ? "Building…" : artifact ? "Build again" : "Build artifact"}
                    </button>
                  </section>
                  {artifact && (
                    <ArtifactPanel artifact={artifact} config={config}
                      onPushed={(git) => setArtifacts((current) => ({
                        ...current, [`${server.server}|${strategy}`]: { ...artifact, git } }))} />
                  )}
                  {serverHistory.length > 0 && (
                    <details className="delivery-panel delivery-history">
                      <summary><History size={14} /> Earlier artifacts for this server ({serverHistory.length})</summary>
                      <ul>
                        {serverHistory.slice(0, 8).map((entry) => (
                          <li key={entry.artifact_id}>
                            <div>
                              <strong>{new Date(entry.created_at).toLocaleString()}</strong>
                              <small>{entry.strategy} · {entry.summary?.products} products{entry.git
                                ? ` · ${entry.git.pushed ? "pushed" : "committed"} ${entry.git.branch}` : ""}</small>
                            </div>
                            <a href={`/api/delivery/artifacts/${entry.artifact_id}/download`} aria-label="Download"><Download size={14} /></a>
                          </li>
                        ))}
                      </ul>
                    </details>
                  )}
                </div>
              </div>

              {server.without_fix.length > 0 && (
                <details className="delivery-panel delivery-nofix">
                  <summary><AlertTriangle size={14} /> CVEs on this server with no fix yet ({server.without_fix.length})</summary>
                  <ul>
                    {server.without_fix.map((entry) => (
                      <li key={`${entry.product}-${entry.cve}`}><code>{entry.cve}</code> {entry.product}
                        <span>{String(entry.verdict || "unknown").replaceAll("_", " ").toLowerCase()}</span></li>
                    ))}
                  </ul>
                </details>
              )}
            </div>
          )}
        </div>
      )}
    </section>
  );
}
