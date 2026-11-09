import { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  Check,
  ChevronDown,
  ChevronRight,
  FileSpreadsheet,
  Layers,
  LoaderCircle,
  Monitor,
  Search,
  ShieldCheck,
} from "lucide-react";

// Compatibility rules: every middleware of the enriched CVE file, the operating systems its
// servers run and, per OS, the products with CVEs there, each with its rule status from
// knowledge.yaml. Rules are entered by hand (several products at once) and checked by the
// engine itself; no model call is made anywhere on this page.

const STATUS_CLASS = {
  supported: "is-covered", not_supported: "is-missing", other_os: "is-partial",
  rules_no_os: "is-partial", no_rules: "is-missing",
};

const RULE_TYPES = [
  { value: "os_support", label: "Supported on this OS" },
  { value: "requirement", label: "Requires a dependency" },
  { value: "application_support", label: "Middleware supports product" },
  { value: "behaviour_change", label: "Behaviour change" },
];

function plural(count, word) {
  return `${count} ${word}${count === 1 ? "" : "s"}`;
}

async function readJson(response, action) {
  const text = await response.text();
  let data;
  try { data = JSON.parse(text); }
  catch { throw new Error(`${action} returned HTTP ${response.status} without JSON. Check the API server logs.`); }
  if (!response.ok) throw new Error(data.error || `${action} failed (HTTP ${response.status}).`);
  return data;
}

function StatusBadge({ status, labels }) {
  return <span className={`cg-status ${STATUS_CLASS[status] || ""}`}>{labels?.[status] || status}</span>;
}

// One rule form for every selected product of one OS: shared fields once, the product versions
// per product (optional for OS support). "Check rules" validates all; "Save all" saves them.
function RuleDraft({ middleware, system, products, onSaved, onCancel }) {
  const [kind, setKind] = useState("os_support");
  const [shared, setShared] = useState({
    os: system.os_name || "", os_versions: system.os_version || "", supported: "yes",
    dependency: "", spec: "", application: middleware, application_release: "", since: "", note: "", source: "",
  });
  const [perProduct, setPerProduct] = useState({});
  const [checked, setChecked] = useState(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const set = (name) => (event) => { setShared((current) => ({ ...current, [name]: event.target.value })); setChecked(null); };
  const setVersion = (product) => (event) => {
    setPerProduct((current) => ({ ...current, [product]: event.target.value }));
    setChecked(null);
  };

  function payloads() {
    return products.map((item) => {
      const versions = (perProduct[item.product] || "").trim();
      const base = { kind, product: item.product, note: shared.note, source: shared.source, cve: "" };
      if (kind === "os_support") return { ...base, os: shared.os, os_versions: shared.os_versions, when: versions, supported: shared.supported };
      if (kind === "requirement") return { ...base, when: versions, dependency: shared.dependency, spec: shared.spec };
      if (kind === "application_support") return { ...base, application: shared.application, when: shared.application_release, versions };
      return { ...base, since: versions || shared.since };
    });
  }

  async function submit(save) {
    setBusy(true); setMessage("");
    try {
      const data = await readJson(await fetch("/api/compatibility/rules/bulk", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ rules: payloads(), save }),
      }), save ? "Saving the rules" : "Checking the rules");
      setChecked(data);
      if (save && data.saved) {
        setMessage(`${plural(data.saved, "rule")} saved. Statuses updated.`);
        onSaved();
      } else if (data.errors) {
        setMessage(`${plural(data.errors, "rule")} need fixing before they can be saved.`);
      }
    } catch (error) { setMessage(error.message); }
    finally { setBusy(false); }
  }

  const versionLabel = { os_support: "Product versions (optional)", requirement: "Product versions",
    application_support: "Supported product versions", behaviour_change: "Since release" }[kind];
  return (
    <div className="compatibility-eval knowledge-gap cr-draft">
      <strong>Draft rule for {plural(products.length, "product")} on {system.os}</strong>
      <p>One rule per product, checked by the engine itself (no model call). Versions take 8.10, 8.x, 9.27+
        or &gt;=8 &lt;9; separate several with commas. Saved rules apply to every CVE of the product.</p>
      <form className="manual-rule" onSubmit={(event) => { event.preventDefault(); submit(false); }}>
        <label>Rule type <select value={kind} onChange={(event) => { setKind(event.target.value); setChecked(null); }}>
          {RULE_TYPES.map((type) => <option key={type.value} value={type.value}>{type.label}</option>)}
        </select></label>
        {kind === "os_support" && (<>
          <label>Operating system <input value={shared.os} onChange={set("os")} required /></label>
          <label>OS versions <input value={shared.os_versions} onChange={set("os_versions")} placeholder="8.10, 8.x" required /></label>
          <label>Supported? <select value={shared.supported} onChange={set("supported")}>
            <option value="yes">Supported</option><option value="no">Not supported</option></select></label>
        </>)}
        {kind === "requirement" && (<>
          <label>Requires (runtime or component) <input value={shared.dependency} onChange={set("dependency")} placeholder="Java, OpenSSL" required /></label>
          <label>Required version <input value={shared.spec} onChange={set("spec")} placeholder="11+" required /></label>
        </>)}
        {kind === "application_support" && (<>
          <label>Middleware / application <input value={shared.application} onChange={set("application")} required /></label>
          <label>Application release <input value={shared.application_release} onChange={set("application_release")} placeholder="10.0" required /></label>
        </>)}
        <table className="cg-table cr-versions">
          <thead><tr><th>Product</th><th>{versionLabel}</th></tr></thead>
          <tbody>
            {products.map((item) => (
              <tr key={item.product}>
                <td>{item.product}{item.components.length ? <small> ({item.components.join(", ")})</small> : null}</td>
                <td><input value={perProduct[item.product] || ""} onChange={setVersion(item.product)}
                  required={kind !== "os_support"}
                  placeholder={kind === "os_support" ? "empty: every version" : kind === "behaviour_change" ? "2.4.60" : "9.27.x"} /></td>
              </tr>
            ))}
          </tbody>
        </table>
        <label>{kind === "behaviour_change" ? "What changes" : "Note (optional)"}
          <textarea value={shared.note} onChange={set("note")} required={kind === "behaviour_change"} /></label>
        <label>Source (optional) <input value={shared.source} onChange={set("source")}
          placeholder="https://vendor.example/support-matrix or where the rule comes from" /></label>
        <div className="server-actions-buttons">
          <button className="button button-secondary" disabled={busy}>{busy ? "Checking…" : "Check rules"}</button>
          <button type="button" className="button button-primary" disabled={busy || !checked || checked.errors > 0}
            onClick={() => submit(true)}>Save all</button>
          <button type="button" className="button button-secondary" onClick={onCancel}>Close</button>
        </div>
      </form>
      {checked && (
        <ul className="cr-checked">
          {checked.checked.map((entry) => (
            <li key={entry.index} className={entry.error ? "cg-error" : "cg-ok"}>
              {entry.error ? <AlertTriangle size={13} /> : <Check size={13} />}{" "}
              <strong>{products[entry.index]?.product}</strong>: {entry.error || entry.proposal.summary}
            </li>
          ))}
        </ul>
      )}
      {message && <p role="status">{message}</p>}
    </div>
  );
}

function OsSection({ middleware, system, labels, onSaved }) {
  const [open, setOpen] = useState(false);
  const [selected, setSelected] = useState(() => new Set());
  const [drafting, setDrafting] = useState(false);
  const chosen = system.products.filter((item) => selected.has(item.product));
  const toggle = (product) => setSelected((current) => {
    const next = new Set(current);
    if (next.has(product)) next.delete(product); else next.add(product);
    return next;
  });
  const uncovered = system.products.filter((item) => item.status !== "supported");
  return (
    <article className={`cg-server cr-os ${open ? "is-open" : ""}`}>
      <div className="cg-server-head">
        <button type="button" className="cg-server-toggle" onClick={() => setOpen(!open)} aria-expanded={open}>
          {open ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
          <Monitor size={16} />
          <span className="cg-server-name">{system.os}</span>
        </button>
        <span className="cg-server-meta">
          {plural(system.products.length, "product")} · {system.counts.supported} supported
          {uncovered.length ? ` · ${uncovered.length} without an OS rule` : ""}
        </span>
        <div className="cg-server-actions">
          <button type="button" className="button button-primary button-small" disabled={!chosen.length}
            onClick={() => { setOpen(true); setDrafting(true); }}>
            Draft rule{chosen.length ? ` (${chosen.length})` : ""}
          </button>
        </div>
      </div>
      {open && (
        <div className="cg-server-body">
          <div className="server-actions-buttons">
            <button type="button" className="button button-secondary button-small"
              onClick={() => setSelected(new Set(uncovered.map((item) => item.product)))}>Select all without an OS rule</button>
            <button type="button" className="button button-secondary button-small"
              onClick={() => setSelected(new Set())}>Clear</button>
          </div>
          <table className="cg-table">
            <thead><tr><th /><th>Product</th><th>Components</th><th>CVEs</th><th>Status</th><th>Rules</th></tr></thead>
            <tbody>
              {system.products.map((item) => (
                <tr key={item.product}>
                  <td><input type="checkbox" checked={selected.has(item.product)} onChange={() => toggle(item.product)}
                    aria-label={`Select ${item.product}`} /></td>
                  <td>{item.product}</td>
                  <td>{item.components.length ? item.components.join(", ") : <span className="cg-muted">not named</span>}</td>
                  <td className="cg-cves">{item.cves.slice(0, 4).join(", ")}{item.cves.length > 4 ? ` +${item.cves.length - 4}` : ""}</td>
                  <td><StatusBadge status={item.status} labels={labels} /></td>
                  <td>
                    {item.os_rules.map((rule, index) => (
                      <div key={`os-${index}`} className="cg-found">
                        {rule.supported === false ? "Not supported" : "Supported"} on {rule.os} {(rule.os_versions || []).join(", ")}
                        {rule.when ? ` (versions ${rule.when})` : ""}
                        {rule.source && /^https?:/.test(rule.source) ? <> · <a href={rule.source} target="_blank" rel="noreferrer">source</a></> : null}
                      </div>
                    ))}
                    {item.rules.filter((rule) => rule.kind !== "os_support").slice(0, 3).map((rule, index) => (
                      <div key={`r-${index}`} className="cg-muted">{rule.text}</div>
                    ))}
                    {item.application_support.map((entry, index) => (
                      <div key={`a-${index}`} className="cg-muted">{middleware} {entry.when}: supports {(entry.versions || []).join(", ")}</div>
                    ))}
                    {!item.os_rules.length && !item.rules.length && !item.application_support.length
                      && <span className="cg-muted">none</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {drafting && chosen.length > 0 && (
            <RuleDraft key={chosen.map((item) => item.product).join("|")} middleware={middleware} system={system}
              products={chosen} onCancel={() => setDrafting(false)}
              onSaved={() => { setSelected(new Set()); onSaved(); }} />
          )}
        </div>
      )}
    </article>
  );
}

function MiddlewareRow({ entry, labels, onSaved }) {
  const [open, setOpen] = useState(false);
  const missing = entry.products - entry.counts.supported;
  return (
    <article className={`cg-server cr-middleware ${open ? "is-open" : ""}`}>
      <div className="cg-server-head">
        <button type="button" className="cg-server-toggle" onClick={() => setOpen(!open)} aria-expanded={open}>
          {open ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
          <Layers size={16} />
          <span className="cg-server-name">{entry.middleware}</span>
        </button>
        <span className="cg-server-meta">
          {plural(entry.systems.length, "OS")} · {plural(entry.products, "product")} · {entry.counts.supported} supported
        </span>
        <span className={`cg-status ${missing ? (entry.counts.supported ? "is-partial" : "is-missing") : "is-covered"}`}>
          {missing ? `${missing} without an OS rule` : "All covered"}
        </span>
      </div>
      {open && (
        <div className="cg-server-body cr-systems">
          {entry.systems.map((system) => (
            <OsSection key={system.os} middleware={entry.middleware} system={system} labels={labels} onSaved={onSaved} />
          ))}
        </div>
      )}
    </article>
  );
}

export function CompatRulesView({ jobId, enrichedKey, sourceName, onOpenWorkspace }) {
  const [data, setData] = useState(null);
  const [failure, setFailure] = useState("");
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState("all");
  const [reload, setReload] = useState(0);

  useEffect(() => {
    if (!jobId) return undefined;
    let live = true;
    setFailure("");
    fetch(`/api/jobs/${encodeURIComponent(jobId)}/compatibility-coverage`)
      .then((response) => readJson(response, "Loading the compatibility rules"))
      .then((result) => live && setData(result))
      .catch((error) => live && setFailure(error.message));
    return () => { live = false; };
  }, [jobId, enrichedKey, reload]);

  const shown = useMemo(() => {
    const text = query.trim().toLowerCase();
    return (data?.middlewares || []).map((entry) => {
      const systems = entry.systems.map((system) => ({
        ...system,
        products: system.products.filter((item) => (filter === "all"
          || (filter === "missing" ? item.status !== "supported" : item.status === "supported"))
          && (!text || `${entry.middleware} ${system.os} ${item.product} ${item.components.join(" ")} ${item.cves.join(" ")}`
            .toLowerCase().includes(text))),
      })).filter((system) => system.products.length);
      return { ...entry, systems };
    }).filter((entry) => entry.systems.length);
  }, [data, query, filter]);

  const totals = useMemo(() => {
    const all = (data?.middlewares || []).flatMap((entry) => entry.systems.flatMap((system) => system.products));
    return { products: all.length, supported: all.filter((item) => item.status === "supported").length,
      none: all.filter((item) => item.status === "no_rules").length,
      systems: new Set((data?.middlewares || []).flatMap((entry) => entry.systems.map((system) => system.os))).size };
  }, [data]);

  return (
    <section className="cg-page">
      <div className="results-heading">
        <div>
          <span className="eyebrow">Compatibility</span>
          <h1>Compatibility rules</h1>
          <p>Every middleware in the enriched CVE file, the operating systems its servers run, and the products with
            CVEs on each. Select products, draft one rule for all of them, and the status updates once saved.
            The engine checks the rules itself; no model is used.</p>
        </div>
      </div>
      <div className="cg-script-note">
        <ShieldCheck size={15} />
        <span><strong>Supported on this OS</strong> covers a product on an OS release. OS-vendor packages (an el8_10
          RPM on RHEL 8.10) are checked from the package itself even without a rule; a rule makes it explicit.</span>
      </div>
      {failure && <p className="cg-error"><AlertTriangle size={14} /> {failure}</p>}
      {!jobId || !enrichedKey ? (
        <div className="cg-empty">
          <FileSpreadsheet size={28} />
          <strong>No enriched CVE file yet</strong>
          <p>Upload the CVE file in the CVE workspace and enrich it. Its middleware, operating systems and products appear here.</p>
          {onOpenWorkspace && <button type="button" className="button button-primary" onClick={onOpenWorkspace}>Open CVE workspace</button>}
        </div>
      ) : (
        <>
          <div className="metric-grid cg-metrics">
            <div className="metric"><span>File</span><strong title={sourceName}>{sourceName || "current upload"}</strong></div>
            <div className="metric"><span>Middleware</span><strong>{data?.middlewares.length ?? "…"}</strong></div>
            <div className="metric"><span>Operating systems</span><strong>{totals.systems}</strong></div>
            <div className="metric"><span>Supported on OS</span><strong>{totals.supported} / {totals.products}</strong></div>
            <div className="metric"><span>No rules</span><strong>{totals.none}</strong></div>
          </div>
          {!data && !failure && <p className="cg-muted"><LoaderCircle className="spin" size={13} /> Loading…</p>}
          <div className="cg-toolbar">
            <label className="cg-search">
              <Search size={15} />
              <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search middleware, OS, product or CVE" />
            </label>
            <div className="cg-filters" role="group" aria-label="Filter products">
              {[["all", "All"], ["missing", "Without an OS rule"], ["covered", "Supported"]].map(([key, label]) => (
                <button key={key} type="button" className={filter === key ? "is-active" : ""} onClick={() => setFilter(key)}>{label}</button>
              ))}
            </div>
            <span className="cg-count">{plural(shown.length, "middleware")}</span>
          </div>
          <div className="cg-servers">
            {shown.map((entry) => (
              <MiddlewareRow key={entry.middleware} entry={entry} labels={data?.status_labels}
                onSaved={() => setReload((value) => value + 1)} />
            ))}
            {data && !shown.length && <p className="cg-muted">Nothing matches.</p>}
          </div>
        </>
      )}
    </section>
  );
}
