import { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  ArrowRight,
  BookOpen,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  ExternalLink,
  GitBranch,
  Layers,
  LoaderCircle,
  Package,
  Search,
  Server,
  Ticket,
  X,
} from "lucide-react";
import { resultAnchor } from "./remediationResults.js";

// Delivery by middleware system (GET /api/jobs/<job>/middleware): the uploaded file as
// middleware -> product (with its components) -> CVEs, each CVE with its servers and the fix
// a run found for it. The three delivery actions are placeholders: they show what would be
// sent and call no agent.

const UNASSIGNED = "unassigned";

function middlewareName(name) {
  return name === UNASSIGNED ? "No middleware named" : name;
}

function slug(value) {
  return String(value || "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
}

function humanize(value) {
  return String(value || "").replaceAll("_", " ").toLowerCase();
}

function plural(count, word) {
  return `${count} ${word}${count === 1 ? "" : "s"}`;
}

function fixedCves(entry) {
  return entry.products.flatMap((product) => product.cves.filter((cve) => cve.fix)
    .map((cve) => ({ ...cve, product: product.product })));
}

// What each delivery action would produce for a middleware. Nothing is sent.
const ACTIONS = [
  {
    id: "git",
    title: "Git artifact push",
    Icon: GitBranch,
    blurb: "Commit the middleware's version updates as a diff folder on its own branch.",
    preview: (entry) => {
      const folder = `${slug(entry.middleware)}/<artifact id>`;
      return {
        heading: `Branch aegis/delivery/${slug(entry.middleware)}`,
        lines: [
          `${folder}/README.md`, `${folder}/manifest.json`, `${folder}/before/versions.yaml`,
          `${folder}/after/versions.yaml`, `${folder}/changes.diff`, "",
          `Commit: "Deliver ${plural(fixedCves(entry).length, "CVE fix")} for ${middlewareName(entry.middleware)}"`,
        ],
      };
    },
  },
  {
    id: "jira",
    title: "Jira ticket creation agent",
    Icon: Ticket,
    blurb: "Open one ticket per middleware, with a sub-task per product update.",
    preview: (entry) => {
      const fixes = fixedCves(entry);
      return {
        heading: `[Security] Patch ${plural(fixes.length, "CVE")} on ${middlewareName(entry.middleware)}`,
        lines: [
          `${plural(entry.summary.products, "product")} · ${plural(entry.summary.servers, "server")}`, "",
          ...entry.products.filter((product) => product.summary.with_fix).map((product) =>
            `Sub-task: ${product.product} (${plural(product.summary.with_fix, "CVE")})`),
          "",
          ...fixes.slice(0, 12).map((cve) => `- ${cve.cve}  ${cve.product}: ${cve.fix.installed_version || "unknown"} -> ${cve.fix.label}`),
          ...(fixes.length > 12 ? [`… and ${fixes.length - 12} more`] : []),
        ],
      };
    },
  },
  {
    id: "confluence",
    title: "Confluence doc creation agent",
    Icon: BookOpen,
    blurb: "Write a remediation page: scope, fixes, servers and compatibility notes.",
    preview: (entry) => ({
      heading: `${middlewareName(entry.middleware)} – CVE remediation plan`,
      lines: [
        "1. Summary",
        `   ${plural(entry.summary.cves, "CVE")}, ${entry.summary.with_fix} with a fix, ${plural(entry.summary.products, "product")}, ${plural(entry.summary.servers, "server")}`,
        "2. Products and components",
        ...entry.products.slice(0, 10).map((product) => `   - ${product.product}: ${product.components.slice(0, 4).join(", ")}${product.components.length > 4 ? ", …" : ""}`),
        "3. Fixes and compatibility",
        "4. Affected servers",
        "5. Rollout and rollback",
      ],
    }),
  },
];

function ActionPlaceholder({ action, entry, onClose }) {
  const preview = action.preview(entry);
  const Icon = action.Icon;
  return (
    <section className="delivery-panel mw-placeholder" aria-live="polite">
      <div className="delivery-panel-head">
        <h2><Icon size={16} /> {action.title}</h2>
        <button type="button" className="button button-ghost button-small" onClick={onClose} aria-label="Close">
          <X size={14} />
        </button>
      </div>
      <p className="delivery-note mw-placeholder-note">
        <AlertTriangle size={13} /> Placeholder: this agent is not connected yet, so nothing is sent. This is the
        draft it would work from.
      </p>
      <div className="mw-draft">
        <strong>{preview.heading}</strong>
        <pre>{preview.lines.join("\n")}</pre>
      </div>
      <button type="button" className="button button-primary" disabled title="Agent not connected">
        <Icon size={15} /> Send (not connected)
      </button>
    </section>
  );
}

function Servers({ servers, assessedOn }) {
  if (!servers.length) return <span className="is-unknown">No server named</span>;
  return (
    <details className="delivery-cve-servers">
      <summary><Server size={11} /> {plural(servers.length, "server")}</summary>
      <ul>
        {servers.map((name) => (
          <li key={name}>{name}{assessedOn && name.toLowerCase() === assessedOn.toLowerCase() && (
            <em className="is-assessed">assessed</em>)}</li>
        ))}
      </ul>
    </details>
  );
}

function CveTable({ cves, onOpenCard }) {
  return (
    <div className="table-shell">
      <table className="delivery-table mw-table">
        <thead><tr><th>CVE</th><th>Component</th><th>Installed → fix</th><th>Compatibility</th><th>Servers</th></tr></thead>
        <tbody>
          {cves.map((cve) => (
            <tr key={cve.cve}>
              <td>
                {cve.fix ? (
                  <a className="mw-card-link" href={`#${resultAnchor(cve.fix.card)}`} title="Open the result card of this fix"
                    onClick={(event) => { event.preventDefault(); onOpenCard(cve.fix, cve.row_index); }}>
                    {cve.cve} <ExternalLink size={11} />
                  </a>
                ) : <code className="mw-cve-plain">{cve.cve}</code>}
                {cve.cvss && <small>CVSS {cve.cvss.split(" (")[0]}</small>}
                {cve.known_exploited && <small className="mw-kev">Known exploited</small>}
              </td>
              <td>{cve.components.join(", ")}</td>
              <td className="delivery-version">
                {cve.fix ? (
                  <>
                    <span className={cve.fix.installed_version ? "" : "is-unknown"}>{cve.fix.installed_version || "unknown"}</span>
                    <ArrowRight size={13} />
                    <strong className="is-change">{cve.fix.label}</strong>
                    <small>{cve.fix.origin === "session" ? "this file's run" : "earlier saved run"}</small>
                  </>
                ) : <span className="is-unknown">Not assessed yet</span>}
              </td>
              <td>
                {cve.fix ? (
                  <span className={`compatibility compatibility-${String(cve.fix.compatibility).toLowerCase()}`}>
                    {humanize(cve.fix.compatibility)}
                  </span>
                ) : <span className="is-unknown">—</span>}
              </td>
              <td><Servers servers={cve.servers} assessedOn={cve.fix?.assessed_on} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ProductRow({ product, open, onToggle, onOpenCard }) {
  const shown = product.components.slice(0, 6);
  return (
    <article className={`delivery-panel mw-product${open ? " is-open" : ""}`}>
      <button type="button" className="mw-product-head" aria-expanded={open} onClick={onToggle}>
        {open ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
        <div className="mw-product-title">
          <strong><Package size={14} /> {product.product}</strong>
          <span className="mw-components">
            {shown.map((name) => <span key={name} className="mw-component">{name}</span>)}
            {product.components.length > shown.length && <span className="cve-more">+{product.components.length - shown.length}</span>}
          </span>
        </div>
        <span className="mw-product-counts">
          <span>{plural(product.summary.cves, "CVE")}</span>
          <span className={product.summary.with_fix ? "has-fix" : ""}>{product.summary.with_fix} with fix</span>
          <span>{plural(product.summary.servers, "server")}</span>
        </span>
      </button>
      {open && <CveTable cves={product.cves} onOpenCard={onOpenCard} />}
    </article>
  );
}

export default function MiddlewareDeliveryView({ jobId, sourceName, onBack, onServerDelivery, onOpenCard }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [failure, setFailure] = useState("");
  const [selected, setSelected] = useState(null);
  const [action, setAction] = useState(null);
  const [openProducts, setOpenProducts] = useState(new Set());
  const [query, setQuery] = useState("");
  const [productQuery, setProductQuery] = useState("");

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setFailure("");
    fetch(`/api/jobs/${jobId}/middleware`)
      .then(async (response) => {
        const body = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(body.error || `Loading the middleware failed (HTTP ${response.status}).`);
        return body;
      })
      .then((body) => {
        if (cancelled) return;
        setData(body);
        setSelected((current) => current || body.middlewares[0]?.middleware || null);
      })
      .catch((error) => !cancelled && setFailure(error.message))
      .finally(() => !cancelled && setLoading(false));
    return () => { cancelled = true; };
  }, [jobId]);

  const shown = useMemo(() => {
    const text = query.trim().toLowerCase();
    return (data?.middlewares || []).filter((entry) => !text || middlewareName(entry.middleware).toLowerCase().includes(text));
  }, [data, query]);
  const entry = data?.middlewares.find((item) => item.middleware === selected);
  const products = useMemo(() => {
    const text = productQuery.trim().toLowerCase();
    if (!entry || !text) return entry?.products || [];
    return entry.products.filter((product) => [product.product, ...product.components, ...product.cves.map((cve) => cve.cve)]
      .some((value) => String(value || "").toLowerCase().includes(text)));
  }, [entry, productQuery]);
  const current = ACTIONS.find((item) => item.id === action);

  function choose(name) {
    setSelected(name);
    setAction(null);
    setOpenProducts(new Set());
    setProductQuery("");
  }

  function toggle(name) {
    setOpenProducts((open) => {
      const next = new Set(open);
      if (next.has(name)) next.delete(name); else next.add(name);
      return next;
    });
  }

  return (
    <section className="delivery-workspace">
      <div className="results-heading">
        <div>
          <button className="back-link" onClick={onBack}><ChevronLeft size={17} /> Back</button>
          <span className="eyebrow">Delivery agent</span>
          <h1>Middleware delivery</h1>
          <p>Every middleware system in {sourceName ? <strong>{sourceName}</strong> : "the uploaded file"}, the products and
            components found under it, and their CVEs with the fix and servers.</p>
        </div>
        {onServerDelivery && (
          <div className="results-heading-side">
            <button type="button" className="button button-secondary" onClick={onServerDelivery}>
              <Server size={16} /> Server delivery
            </button>
          </div>
        )}
      </div>

      {failure && <div className="delivery-error"><AlertTriangle size={15} /> {failure}</div>}

      {loading && !data ? (
        <div className="delivery-loading"><LoaderCircle className="spin" size={20} /> Reading the file's middleware and fixes…</div>
      ) : data && !data.middlewares.length ? (
        <div className="empty-previous-fixes">The file has no grouped components.</div>
      ) : data && (
        <div className="delivery-layout">
          <nav className="delivery-servers" aria-label="Middleware systems">
            <span className="delivery-servers-title">Middleware ({data.middlewares.length})</span>
            {data.middlewares.length > 8 && (
              <label className="search-field delivery-server-search">
                <Search size={14} aria-hidden="true" />
                <input type="search" placeholder="Find a middleware…" value={query} aria-label="Find a middleware"
                  onChange={(event) => setQuery(event.target.value)} />
              </label>
            )}
            {shown.map((item) => (
              <button key={item.middleware} type="button"
                className={`delivery-server${item.middleware === selected ? " active" : ""}`}
                onClick={() => choose(item.middleware)}>
                <span className="delivery-server-name"><Layers size={14} /> {middlewareName(item.middleware)}</span>
                <span className="delivery-server-meta">
                  {plural(item.summary.products, "product")} · {plural(item.summary.cves, "CVE")} · {item.summary.with_fix} with fix
                </span>
              </button>
            ))}
          </nav>

          {entry && (
            <div className="delivery-main">
              <div className="delivery-summary">
                {[
                  { label: "Products", value: entry.summary.products },
                  { label: "Components", value: entry.summary.components },
                  { label: "CVEs", value: entry.summary.cves },
                  { label: "With a fix", value: entry.summary.with_fix, tone: "ready" },
                  { label: "Servers", value: entry.summary.servers },
                  { label: "Incompatible fixes", value: entry.summary.incompatible, tone: "blocked" },
                ].map((metric) => (
                  <div key={metric.label} className={`delivery-metric${metric.tone ? ` tone-${metric.tone}` : ""}`}>
                    <span>{metric.label}</span><strong>{metric.value}</strong>
                  </div>
                ))}
              </div>

              {!entry.assigned && (
                <p className="delivery-note delivery-unassigned">These rows name no application
                  (<code>Unspecified Application</code>), so they are listed together here.</p>
              )}

              <div className="mw-actions" role="group" aria-label="Delivery options">
                {ACTIONS.map((item) => {
                  const Icon = item.Icon;
                  return (
                    <button key={item.id} type="button" className={`mw-action${action === item.id ? " active" : ""}`}
                      aria-pressed={action === item.id} onClick={() => setAction(action === item.id ? null : item.id)}>
                      <Icon size={20} />
                      <strong>{item.title}</strong>
                      <small>{item.blurb}</small>
                      <span className="mw-action-tag">Placeholder</span>
                    </button>
                  );
                })}
              </div>

              {current && <ActionPlaceholder action={current} entry={entry} onClose={() => setAction(null)} />}

              <div className="mw-products-head">
                <h2><Package size={16} /> Products and components under {middlewareName(entry.middleware)}</h2>
                <div className="delivery-tools">
                  <label className="search-field">
                    <Search size={15} aria-hidden="true" />
                    <input type="search" placeholder="Product, component or CVE…" value={productQuery}
                      aria-label="Search products" onChange={(event) => setProductQuery(event.target.value)} />
                    {productQuery && <button type="button" aria-label="Clear search" onClick={() => setProductQuery("")}><X size={13} /></button>}
                  </label>
                  <button type="button" className="button button-ghost button-small"
                    onClick={() => setOpenProducts(openProducts.size ? new Set() : new Set(products.map((p) => p.product)))}>
                    {openProducts.size ? "Collapse all" : "Expand all"}
                  </button>
                </div>
              </div>
              {products.length ? products.map((product) => (
                <ProductRow key={product.product} product={product} open={openProducts.has(product.product)}
                  onToggle={() => toggle(product.product)} onOpenCard={onOpenCard} />
              )) : <div className="empty-previous-fixes">No product matches “{productQuery}”.</div>}
            </div>
          )}
        </div>
      )}
    </section>
  );
}
