import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  Check,
  ChevronLeft,
  CircleCheckBig,
  Clock,
  Database,
  Download,
  ExternalLink,
  Eye,
  FileSpreadsheet,
  Flag,
  History,
  Info,
  Layers3,
  ListFilter,
  LoaderCircle,
  Play,
  Plug,
  RefreshCw,
  Search,
  ShieldCheck,
  UploadCloud,
  Wrench,
  X,
} from "lucide-react";
import { combineRemediationRuns, mergeRemediationRuns } from "./remediationResults.js";
import { distinctValues, filterRows } from "./tableFilters.js";

const PAGE_SIZE = 10;
const ENRICHMENT_TIMEOUT_MS = 30 * 60 * 1000;
const WORKFLOW_STAGES = [
  { id: "route", title: "Orchestrator", description: "Choose the evidence route for this CVE." },
  { id: "vendor_evidence", title: "MCP evidence sources", description: "Check matching vendor and host OS adapters." },
  { id: "internet_lookup", title: "Internet lookup", description: "Search and validate pages when publisher evidence is missing." },
  { id: "assess", title: "Remediation engine", description: "Assess the collected evidence and host context." },
  { id: "compatibility", title: "Compatibility check", description: "Check the proposed fix against the full host inventory." },
];

const MAIN_VERDICTS = [
  { id: "FIX_AVAILABLE", label: "Fix available" },
  { id: "NEEDS_INPUT", label: "Needs input" },
  { id: "NOT_APPLICABLE", label: "Not applicable" },
  { id: "ASSESSMENT_LIMITED", label: "Assessment limited" },
];

function humanize(value) {
  return String(value || "Unknown").replaceAll("_", " ");
}

function stageDetail(id, event) {
  if (event.status === "failed") return event.reason || "This stage failed.";
  if (event.status === "skipped") {
    return event.reason || (id === "vendor_evidence"
      ? "No matching publisher adapter was selected." : "This branch was not needed.");
  }
  if (id === "route" && event.route) {
    return event.route === "vendor_evidence"
      ? `Publisher route selected${event.vendor ? `: ${event.vendor}` : ""}.`
      : "Direct internet lookup route selected.";
  }
  if (id === "vendor_evidence" && event.status === "completed") {
    const sources = event.sources?.length ? event.sources.join(", ") : "Configured adapters";
    return `${sources}: ${event.evidence_count || 0} evidence record(s).`;
  }
  if (id === "internet_lookup" && event.status === "completed") {
    return `${humanize(event.lookup_status)} · ${event.sources?.length || 0} page(s) reviewed.`;
  }
  if (id === "assess" && event.status === "completed") {
    if (event.assessment_limited) return event.assessment_limit_reason === "validation"
      ? "Model response failed evidence validation; source evidence is retained for review."
      : "Model limit reached; source evidence is retained for review.";
    return event.verdict ? `Verdict: ${humanize(event.verdict)}` : "Assessment complete.";
  }
  if (id === "compatibility" && event.status === "completed") {
    return `${event.host ? `${event.host}: ` : ""}${humanize(event.compatibility_status)}`;
  }
  if (event.status === "running") {
    return id === "vendor_evidence" ? `Calling ${event.vendor || "publisher"} evidence adapters…`
      : id === "internet_lookup" ? "Searching and checking source pages…"
      : id === "assess" ? (event.evidence_count != null
        ? `Model is assessing ${event.evidence_count} evidence record(s)…` : "Evaluating fixes and applicability…")
      : id === "compatibility" ? "Checking versions, ownership and runtimes on the host…" : "Selecting the route…";
  }
  return WORKFLOW_STAGES.find((stage) => stage.id === id)?.description;
}

const STAGE_TITLES = Object.fromEntries(WORKFLOW_STAGES.map((stage) => [stage.id, stage.title]));

function formatNumber(value) {
  return Number(value || 0).toLocaleString();
}

function useNow(active) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!active) return undefined;
    setNow(Date.now());
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [active]);
  return now;
}

function elapsed(from, to) {
  const start = Date.parse(from || "");
  if (!Number.isFinite(start)) return "";
  const seconds = Math.max(0, Math.round((to - start) / 1000));
  return seconds < 60 ? `${seconds}s` : `${Math.floor(seconds / 60)}m ${String(seconds % 60).padStart(2, "0")}s`;
}

function clockTime(value) {
  const time = Date.parse(value || "");
  return Number.isFinite(time)
    ? new Date(time).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "";
}

// One line of the live agent feed: icon, tone, title and detail for an activity event.
function describeActivity(event) {
  if (event.kind === "source") {
    const took = event.seconds != null ? ` · ${event.seconds}s` : "";
    return {
      Icon: Plug, tone: event.status === "failed" ? "failed" : event.status === "running" ? "running" : "source",
      title: `${event.source} ${event.source === "CVE.org record" ? "lookup" : "adapter"}`,
      detail: event.status === "running" ? "Calling…"
        : event.status === "failed" ? `Failed${event.error ? `: ${event.error}` : ""}${took}`
          : `${event.evidence_count ?? "Record"}${event.evidence_count != null ? " evidence record(s)" : " fetched"}${took}`,
    };
  }
  if (event.kind === "latest_releases") {
    return {
      Icon: Search, tone: "source", title: "Latest release lookup",
      detail: event.evidence_count ? `Newest on branch: ${(event.versions || []).join(", ")}` : "No newer release record.",
    };
  }
  if (event.kind === "item") {
    return {
      Icon: Flag, tone: event.status === "failed" ? "failed" : event.status === "running" ? "start" : "done",
      title: event.status === "running" ? `Started ${event.cve}` : `Finished ${event.cve}`,
      detail: event.status === "running"
        ? `${event.product || ""}${event.component ? ` · ${event.component}` : ""} · ${event.index} of ${event.total}`
        : event.error || (event.verdict ? `Verdict: ${humanize(event.verdict)}` : humanize(event.status)),
    };
  }
  return {
    Icon: Activity, tone: event.status === "failed" ? "failed" : event.status === "running" ? "running" : "stage",
    title: `${STAGE_TITLES[event.stage] || humanize(event.stage)} · ${humanize(event.status)}`,
    detail: stageDetail(event.stage, event),
  };
}

const FEED_FILTERS = [
  { id: "all", label: "All" },
  { id: "source", label: "Adapters" },
  { id: "stage", label: "Stages" },
];

function ActivityFeed({ activity, live }) {
  const [filter, setFilter] = useState("all");
  const entries = useMemo(() => {
    // LLM calls and token counts stay in workflow_progress.json for reference only.
    const list = (activity || []).filter((event) => event.kind !== "model");
    // A "running" line is replaced by its result once that arrives, so only work
    // that is still in progress shows as running.
    const sameStep = (a, b) => a.cve === b.cve && a.kind === b.kind
      && (a.kind === "source" ? a.source === b.source : a.stage === b.stage);
    const visible = list.filter((event, position) => !(
      (event.kind === "source" || event.kind === "stage") && event.status === "running"
      && list.slice(position + 1).some((later) => sameStep(later, event))));
    return visible
      .filter((event) => filter === "all" || event.kind === filter
        || (filter === "source" && event.kind === "latest_releases")
        || (filter === "stage" && event.kind === "item"))
      .reverse();
  }, [activity, filter]);

  return (
    <section className="activity-feed" aria-label="Live agent calls">
      <div className="activity-feed-heading">
        <div>
          <strong><Activity size={15} /> Agent calls</strong>
          <span>{live ? "Updating live as each stage and evidence source call completes." : "Recorded activity for this run."}</span>
        </div>
        <div className="segmented" role="tablist" aria-label="Filter agent calls">
          {FEED_FILTERS.map((option) => (
            <button key={option.id} role="tab" aria-selected={filter === option.id}
              className={filter === option.id ? "active" : ""} onClick={() => setFilter(option.id)}>
              {option.label}
            </button>
          ))}
        </div>
      </div>
      {entries.length ? (
        <ol className="activity-list">
          {entries.map((event, position) => {
            const view = describeActivity(event);
            const Icon = view.Icon;
            return (
              <li key={`${event.at}-${position}`} className={`activity-item activity-${view.tone}`}>
                <span className="activity-icon">
                  {view.tone === "running" ? <LoaderCircle className="spin" size={14} /> : <Icon size={14} />}
                </span>
                <div className="activity-copy">
                  <div><strong>{view.title}</strong>{event.cve && event.kind !== "item" && <code>{event.cve}</code>}</div>
                  <p>{view.detail}</p>
                </div>
                <time dateTime={event.at}>{clockTime(event.at)}</time>
              </li>
            );
          })}
        </ol>
      ) : (
        <p className="activity-empty">
          {activity?.length ? "No calls match this filter yet." : live ? "Waiting for the first agent call…"
            : "This run did not record agent calls (runs from before this view was added)."}
        </p>
      )}
    </section>
  );
}

function WorkflowView({ run }) {
  const progress = run?.workflow_progress;
  const current = progress?.current;
  const stages = progress?.stages || {};
  const total = progress?.total || run?.selected_count || 0;
  const completed = progress?.completed || 0;
  const percent = total ? Math.round((completed / total) * 100) : 0;
  const live = ["queued", "running"].includes(run?.status);
  const now = useNow(live);
  const totals = progress?.totals;
  const runStart = run?.started_at || run?.created_at;

  return (
    <section className={`workflow-view ${live ? "is-live" : ""}`} aria-label="Remediation workflow progress">
      <div className="workflow-heading">
        <div>
          <span className="eyebrow">{live ? <><span className="live-dot" /> Live orchestrator workflow</> : "Orchestrator workflow"}</span>
          <h2>{current ? `${current.cve} · ${current.component || current.product}` : "Preparing selected CVEs"}</h2>
          <p>{current ? `${current.product} · CVE ${current.index} of ${total}`
            : "The evidence route will appear as soon as processing starts."}</p>
        </div>
        <strong>{completed} / {total} processed</strong>
      </div>
      <div className="workflow-stats">
        <div><span><Plug size={13} /> Adapter calls</span><strong>{totals ? formatNumber(totals.source_calls) : "–"}</strong></div>
        <div><span><Clock size={13} /> Elapsed</span><strong>{live
          ? elapsed(runStart, now) || "–"
          : run?.completed_at ? elapsed(runStart, Date.parse(run.completed_at)) || "–" : "–"}</strong></div>
      </div>
      <div className="workflow-meter" role="progressbar" aria-valuenow={completed} aria-valuemin={0}
        aria-valuemax={total || 1} aria-label="CVEs processed">
        <span style={{ width: `${percent}%` }} />
      </div>
      <ol className="workflow-steps">
        {WORKFLOW_STAGES.map((stage, index) => {
          const event = stages[stage.id] || { status: "pending" };
          return (
            <li className={`workflow-step workflow-step-${event.status}`} key={stage.id}>
              <div className="workflow-marker">
                {event.status === "running" ? <LoaderCircle className="spin" size={17} />
                  : event.status === "completed" ? <Check size={17} />
                    : event.status === "failed" ? <AlertTriangle size={17} /> : index + 1}
              </div>
              <div className="workflow-step-copy">
                <div>
                  <strong>{stage.title}</strong>
                  <span>{humanize(event.status)}{event.status === "running" && live && event.at
                    ? ` · ${elapsed(event.at, now)}` : ""}</span>
                </div>
                <p>{stageDetail(stage.id, event)}</p>
                {stage.id === "internet_lookup" && <small>Runs only when the evidence route needs it.</small>}
              </div>
            </li>
          );
        })}
      </ol>
      <ActivityFeed activity={progress?.activity} live={live} />
    </section>
  );
}

function uniqueLookupSources(sources = []) {
  const pages = new Map();
  for (const source of sources) {
    const url = String(source.url || "").trim();
    if (!url) continue;
    const previous = pages.get(url);
    if (!previous || (source.validated && !previous.validated) ||
        (source.validated === previous.validated && source.fetched && !previous.fetched)) {
      pages.set(url, source);
    }
  }
  return [...pages.values()];
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

const LATEST_VERDICTS = { SUITABLE: "Suitable", NOT_SUITABLE: "Not suitable", UNVERIFIED: "Unverified" };

function LatestRelease({ latest, check }) {
  // The newest release on the fix's branch: the agent's verdict, then the host compatibility check.
  if (!latest) return null;
  return (
    <div className={`latest-release latest-${String(latest.verdict).toLowerCase()}`}>
      <div>
        <span>Latest release on this branch</span>
        <strong>{latest.version}</strong>
        <em>{LATEST_VERDICTS[latest.verdict] || humanize(latest.verdict)}</em>
      </div>
      <p>{latest.reason}</p>
      {check && (
        <p className="latest-check">
          Host check: <strong>{humanize(check.status)}</strong>
          {(() => {
            const flagged = (check.checks || []).find((item) => item.status === "FAIL")
              || (check.checks || []).find((item) => item.status === "WARN" || item.status === "UNKNOWN");
            return flagged ? ` (${flagged.detail.split(". ")[0]})` : "";
          })()}
        </p>
      )}
    </div>
  );
}

function RemedyCard({ remedy, sources, recommended = false, installations = [], compatibility = null }) {
  if (!remedy) return null;
  // Name the copy this fix is for, with its installed version, and say when the
  // application does not use it (the header above describes the copy it does use).
  const copy = installations?.find((entry) => entry.installation === remedy.installation);
  const appCopy = installations?.find((entry) => entry.used_by_application === true);
  const otherCopy = Boolean(recommended && appCopy && copy && copy !== appCopy);
  const identifier = remedy.target_version || remedy.patch_id;
  const claims = [
    ...(remedy.fix_support || []),
    ...(remedy.applicability_support || []),
    ...(remedy.compatibility_support || []),
    ...(remedy.latest_release?.support || []),
  ];
  const latestCheck = (compatibility?.evaluations || []).find((evaluation) =>
    evaluation.role === "latest" && evaluation.latest_of === identifier);
  return (
    <article className={`remedy-card ${recommended ? "is-recommended" : ""}`}>
      <div className="remedy-card-heading">
        <div>
          <span>{otherCopy ? "Fix for another installed copy" : recommended ? "Recommended remediation" : humanize(remedy.route)}</span>
          <h4>{identifier || humanize(remedy.route)}</h4>
          {remedy.latest_release && identifier && <small className="first-fix-label">First fixed release</small>}
        </div>
        <span className={`compatibility compatibility-${String(remedy.compatibility).toLowerCase()}`}>
          {humanize(remedy.compatibility)}
        </span>
      </div>
      {remedy.installation && (
        <p className="remedy-installation">
          For {remedy.installation}
          {copy?.installed_version ? ` (installed ${copy.installed_version})` : ""}
          {copy?.used_by_application === false ? ", not used by the application" : ""}
        </p>
      )}
      {otherCopy && (
        <p className="validation-note">
          <AlertTriangle size={14} /> The copy the application uses ({appCopy.installation}, {appCopy.installed_version || "version not captured"})
          gets no fix here (not affected, or no evidence-backed fix); the assessment notes say which.
        </p>
      )}
      <p>{remedy.summary}</p>
      <LatestRelease latest={remedy.latest_release} check={latestCheck} />
      <details>
        <summary>Supporting evidence ({claims.length})</summary>
        <ClaimList claims={claims} sources={sources} />
      </details>
    </article>
  );
}

function InstallationFixes({ installations }) {
  if (!installations || installations.length < 2) return null;
  return (
    <section className="candidate-section installation-fixes">
      <h3>Fix per installation</h3>
      <p>Every installed copy of this product on the host, assessed together.</p>
      <div className="table-shell">
        <table>
          <thead>
            <tr><th>Installation</th><th>Installed version</th><th>Used by application</th><th>Fix</th></tr>
          </thead>
          <tbody>
            {installations.map((entry) => (
              <tr key={entry.installation}>
                <td>{entry.installation}</td>
                <td>{entry.installed_version || "Not captured"}</td>
                <td>{entry.used_by_application === true ? "Yes" : entry.used_by_application === false ? "No" : "Unknown"}</td>
                <td>
                  {entry.fixes?.length
                    ? entry.fixes.map((fix) => (fix.target_version || fix.patch_id || humanize(fix.route))
                        + (fix.latest_release ? ` (latest ${fix.latest_release.version}: `
                          + `${LATEST_VERDICTS[fix.latest_release.verdict] || fix.latest_release.verdict})` : "")).join(", ")
                    : "No evidence-backed fix (see notes)"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
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

function SourceFixesSection({ groups, compatibility }) {
  // Every fix the evidence reports, one card per publisher (IBM first): an IBM fileset fix and
  // a separate upstream / Toolbox / distribution fix are both shown.
  if (!groups?.length) return null;
  const hasIbm = groups.some((group) => group.is_ibm);
  const hasOther = groups.some((group) => !group.is_ibm);
  return (
    <section className="candidate-section source-fixes-by-source">
      <h3>Fixes reported by each source ({groups.length})</h3>
       <p>{hasIbm && hasOther
         ? "These options target different copies or release lines. An AIX base fileset update does not update an AIX Toolbox RPM. Check each option's scope and compatibility before choosing."
         : "These are source-reported options. Check each option's scope and compatibility before choosing."}</p>
      <div className="source-fix-grid">
        {groups.map((group) => (
           <SourceFixCard key={group.source} title={group.is_ibm ? "IBM" : group.source}
             fixes={group.fixes} compatibility={compatibility} />
        ))}
      </div>
    </section>
  );
}

function SourceFixCard({ title, fixes, compatibility }) {
  return (
    <div className="source-fix-card">
      <h4>{title}</h4>
      <ul>
        {fixes.map((fix) => (
          <li key={fix.evidence_ids.join("-")}>
            <div className="source-fix-heading">
              <strong>{fix.identifier}</strong>
              <span>{fix.identifier_kind}</span>
            </div>
            <p>{[fix.source, fix.product, fix.component].filter(Boolean).join(" · ")}</p>
             {fix.target_scope && <p>Targets: {fix.target_scope}</p>}
             {fix.caution && <p className="validation-note"><AlertTriangle size={14} /> {fix.caution}</p>}
             {(() => {
               const evaluation = (compatibility?.evaluations || []).find((entry) =>
                 entry.target === fix.identifier && entry.evidence_id && fix.evidence_ids?.includes(entry.evidence_id));
               return evaluation ? <p>Host check: {humanize(evaluation.status)}</p> : null;
             })()}
            {fix.releases?.length > 0 && <p>Release: {fix.releases.join(", ")}</p>}
            {fix.packages?.length > 0 && (
              <p>Packages: {fix.packages.slice(0, 4).join(", ")}{fix.packages.length > 4 ? ` and ${fix.packages.length - 4} more` : ""}</p>
            )}
            <div className="source-fix-footer">
              <span>{fix.evidence_ids.join(", ")}</span>
              {fix.url && /^https?:\/\//.test(fix.url) && (
                <a href={fix.url} target="_blank" rel="noreferrer">
                  View source <ExternalLink size={12} />
                </a>
              )}
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}

const COMPATIBILITY_ROLES = {
  recommended: "Recommended fix", candidate: "Alternative", source_lead: "Source lead", proposal: "Proposed fix",
  latest: "Latest release",
};

function CompatibilityRuleRequest({ compatibility, result, onChecked }) {
  const [sourceUrl, setSourceUrl] = useState("");
  const [ruleText, setRuleText] = useState("");
  const [draft, setDraft] = useState(null);
  const [ruleBusy, setRuleBusy] = useState(false);
  const [ruleMessage, setRuleMessage] = useState("");
  const evaluations = compatibility?.evaluations || [];
  const missingRules = compatibility?.rule_request
    || evaluations.find((entry) => entry.model_judgment?.validation === "no_rules")
    || (compatibility?.status === "UNVERIFIED" ? evaluations[0] : null)
    || (compatibility?.status === "COMPATIBLE_WITH_WARNINGS"
      ? evaluations.find((entry) => !entry.model_judgment &&
        entry.checks?.some((check) => check.id === "application_support" && check.status === "WARN"))
      : null)
    || (compatibility === result.compatibility
      && result.recommended_remediation?.compatibility === "UNVERIFIED"
      && !result.recommended_remediation.compatibility_support?.length
      && result.applications?.length
      ? { product: result.product, target_version: result.recommended_remediation.target_version,
        application: result.applications[0], application_version: result.application_version }
      : null);

  async function readRuleResponse(response, action) {
    const body = await response.text();
    let data;
    try { data = JSON.parse(body); }
    catch { throw new Error(`${action} returned HTTP ${response.status} without JSON. Check the API server logs.`); }
    if (!response.ok) throw new Error(data.error || `${action} failed (HTTP ${response.status}).`);
    return data;
  }

  async function draftNewRule(event) {
    event.preventDefault();
    setRuleBusy(true); setRuleMessage(""); setDraft(null);
    try {
      const response = await fetch("/api/compatibility/rules/draft", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ cve: result.cve, product: missingRules.product || result.product || result.component,
          application: missingRules.application || result.applications?.[0] || "",
          application_version: missingRules.application_version || result.application_version || "",
          target_version: missingRules.target_version || missingRules.target || "",
          source_url: sourceUrl, rule_text: ruleText }),
      });
      const data = await readRuleResponse(response, "Rule draft");
      setDraft(data);
    } catch (error) { setRuleMessage(error.message); }
    finally { setRuleBusy(false); }
  }

  async function applyNewRule() {
    setRuleBusy(true); setRuleMessage("");
    try {
      const savedResponse = await fetch(`/api/compatibility/rules/${draft.draft_id}/apply`, { method: "POST" });
      await readRuleResponse(savedResponse, "Rule save");
      setDraft(null);
      setRuleMessage("Rule saved. Rechecking this CVE against the updated knowledge…");
      const response = await fetch("/api/compatibility/recheck", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ run_id: result.run_id, cve: result.cve, component_id: result.component_id }),
      });
      const data = await readRuleResponse(response, "Compatibility recheck");
      onChecked(data.compatibility);
      setRuleMessage("Rule saved and compatibility rechecked. The original run record is unchanged.");
    } catch (error) { setRuleMessage(error.message); }
    finally { setRuleBusy(false); }
  }
  if (!missingRules) return null;
  return (
        <div className="compatibility-eval knowledge-gap">
          <strong>Compatibility rules needed for {missingRules.product || result.product || result.component}</strong>
          <p>Provide an approved publisher HTTPS page or paste a compatibility rule. A small model call will draft one rule for review.</p>
          <form onSubmit={draftNewRule}>
            <label>Source URL <input type="url" value={sourceUrl} onChange={(event) => setSourceUrl(event.target.value)}
              placeholder="https://publisher.example/support" /></label>
            <label>Compatibility rule text <textarea value={ruleText} onChange={(event) => setRuleText(event.target.value)}
              placeholder="Paste the exact vendor statement or the rule you want checked" /></label>
            <button className="button button-secondary" disabled={ruleBusy || (!sourceUrl.trim() && !ruleText.trim())}>
              {ruleBusy ? "Working…" : "Draft rule"}</button>
          </form>
          {draft && (
            <div>
              <p><strong>Review extracted rule before saving</strong></p>
              <p>{draft.proposal.kind === "requirement"
                ? `${draft.proposal.product} ${draft.proposal.when} requires ${draft.proposal.runtime || draft.proposal.component} ${draft.proposal.spec}.`
                : draft.proposal.kind === "application_support"
                  ? `${draft.proposal.application} ${draft.proposal.when} supports ${draft.proposal.product} ${draft.proposal.versions.join(", ")}.`
                  : `${draft.proposal.product}: behaviour change since ${draft.proposal.since}.`}</p>
              <blockquote>{draft.proposal.quote}</blockquote>
              <p>Source: {draft.proposal.source}. This rule is not in the knowledge base yet.</p>
              <details><summary>Full rule fields</summary><pre>{JSON.stringify(draft.proposal, null, 2)}</pre></details>
              <button type="button" className="button button-primary" disabled={ruleBusy} onClick={applyNewRule}>
                Save rule and recheck</button>
            </div>
          )}
          {ruleMessage && <p role="status">{ruleMessage}</p>}
        </div>
  );
}

function CompatibilitySection({ compatibility }) {
  if (!compatibility) return null;
  const evaluations = compatibility.evaluations || [];
  return (
    <section className="compatibility-section">
      <div className="result-title-row">
        <h3>Compatibility check</h3>
        <span className={`compatibility compatibility-${String(compatibility.status).toLowerCase()}`}>
          {humanize(compatibility.status)}
        </span>
      </div>
      <p>{compatibility.error || compatibility.summary}
        {compatibility.host ? ` Host: ${compatibility.host}.` : ""}
        {compatibility.computed_after_run ? " Checked against the current inventory after this run." : ""}</p>
      {evaluations.map((evaluation, index) => {
        const flagged = (evaluation.checks || []).filter((check) => check.status !== "PASS");
        const passed = (evaluation.checks || []).length - flagged.length;
        return (
          <article className="compatibility-eval" key={`${evaluation.role}-${evaluation.target}-${index}`}>
            <div className="compatibility-eval-heading">
              <div>
                <strong>{COMPATIBILITY_ROLES[evaluation.role] || humanize(evaluation.role)}: {evaluation.target || "no target"}</strong>
                <small>{evaluation.component} · installed {evaluation.installed_version || "unknown"} · {humanize(evaluation.ownership)}</small>
              </div>
              <span className={`compatibility compatibility-${String(evaluation.status).toLowerCase()}`}>
                {humanize(evaluation.status)}
              </span>
            </div>
            <ul className="compatibility-checks">
              {flagged.map((check) => (
                <li key={check.id + check.detail}>
                  <span className={`check-${check.status.toLowerCase()}`}>{check.status}</span>
                  <div><strong>{humanize(check.id)}:</strong> {check.detail}</div>
                </li>
              ))}
              {passed > 0 && <li><span className="check-pass">PASS</span><div>{passed} other check(s) passed.</div></li>}
            </ul>
            {evaluation.model_judgment && (
              <details>
                <summary>Model judgment: {evaluation.model_judgment.validation === "accepted"
                  ? humanize(evaluation.model_judgment.model_status)
                  : evaluation.model_judgment.validation === "no_rules"
                    ? "no matching knowledge rule"
                    : "rejected; inventory checks retained"}</summary>
                {evaluation.model_judgment.validation === "accepted" ? (
                  <>
                    <p>Rule and fact references were checked. Final status: {humanize(evaluation.model_judgment.status)}.</p>
                    <ul>
                      {(evaluation.model_judgment.cited_rules || []).map((rule) => (
                        <li key={rule.id}>{rule.id}: {typeof rule.value === "string"
                          ? rule.value : JSON.stringify(rule.value)}{rule.source && /^https?:\/\//.test(rule.source)
                          ? <> · <a href={rule.source} target="_blank" rel="noreferrer">Source</a></> : null}</li>
                      ))}
                      {(evaluation.model_judgment.cited_facts || []).filter((fact) =>
                        ["installed_version", "target_version"].includes(fact.id)).map((fact) => (
                        <li key={fact.id}>{humanize(fact.id)}: {String(fact.value)}</li>
                      ))}
                    </ul>
                  </>
                ) : <p>{evaluation.model_judgment.reason}</p>}
              </details>
            )}
            <GuidanceList title="Required actions" items={evaluation.required_actions} tone="warning" />
            {!!evaluation.verification_commands?.length && (
              <details>
                <summary>Read-only verification commands ({evaluation.verification_commands.length})</summary>
                <GuidanceList title="Run on the host to confirm" items={evaluation.verification_commands} />
              </details>
            )}
          </article>
        );
      })}
    </section>
  );
}

function RemediationResultCard({ result }) {
  const [currentCompatibility, setCurrentCompatibility] = useState(result.compatibility);
  useEffect(() => { setCurrentCompatibility(result.compatibility); }, [result.compatibility]);
  const lookupSources = uniqueLookupSources(result.lookup_sources);
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
            {result.run_id && <span>Run {result.run_id}</span>}
            {result.component_id && <span>Component ID {result.component_id}</span>}
            {context.filter(Boolean).map((item, index) => <span key={`${item}-${index}`}>{item}</span>)}
          </div>
        </div>
      </header>

      <dl className="result-metadata">
        <div><dt>Affected component</dt><dd>{result.component || "Unknown"}</dd></div>
        <div><dt>Component version</dt><dd>{result.component_version || "Unknown"}</dd></div>
        <div><dt>Application</dt><dd>{result.applications?.join(" | ") || "Unknown"}</dd></div>
        <div><dt>Application version</dt><dd>{result.application_version || "Unknown"}</dd></div>
        <div><dt>Application path</dt><dd>{result.application_install_path || "Unknown"}</dd></div>
        <div><dt>Component path</dt><dd>{result.component_path || "Unknown"}</dd></div>
      </dl>

      {!result.recommended_remediation && result.primary_source_fix && (
        <section className="source-fix-section">
          <h3>Most relevant source-reported fix</h3>
          <p>{result.primary_source_fix.match_scope === "host"
            ? "This fix matches the AIX host level. Its link to the recorded component is unverified; confirm package ownership and compatibility before applying it."
            : result.primary_source_fix.match_scope === "component"
              ? "This source fix matches the recorded component. Verify package ownership and compatibility before applying it."
              : "This is a source-reported fix lead. Verify its match to this installation before applying it."}</p>
          {(() => {
            const rejected = (result.compatibility?.evaluations || []).find((evaluation) =>
              evaluation.target === result.primary_source_fix.identifier && evaluation.status === "INCOMPATIBLE");
            const reason = rejected?.checks?.find((check) => check.status === "FAIL");
            return rejected ? (
              <p className="validation-note"><AlertTriangle size={14} /> The compatibility check rejects this lead
                for this host: {reason?.detail}</p>
            ) : null;
          })()}
          <div className="source-fix-grid">
            <SourceFixCard
              title={result.primary_source_fix.source || "Source"}
              fixes={[{
                ...result.primary_source_fix,
                releases: result.primary_source_fix.release ? [result.primary_source_fix.release] : [],
                evidence_ids: [result.primary_source_fix.evidence_id],
              }]}
            />
          </div>
        </section>
      )}

      {result.error ? (
        <section className="result-error"><AlertTriangle size={18} /><span>{result.error}</span></section>
      ) : (
        <>
          <section className="assessment-summary">
            <h3>Assessment</h3>
            <p>{result.assessment_summary || "No assessment summary was returned."}</p>
            {result.assessment_limited && (
              <p className="validation-note">
                <Info size={14} /> {result.assessment_limit_reason === "validation"
                  ? ({ unsupported_citation: "The model cited text that was not in its evidence record.",
                       invalid_schema: "The model response did not match the required assessment format.",
                       uncited_fix_identifier: "The selected fix identifier was absent from its cited quote." }
                      [result.validation_failure] || "The model response failed evidence validation.")
                  : "The per-CVE model limit stopped the assessment."} Any fix shown above is a source lead, not a validated recommendation.
              </p>
            )}
          </section>

          {result.recommended_remediation && (
            <RemedyCard remedy={result.recommended_remediation} sources={result.evidence_sources} recommended
              installations={result.installation_fixes} compatibility={currentCompatibility} />
          )}

          <CompatibilityRuleRequest compatibility={currentCompatibility} result={result}
            onChecked={setCurrentCompatibility} />

          <InstallationFixes installations={result.installation_fixes} />

           <SourceFixesSection groups={result.fixes_by_source} compatibility={currentCompatibility} />

          {(() => {
            // Fixes for the other installed copies are shown open; anything else stays an option.
            const primary = result.recommended_remediation?.installation;
            const candidates = result.candidate_remediations || [];
            const perCopy = candidates.filter((remedy) => remedy.installation && remedy.installation !== primary);
            const options = candidates.filter((remedy) => !perCopy.includes(remedy));
            return (
              <>
                {!!perCopy.length && (
                  <section className="candidate-section">
                    <h3>Fixes for the other installations ({perCopy.length})</h3>
                    <p>Each installed copy needs its own fix on its own release branch.</p>
                    <div className="remedy-grid">
                      {perCopy.map((remedy, index) => (
                        <RemedyCard key={index} remedy={remedy} sources={result.evidence_sources}
                          installations={result.installation_fixes} compatibility={currentCompatibility} />
                      ))}
                    </div>
                  </section>
                )}
                {!!options.length && (
                  <details className="candidate-section">
                    <summary>Other conditional remediation options ({options.length})</summary>
                    <p>Confirm compatibility and the missing inventory details before selecting one of these options.</p>
                    <div className="remedy-grid">
                      {options.map((remedy, index) => (
                        <RemedyCard key={index} remedy={remedy} sources={result.evidence_sources}
                          installations={result.installation_fixes} compatibility={currentCompatibility} />
                      ))}
                    </div>
                  </details>
                )}
              </>
            );
          })()}

          {currentCompatibility?.status !== "AWAITING_RULES" &&
            <CompatibilitySection compatibility={currentCompatibility} />}

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

      <details className="result-details">
        <summary>Collected evidence ({result.evidence_records?.length || 0})</summary>
        <p className="validation-note">
          {result.evidence_route === "internet_lookup" ? "Internet lookup" : "Configured vendor sources"}
          {result.evidence_searched_sources?.length > 0 &&
            `: ${result.evidence_searched_sources.join(", ")}`}
        </p>
        {result.evidence_records?.length > 0 ? (
          <div className="claim-list">
            {result.evidence_records.map((record) => (
              <blockquote key={record.evidence_id}>
                <p>{record.verbatim_excerpt || record.remediation || record.notes || "Source record"}</p>
                <footer>
                  <span>{record.evidence_id}</span>
                  {record.fixed_version && <span>Fixed version: {record.fixed_version}</span>}
                  {record.evidence_kind === "interim_fix" && record.advisory &&
                    <span>Interim fix: {record.advisory}</span>}
                  {record.product && <span>{record.product}</span>}
                  {record.url && /^https?:\/\//.test(record.url) ? (
                    <a href={record.url} target="_blank" rel="noreferrer">
                      {record.source || "Evidence source"} <ExternalLink size={12} />
                    </a>
                  ) : <span>{record.source || "Evidence source"}</span>}
                </footer>
              </blockquote>
            ))}
          </div>
        ) : <p>No verified evidence records were returned by the searched source.</p>}
        {result.evidence_notes?.length > 0 &&
          <GuidanceList title="Source notes" items={result.evidence_notes} tone="info" />}
        {result.evidence_errors?.length > 0 &&
          <GuidanceList title="Source errors" items={result.evidence_errors.map(
            (entry) => `${entry.source}: ${entry.error}`)} tone="warning" />}
        {lookupSources.length > 0 && (
          <details className="result-details">
            <summary>Internet lookup pages ({lookupSources.length})</summary>
            <div className="claim-list">
              {lookupSources.map((source) => (
                <blockquote key={source.url}>
                  <p>{source.note || (source.validated ? "Validated source" : "Source not validated")}</p>
                  <footer>
                    <span>{source.validated ? "Validated" : "Unverified"}</span>
                    {source.url && /^https?:\/\//.test(source.url) && (
                      <a href={source.url} target="_blank" rel="noreferrer">
                        {source.url} <ExternalLink size={12} />
                      </a>
                    )}
                  </footer>
                </blockquote>
              ))}
            </div>
          </details>
        )}
      </details>
    </article>
  );
}

const FILTER_MODES = [
  { id: "contains", label: "contains" },
  { id: "equals", label: "is" },
  { id: "not_empty", label: "has a value" },
  { id: "empty", label: "is empty" },
];

let filterSequence = 0;

// Search across every column plus any number of per-column filters.
function useTableFilter(columns, rows, extra = null) {
  const [query, setQuery] = useState("");
  const [filters, setFilters] = useState([]);
  const entries = useMemo(
    () => filterRows(rows, columns, { query, filters, extra }),
    [rows, columns, query, filters, extra],
  );
  return { query, setQuery, filters, setFilters, entries };
}

function FilterBar({ columns, rows, state, total, children, extraActive = false, onClearExtra }) {
  const { query, setQuery, filters, setFilters, entries } = state;
  const choices = useMemo(() => Object.fromEntries(
    columns.map((column) => [column, distinctValues(rows, column)])), [columns, rows]);
  const active = Boolean(query.trim()) || filters.length > 0 || extraActive;

  function addFilter() {
    filterSequence += 1;
    setFilters((current) => [...current, { id: filterSequence, column: columns[0], mode: "contains", value: "" }]);
  }

  function update(id, change) {
    setFilters((current) => current.map((filter) => {
      if (filter.id !== id) return filter;
      const next = { ...filter, ...change };
      // A new column's value list differs, so start that filter's value again.
      if (change.column && change.column !== filter.column) next.value = "";
      if (change.mode === "equals" && !choices[next.column]) next.mode = "contains";
      return next;
    }));
  }

  return (
    <div className="filter-bar">
      <div className="filter-bar-row">
        <label className="search-field">
          <Search size={16} aria-hidden="true" />
          <input
            type="search"
            placeholder="Search every column…"
            aria-label="Search every column"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
          />
          {query && (
            <button type="button" aria-label="Clear search" onClick={() => setQuery("")}><X size={14} /></button>
          )}
        </label>
        <button type="button" className="button button-secondary button-small" onClick={addFilter}
          disabled={!columns.length}>
          <ListFilter size={15} /> Add column filter
        </button>
        {children}
        <span className="filter-count">
          {active ? <><strong>{entries.length}</strong> of {total} shown</> : <>{total} rows</>}
        </span>
        {active && (
          <button type="button" className="button button-ghost button-small" onClick={() => {
            setQuery("");
            setFilters([]);
            onClearExtra?.();
          }}>
            Clear filters
          </button>
        )}
      </div>
      {filters.length > 0 && (
        <div className="filter-chips">
          {filters.map((filter) => {
            const values = choices[filter.column];
            const needsValue = filter.mode === "contains" || filter.mode === "equals";
            return (
              <div className="filter-chip" key={filter.id}>
                <select aria-label="Filter column" value={filter.column}
                  onChange={(event) => update(filter.id, { column: event.target.value })}>
                  {columns.map((column) => <option key={column} value={column}>{column}</option>)}
                </select>
                <select aria-label="Filter rule" value={filter.mode}
                  onChange={(event) => update(filter.id, { mode: event.target.value })}>
                  {FILTER_MODES.filter((mode) => mode.id !== "equals" || values)
                    .map((mode) => <option key={mode.id} value={mode.id}>{mode.label}</option>)}
                </select>
                {needsValue && (filter.mode === "equals" && values ? (
                  <select aria-label="Filter value" value={filter.value}
                    onChange={(event) => update(filter.id, { value: event.target.value })}>
                    <option value="">Choose a value…</option>
                    {values.map((value) => <option key={value} value={value}>{value}</option>)}
                  </select>
                ) : (
                  <input aria-label="Filter text" placeholder="Value" value={filter.value}
                    list={values ? `filter-values-${filter.id}` : undefined}
                    onChange={(event) => update(filter.id, { value: event.target.value })} />
                ))}
                {needsValue && filter.mode === "contains" && values && (
                  <datalist id={`filter-values-${filter.id}`}>
                    {values.map((value) => <option key={value} value={value} />)}
                  </datalist>
                )}
                <button type="button" aria-label="Remove filter"
                  onClick={() => setFilters((current) => current.filter((item) => item.id !== filter.id))}>
                  <X size={14} />
                </button>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function Pager({ page, pages, setPage, first, last, total }) {
  if (total <= PAGE_SIZE) return null;
  return (
    <div className="pagination">
      <span>Rows {first}-{last} of {total}</span>
      <div>
        <button className="button button-secondary button-small" disabled={page === 1}
          onClick={() => setPage(page - 1)}>Previous</button>
        <span className="page-count">{page} / {pages}</span>
        <button className="button button-secondary button-small" disabled={page === pages}
          onClick={() => setPage(page + 1)}>Next</button>
      </div>
    </div>
  );
}

function usePaging(entries, resetKey) {
  const [page, setPage] = useState(1);
  useEffect(() => setPage(1), [resetKey]);
  const pages = Math.max(1, Math.ceil(entries.length / PAGE_SIZE));
  const safePage = Math.min(page, pages);
  const start = (safePage - 1) * PAGE_SIZE;
  return {
    page: safePage, pages, setPage,
    visible: entries.slice(start, start + PAGE_SIZE),
    first: entries.length ? start + 1 : 0,
    last: Math.min(start + PAGE_SIZE, entries.length),
  };
}

function shortDate(value) {
  const time = Date.parse(value || "");
  return Number.isFinite(time) ? new Date(time).toLocaleDateString([], { day: "numeric", month: "short" }) : "";
}

const HISTORY_FILTERS = [
  { id: "all", label: "All" },
  { id: "with", label: "Fix found before" },
  { id: "without", label: "Not fixed before" },
];

function GroupedTable({ columns, rows, selected, setSelected, history, historyStatus, onViewHistory }) {
  const [historyFilter, setHistoryFilter] = useState("all");
  const extra = useCallback((_row, index) => historyFilter === "all"
    || (historyFilter === "with" ? Boolean(history[index]) : !history[index]), [historyFilter, history]);
  const filter = useTableFilter(columns, rows, extra);
  const { entries } = filter;
  const paging = usePaging(entries, `${filter.query}|${JSON.stringify(filter.filters)}|${historyFilter}`);
  const shownSelected = entries.filter((entry) => selected.has(entry.index)).length;
  const allShownSelected = entries.length > 0 && shownSelected === entries.length;
  const headerBox = useRef(null);

  useEffect(() => {
    if (headerBox.current) headerBox.current.indeterminate = shownSelected > 0 && !allShownSelected;
  }, [shownSelected, allShownSelected]);

  function toggle(index) {
    setSelected((current) => {
      const next = new Set(current);
      if (next.has(index)) next.delete(index);
      else next.add(index);
      return next;
    });
  }

  // The header box selects or clears only the rows the filters show.
  function toggleShown() {
    setSelected((current) => {
      const next = new Set(current);
      for (const entry of entries) {
        if (allShownSelected) next.delete(entry.index);
        else next.add(entry.index);
      }
      return next;
    });
  }

  const fixedCount = Object.keys(history).length;

  return (
    <>
      <FilterBar columns={columns} rows={rows} state={filter} total={rows.length}
        extraActive={historyFilter !== "all"} onClearExtra={() => setHistoryFilter("all")}>
        <div className="segmented" role="tablist" aria-label="Previous fix filter">
          {HISTORY_FILTERS.map((option) => (
            <button key={option.id} role="tab" aria-selected={historyFilter === option.id}
              className={historyFilter === option.id ? "active" : ""}
              disabled={historyStatus !== "ready" && option.id !== "all"}
              onClick={() => setHistoryFilter(option.id)}>
              {option.label}{option.id === "with" && historyStatus === "ready" ? ` (${fixedCount})` : ""}
            </button>
          ))}
        </div>
      </FilterBar>
      <div className="table-shell grouped-table-shell">
        <table>
          <thead>
            <tr>
              <th className="select-column">
                <input
                  ref={headerBox}
                  type="checkbox"
                  aria-label="Select all shown component groups"
                  checked={allShownSelected}
                  onChange={toggleShown}
                />
              </th>
              <th className="row-number">#</th>
              <th className="history-column">Previous fix</th>
              {columns.map((column) => <th key={column}>{column}</th>)}
            </tr>
          </thead>
          <tbody>
            {paging.visible.length ? paging.visible.map(({ row, index }) => {
              const past = history[index];
              return (
                <tr
                  key={`${row.Product}-${row.Component}-${index}`}
                  className={`${selected.has(index) ? "is-selected" : ""} ${past ? "has-history" : ""}`}
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
                  <td className="history-column">
                    {past ? (
                      <button type="button" className="history-badge"
                        title={`Fix found in run ${past.fixes[0].run_id}. Click to view it.`}
                        onClick={(event) => {
                          event.stopPropagation();
                          onViewHistory(index);
                        }}>
                        <History size={13} /> Fix found
                        <span>{shortDate(past.fixes[0].assessed_at)}</span>
                      </button>
                    ) : historyStatus === "loading" ? (
                      <span className="history-pending"><LoaderCircle className="spin" size={12} /> Checking</span>
                    ) : <span className="empty">-</span>}
                  </td>
                  {columns.map((column) => (
                    <td key={column} title={String(row[column] ?? "")}>
                      {String(row[column] ?? "") || <span className="empty">-</span>}
                    </td>
                  ))}
                </tr>
              );
            }) : (
              <tr>
                <td className="table-empty" colSpan={columns.length + 3}>No component groups match these filters.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <Pager {...paging} total={entries.length} />
    </>
  );
}

function DataTable({ columns, rows, emptyMessage }) {
  const filter = useTableFilter(columns, rows);
  const { entries } = filter;
  const paging = usePaging(entries, `${filter.query}|${JSON.stringify(filter.filters)}`);

  return (
    <>
      <FilterBar columns={columns} rows={rows} state={filter} total={rows.length} />
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
            {paging.visible.length ? (
              paging.visible.map(({ row, index }) => (
                <tr key={index}>
                  <td className="row-number">{index + 1}</td>
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
                  {rows.length ? "No rows match these filters." : emptyMessage}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <Pager {...paging} total={entries.length} />
    </>
  );
}

function FixHistoryList({ indices, rows, history }) {
  const shown = indices.slice(0, 6);
  return (
    <ul className="history-list">
      {shown.map((index) => {
        const row = rows[index] || {};
        const fix = history[index]?.fixes?.[0];
        return (
          <li key={index}>
            <div>
              <strong>{row.Product || "Unknown product"} · {row.Component || "Unknown component"}</strong>
              {fix && <span>{fix.cve} → {fix.target || "fix recorded"}</span>}
            </div>
            {fix && <small>Run {fix.run_id}{fix.assessed_at ? ` · ${new Date(fix.assessed_at).toLocaleString()}` : ""}</small>}
          </li>
        );
      })}
      {indices.length > shown.length && <li className="history-more">and {indices.length - shown.length} more</li>}
    </ul>
  );
}

function PreviousFixDialog({ prompt, rows, history, loading, onClose, onView, onRun }) {
  useEffect(() => {
    const close = (event) => event.key === "Escape" && onClose();
    window.addEventListener("keydown", close);
    return () => window.removeEventListener("keydown", close);
  }, [onClose]);

  const isRun = prompt.type === "run";
  const fixed = isRun ? prompt.fixed : [prompt.index];
  const rest = isRun ? prompt.rest : [];
  return (
    <div className="modal-backdrop" role="presentation" onClick={(event) => event.target === event.currentTarget && onClose()}>
      <section className="modal-card" role="dialog" aria-modal="true" aria-labelledby="previous-fix-title">
        <div className="modal-icon"><History size={24} /></div>
        <span className="eyebrow">Fix already found</span>
        <h2 id="previous-fix-title">
          {!isRun ? "A previous run already found a fix for this component"
            : fixed.length + rest.length === 1 ? "This component already has a fix"
              : `${fixed.length} of ${fixed.length + rest.length} selected components already ${fixed.length === 1 ? "has" : "have"} a fix`}
        </h2>
        <p>{isRun
          ? "A saved run found a validated fix (Fix available) for these. Do you want to view the previous result instead of running them again?"
          : "Do you want to view the previous run's result?"}</p>
        <FixHistoryList indices={fixed} rows={rows} history={history} />
        <div className="modal-actions">
          <button className="button button-ghost" onClick={onClose}>{isRun ? "Cancel" : "Not now"}</button>
          {isRun && rest.length > 0 && (
            <button className="button button-secondary" onClick={() => onRun(rest)}>
              Run only the other {rest.length}
            </button>
          )}
          {isRun && (
            <button className="button button-secondary" onClick={() => onRun([...fixed, ...rest])}>
              <Play size={15} /> Run all {fixed.length + rest.length} again
            </button>
          )}
          <button className="button button-primary" disabled={loading} onClick={() => onView(fixed)}>
            {loading ? <LoaderCircle className="spin" size={16} /> : <Eye size={16} />}
            {fixed.length === 1 ? "View previous fix" : "View previous fixes"}
          </button>
        </div>
      </section>
    </div>
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
  const [reuseFile, setReuseFile] = useState(null);
  const [selectedGroups, setSelectedGroups] = useState(new Set());
  const [pipelineRun, setPipelineRun] = useState(null);
  const [remediationRuns, setRemediationRuns] = useState([]);
  const remediationResults = useMemo(() => combineRemediationRuns(remediationRuns), [remediationRuns]);
  const [previousFixRuns, setPreviousFixRuns] = useState([]);
  const previousFixResults = useMemo(() => combineRemediationRuns(previousFixRuns) || {
    run_ids: [], total: 0, verdict_counts: {}, uses_test_context: false, results: [],
  }, [previousFixRuns]);
  const displayResults = view === "previous_fixes" ? previousFixResults : remediationResults;
  // Grouped rows that saved runs already fixed (FIX_AVAILABLE and still valid), by row index.
  const [fixHistory, setFixHistory] = useState({ status: "idle", byIndex: {} });
  const historyRequest = useRef(0);
  // Confirmation dialog: { type: "row", index } or { type: "run", fixed: [...], rest: [...] }.
  const [prompt, setPrompt] = useState(null);
  const [previousScope, setPreviousScope] = useState(null);
  const [verdictFilter, setVerdictFilter] = useState(null);
  const [loadingResults, setLoadingResults] = useState(false);
  const [loadingPreviousFixes, setLoadingPreviousFixes] = useState(false);
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
    let pollTimer;
    async function pollStatus() {
      try {
        const response = await fetch(`/api/pipeline-runs/${pipelineRun.run_id}`);
        if (!response.ok) throw new Error("Status request failed");
        const next = await response.json();
        setPipelineRun(next);
        if (["completed", "failed"].includes(next.status)) {
          finished = true;
          window.clearInterval(pollTimer);
        }
      } catch {
        setError("Could not refresh the live remediation workflow.");
      }
    }
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
      if (!finished) {
        pollTimer = window.setInterval(pollStatus, 2000);
        pollStatus();
      }
    };
    return () => {
      events.close();
      window.clearInterval(pollTimer);
    };
  }, [pipelineRun?.run_id]);

  async function loadFixHistory(jobId) {
    if (!jobId) return;
    const request = ++historyRequest.current;
    setFixHistory({ status: "loading", byIndex: {} });
    try {
      const response = await fetch(`/api/jobs/${jobId}/fix-history`);
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || "Could not check previous fixes.");
      if (request !== historyRequest.current) return;
      setFixHistory({
        status: "ready",
        byIndex: Object.fromEntries((result.components || []).map((entry) => [entry.index, entry])),
      });
    } catch {
      if (request === historyRequest.current) setFixHistory({ status: "error", byIndex: {} });
    }
  }

  // A finished run can add new fixes, so the grouped rows are checked again.
  useEffect(() => {
    if (pipelineRun?.status === "completed" && dataset?.job_id && grouped) loadFixHistory(dataset.job_id);
  }, [pipelineRun?.status, pipelineRun?.run_id]);

  function reset() {
    historyRequest.current += 1;
    setDataset(null);
    setEnriched(null);
    setGrouped(null);
    setView("workspace");
    setReusePrompt(false);
    setReuseFile(null);
    setSelectedGroups(new Set());
    setPipelineRun(null);
    setRemediationRuns([]);
    setPreviousFixRuns([]);
    setFixHistory({ status: "idle", byIndex: {} });
    setPrompt(null);
    setPreviousScope(null);
    setVerdictFilter(null);
    setLoadingResults(false);
    setLoadingPreviousFixes(false);
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
    loadFixHistory(result.run_id || dataset?.job_id);
  }

  function requestPipelineRun() {
    if (dataset.existing_enrichment) {
      // Default to the newest saved enrichment; the dialog lets the user pick an older one.
      setReuseFile((current) => current || dataset.existing_enrichment.filename);
      setReusePrompt(true);
    }
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
          ? { job_id: dataset.job_id, filename: reuseFile || dataset.existing_enrichment.filename }
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

  // confirmed=false first asks when a selected component already has a saved fix.
  async function runSelectedComponents(indices = null, confirmed = false) {
    const chosen = [...(indices || selectedGroups)].sort((a, b) => a - b);
    if (!chosen.length || ["queued", "running"].includes(pipelineRun?.status)) return;
    if (!confirmed) {
      const fixed = chosen.filter((index) => fixHistory.byIndex[index]);
      if (fixed.length) {
        setPrompt({ type: "run", fixed, rest: chosen.filter((index) => !fixHistory.byIndex[index]) });
        return;
      }
    }
    setPrompt(null);
    if (indices) setSelectedGroups(new Set(chosen));
    setError("");
    try {
      const response = await fetch("/api/pipeline-runs", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          job_id: dataset.job_id,
          selected_indices: chosen,
        }),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || "Could not start the selected components.");
      setPipelineRun(result);
    } catch (runError) {
      setError(runError.message);
    }
  }

  async function showRemediationResults() {
    if (!pipelineRun?.run_id) return;
    setLoadingResults(true);
    setError("");
    try {
      const response = await fetch(`/api/jobs/${dataset.job_id}/remediation-results`);
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || "Could not load remediation results.");
      setRemediationRuns((runs) => result.runs.reduce(mergeRemediationRuns, runs));
      setVerdictFilter(null);
      setView("results");
    } catch (resultError) {
      setError(resultError.message);
    } finally {
      setLoadingResults(false);
    }
  }

  // indices=null lists every saved fix; otherwise only the fixes for those grouped rows.
  async function showPreviousFixes(indices = null) {
    setPrompt(null);
    setLoadingPreviousFixes(true);
    setError("");
    try {
      const response = await fetch(`/api/jobs/${dataset.job_id}/previous-fixes`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(indices
          ? { scope: "selected", selected_indices: indices }
          : { exclude_run_id: pipelineRun?.run_id }),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || "Could not load previous fixes.");
      setPreviousFixRuns(result.runs);
      const row = indices?.length === 1 ? grouped?.rows?.[indices[0]] : null;
      setPreviousScope(!indices ? null
        : row ? `${row.Product || "Unknown product"} · ${row.Component || "Unknown component"}`
          : `${indices.length} selected components`);
      setVerdictFilter(null);
      setView("previous_fixes");
    } catch (resultError) {
      setError(resultError.message);
    } finally {
      setLoadingPreviousFixes(false);
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
        <ol className="step-indicator" aria-label="Workflow steps">
          {["Upload", "Enrich", "Select components", "Results"].map((label, index) => {
            const current = !dataset ? 0 : view === "workspace" ? 1 : view === "grouped" ? 2 : 3;
            return (
              <li key={label} className={index < current ? "is-done" : index === current ? "is-current" : ""}
                aria-current={index === current ? "step" : undefined}>
                <span>{index < current ? <Check size={12} /> : index + 1}</span>{label}
              </li>
            );
          })}
        </ol>
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
        ) : (view === "results" || view === "previous_fixes") && displayResults ? (
          <section className="results-workspace">
            <div className="results-heading">
              <div>
                <button className="back-link" onClick={() => {
                  if (view === "results") {
                    setSelectedGroups(new Set());
                    setPipelineRun(null);
                  }
                  setVerdictFilter(null);
                  setView("grouped");
                }}>
                  <ChevronLeft size={17} /> Back to remediation selection
                </button>
                <span className="eyebrow">{view === "previous_fixes" ? "Saved remediation history" : "Remediation assessment complete"}</span>
                <h1>{view === "previous_fixes" ? (previousScope ? "Previous fix" : "Previous fixes") : "Remediation results"}</h1>
                <p>{view === "previous_fixes"
                  ? previousScope
                    ? `Latest citation-validated fix saved for ${previousScope}. Each card shows the run that found it.`
                    : "Latest citation-validated fixes across saved components. Each card shows its original run ID."
                  : "Review the evidence-backed results from this file's remediation runs."}</p>
                {displayResults.uses_test_context && (
                  <span className="test-context-badge">Test-context inventory</span>
                )}
              </div>
              <div className="run-identity">
                <span>{displayResults.run_ids.length} remediation run{displayResults.run_ids.length === 1 ? "" : "s"}</span>
                {displayResults.run_ids.map((runId) => <code key={runId}>{runId}</code>)}
              </div>
            </div>

            <section className="results-summary" aria-label="Filter results by verdict">
              <div className="summary-icon"><CircleCheckBig size={24} /></div>
              {[
                { id: null, label: "Assessments", count: displayResults.total },
                ...MAIN_VERDICTS.map((verdict) => ({
                  id: verdict.id, label: verdict.label, count: displayResults.verdict_counts[verdict.id] || 0,
                })),
                { id: "OTHER", label: "Other verdicts", count: displayResults.total - MAIN_VERDICTS.reduce(
                  (sum, verdict) => sum + (displayResults.verdict_counts[verdict.id] || 0), 0) },
              ].map((metric) => (
                <button type="button" key={metric.label}
                  className={`summary-metric ${verdictFilter === metric.id ? "is-active" : ""}`}
                  aria-pressed={verdictFilter === metric.id}
                  disabled={metric.id !== null && !metric.count}
                  onClick={() => setVerdictFilter(verdictFilter === metric.id ? null : metric.id)}>
                  <span>{metric.label}</span>
                  <strong>{metric.count}</strong>
                </button>
              ))}
            </section>

            {view === "results" && pipelineRun && <WorkflowView run={pipelineRun} />}

            <div className="results-list">
              {view === "previous_fixes" && !displayResults.results.length && (
                <div className="empty-previous-fixes">No validated previous fixes were found in saved runs.</div>
              )}
              {verdictFilter && (
                <div className="results-filter-note">
                  <ListFilter size={15} />
                  Showing {verdictFilter === "OTHER" ? "other verdicts"
                    : humanize(verdictFilter).toLowerCase()} only.
                  <button type="button" className="button button-ghost button-small" onClick={() => setVerdictFilter(null)}>
                    Show all
                  </button>
                </div>
              )}
              {displayResults.results.filter((result) => !verdictFilter
                || (verdictFilter === "OTHER"
                  ? !MAIN_VERDICTS.some((verdict) => verdict.id === result.verdict)
                  : result.verdict === verdictFilter)).map((result, index) => (
                <RemediationResultCard
                  key={`${result.run_id || "run"}-${result.product}-${result.cve}-${index}`}
                  result={result}
                />
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
                    <Wrench size={16} /> View remediation results ({remediationResults.total})
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
                  <p>{selectedGroups.size} of {grouped.rows.length} component groups selected.
                    {fixHistory.status === "ready" && Object.keys(fixHistory.byIndex).length > 0 && (
                      <> <span className="history-hint"><History size={13} /> {Object.keys(fixHistory.byIndex).length} already
                        have a fix from a previous run.</span></>
                    )}
                    {fixHistory.status === "loading" && (
                      <> <span className="history-hint"><LoaderCircle className="spin" size={13} /> Checking previous runs…</span></>
                    )}
                    {fixHistory.status === "error" && (
                      <> <span className="history-hint">Previous runs could not be checked.</span></>
                    )}
                  </p>
                </div>
              </div>
              <div className="selection-actions">
                <button
                  className="button button-primary"
                  disabled={!selectedGroups.size || ["queued", "running"].includes(pipelineRun?.status)}
                  onClick={() => runSelectedComponents()}
                >
                  {["queued", "running"].includes(pipelineRun?.status) ? (
                    <><LoaderCircle className="spin" size={18} /> Getting remediation...</>
                  ) : (
                    <><Play size={17} /> Get remediation</>
                  )}
                </button>
                <button className="button button-secondary" disabled={loadingPreviousFixes}
                  onClick={() => showPreviousFixes()}>
                  {loadingPreviousFixes ? <LoaderCircle className="spin" size={17} /> : <Wrench size={17} />}
                  {loadingPreviousFixes ? "Loading previous fixes..." : "Previous fixes"}
                </button>
              </div>
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

            {pipelineRun && <WorkflowView run={pipelineRun} />}

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
                history={fixHistory.byIndex}
                historyStatus={fixHistory.status}
                onViewHistory={(index) => setPrompt({ type: "row", index })}
              />
            </section>
          </section>
        ) : (
          <>
            <section className="workspace-heading">
              <div>
                <span className="eyebrow">Dataset ready</span>
                <h1>{dataset.filename}</h1>
                <div className="run-identity"><span>Run ID</span><code>{dataset.run_id}</code></div>
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
              {(() => {
                const files = dataset.enrichment_files?.length ? dataset.enrichment_files : [dataset.existing_enrichment];
                const chosen = files.find((file) => file.filename === reuseFile) || files[0];
                return (
                  <>
                    {files.length > 1 && (
                      <label className="reuse-picker">
                        Saved enrichment ({files.length} available, newest first)
                        <select value={chosen.filename} onChange={(event) => setReuseFile(event.target.value)}>
                          {files.map((file, index) => (
                            <option key={file.filename} value={file.filename}>
                              {file.filename} · {file.row_count} rows · {new Date(file.modified_at).toLocaleString()}
                              {index === 0 ? " (newest)" : ""}
                            </option>
                          ))}
                        </select>
                      </label>
                    )}
                    <p>
                      <strong>{chosen.filename}</strong> contains {chosen.row_count} enriched rows
                      and was saved {new Date(chosen.modified_at).toLocaleString()}.
                    </p>
                  </>
                );
              })()}
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

        {prompt && grouped && (
          <PreviousFixDialog
            prompt={prompt}
            rows={grouped.rows}
            history={fixHistory.byIndex}
            loading={loadingPreviousFixes}
            onClose={() => setPrompt(null)}
            onView={(indices) => showPreviousFixes(indices)}
            onRun={(indices) => runSelectedComponents(indices, true)}
          />
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
