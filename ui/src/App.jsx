import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  Check,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  CircleCheckBig,
  Clock,
  Database,
  Download,
  ExternalLink,
  Eye,
  FileSpreadsheet,
  Flag,
  GitBranch,
  History,
  Info,
  Layers3,
  ListFilter,
  LoaderCircle,
  Play,
  Plug,
  RefreshCw,
  Search,
  Server,
  ShieldCheck,
  UploadCloud,
  Workflow,
  Wrench,
  X,
} from "lucide-react";
import { ContextGathererView } from "./contextGatherer.jsx";
import { CompatRulesView } from "./compatRules.jsx";
import DeliveryView from "./delivery.jsx";
import MiddlewareDeliveryView from "./middlewareDelivery.jsx";
import { combineRemediationRuns, mergeRemediationRuns, resultAnchor } from "./remediationResults.js";
import { COLUMN_VALUE_LIMIT, distinctValues, filterRows } from "./tableFilters.js";

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

// ------------------------------------------------------------ compatibility questions

const ASPECT_LABELS = {
  installed_version: "Installed version", ownership: "Who installed it", application_usage: "Used by the application",
  java_runtime: "Java runtime", dependency_version: "Dependency version", application_support: "Vendor support",
  branch_change: "Branch change", support_contract: "Support contract", aix_tl_update: "AIX technology level",
  cve_fix: "CVE fix in package",
};

async function postAnswers(item, answers) {
  const response = await fetch("/api/compatibility/answers", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ run_id: item.run_id, cve: item.cve, component_id: item.component_id,
      host: item.host || null, answers }),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `Saving the answer failed (HTTP ${response.status}).`);
  return data;
}

function QuestionItem({ question, onAnswer }) {
  const [value, setValue] = useState("");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState("");
  const textual = question.kind === "text";

  async function save() {
    setBusy(true);
    setFailure("");
    try { await onAnswer(question, value, note); }
    catch (error) { setFailure(error.message); }
    finally { setBusy(false); }
  }

  return (
    <li className="question-item">
      <div className="question-copy">
        <span className="question-aspect">{ASPECT_LABELS[question.aspect] || humanize(question.aspect)}</span>
        <strong>{question.question}</strong>
        {question.why && <p>{question.why}</p>}
        {question.hint && <code title="How to find out (read-only)">{question.hint}</code>}
      </div>
      <div className="question-answer">
        {!textual && (
          <div className="question-options" role="radiogroup" aria-label={question.question}>
            {(question.options || []).map((option) => (
              <label key={option.value} className={value === option.value ? "is-chosen" : ""}>
                <input type="radio" name={question.key} value={option.value} checked={value === option.value}
                  onChange={() => setValue(option.value)} />
                {option.label}
              </label>
            ))}
          </div>
        )}
        {(textual || question.allow_text) && (
          <input className="question-text" aria-label="Answer" placeholder={question.placeholder || "Answer"}
            value={textual || !(question.options || []).some((o) => o.value === value) ? value : ""}
            onChange={(event) => setValue(event.target.value)} />
        )}
        {question.note_label && (
          <input className="question-text" aria-label={question.note_label} placeholder={question.note_label}
            value={note} onChange={(event) => setNote(event.target.value)} maxLength={300} />
        )}
        <button type="button" className="button button-primary button-small" disabled={!value.trim() || busy} onClick={save}>
          {busy ? <LoaderCircle className="spin" size={14} /> : <Check size={14} />} Save answer
        </button>
        {failure && <p className="question-error">{failure}</p>}
      </div>
    </li>
  );
}

function QuestionsList({ questions, onAnswer }) {
  if (!questions?.length) return null;
  return (
    <ol className="question-list">
      {questions.map((question) => <QuestionItem key={question.key} question={question} onAnswer={onAnswer} />)}
    </ol>
  );
}

// Facts a shell can answer: they come from the server's script output, not from a question.
const HOST_FACT_ASPECTS = new Set(["installed_version", "ownership", "application_usage", "java_runtime", "dependency_version"]);

// The card's own server: download the read-only script, paste what it printed, and the card re-checks.
function CardServerContext({ item, compatibility, onChecked, onResult }) {
  const input = useRef(null);
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState("");
  const [stored, setStored] = useState(null);
  const [show, setShow] = useState(false);
  const server = item.host || "";

  async function apply(content) {
    if (!content?.trim()) { setFailure("Paste the output of the script first."); return; }
    setBusy(true);
    setFailure("");
    try {
      const response = await fetch("/api/compatibility/context", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ run_id: item.run_id, cve: item.cve, component_id: item.component_id,
          host: item.host || null, text: content }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || `Applying the context failed (HTTP ${response.status}).`);
      setStored({ ...data.context, verdict: data.result?.verdict, version: data.result?.component_version });
      setText("");
      // The CVE was re-assessed with this context: the whole card is replaced, not only compatibility.
      if (data.result && onResult) onResult(data.result);
      else onChecked(data.compatibility);
    } catch (error) {
      setFailure(error.message);
    } finally {
      setBusy(false);
      if (input.current) input.current.value = "";
    }
  }

  const open = (compatibility?.questions || []).filter((q) => HOST_FACT_ASPECTS.has(q.aspect));
  const decisions = (compatibility?.questions || []).filter((q) => !HOST_FACT_ASPECTS.has(q.aspect));
  const answer = async (question, value, note) => {
    const data = await postAnswers(item, [{ key: question.key, value, note }]);
    onChecked(data.compatibility);
  };
  // No open server questions: the paste box stays folded behind one button, so a newer context
  // (for example an edited inventory YAML) can still re-check this card.
  if (item.host && !open.length && !stored && !decisions.length && !show) {
    return (
      <section className="card-questions">
        <button type="button" className="button button-secondary button-small" onClick={() => setShow(true)}>
          <UploadCloud size={14} /> Update server context
        </button>
      </section>
    );
  }
  return (
    <section className="card-questions">
      {(open.length > 0 || stored || !item.host || show) && (
        <div className="card-context">
          <h3>{server ? `Server context · ${server}` : "Server context · this run only"}</h3>
          {stored ? (
            <p className="server-upload-ok"><Check size={13} /> Read {stored.hostname}{stored.run_only ? " for this run only" : ""}{stored.os ? ` (${stored.os})` : ""}:
              {" "}{stored.components} components.{stored.verdict ? ` Re-assessed: ${humanize(stored.verdict)}` : ""}
              {stored.version ? `, component version ${stored.version}.` : stored.verdict ? "." : ""} {open.length
                ? `${open.length} thing${open.length === 1 ? " is" : "s are"} not in this output (listed below).`
                : "Everything about this server that the check needs was read from the output."}
              {stored.warnings?.map((warning) => <span key={warning}> {warning}</span>)}</p>
          ) : (
            <p>Run the read-only script on this server and paste its whole output. The installed version, who
              installed it, the Java runtime and the dependencies are read from it, and this card updates.</p>
          )}
          {!item.host && <p>The scanner gave this CVE no server. Paste the output of the script from the machine it runs
            on: it is used for this run's result only and is not stored against any server.</p>}
          <div className="server-actions-buttons">
            <a className="button button-secondary button-small"
              href={`/api/context-script?server=${encodeURIComponent(server || "this-server")}`}><Download size={14} /> Download script</a>
            <button type="button" className="button button-secondary button-small" disabled={busy}
              onClick={() => input.current?.click()}><UploadCloud size={14} /> Choose output file</button>
            <input ref={input} type="file" accept=".txt,text/plain" hidden
              onChange={async (event) => { const file = event.target.files[0]; if (file) apply(await file.text()); }} />
          </div>
          <textarea className="card-context-text" rows={5} value={text} disabled={busy}
            placeholder={`Paste the output of the collection script (or an inventory YAML) for ${server || "<server>"}`}
            onChange={(event) => setText(event.target.value)} />
          <button type="button" className="button button-primary button-small" disabled={busy || !text.trim()}
            onClick={() => apply(text)}>
            {busy ? <LoaderCircle className="spin" size={14} /> : <Check size={14} />}
            {busy ? "Reading…" : "Apply server context"}
          </button>
          {failure && <p className="server-upload-error"><AlertTriangle size={13} /> {failure}</p>}
          {stored && open.length > 0 && (
            <ul className="card-context-missing">
              {open.map((question) => <li key={question.key}><strong>{ASPECT_LABELS[question.aspect]}:</strong> not
                in the output. {question.why}</li>)}
            </ul>
          )}
        </div>
      )}
      {decisions.length > 0 && (
        <>
          <h3>Decisions only you can make ({decisions.length})</h3>
          <p>A server cannot tell these (vendor support, accepted branch change, contracts); each answer re-checks this CVE and is reused.</p>
          <QuestionsList questions={decisions} onAnswer={answer} />
        </>
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
          <h2>{current ? `${current.cve} · ${current.component || current.product}${current.host ? ` · ${current.host}` : ""}` : "Preparing selected CVEs"}</h2>
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
  // An Oracle CPU fix is shown as the Database patch level it gives; the CPU name goes below it.
  const shown = remedy.target_version || patchVersions(remedy) || remedy.patch_id;
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
          <h4>{shown || humanize(remedy.route)}</h4>
          {!remedy.target_version && remedy.patch_versions?.length > 0 && (
            <small className="first-fix-label">
              {remedy.patch_id}{remedy.patch_versions.length > 1 ? " · one patch level per Database release" : ""}
            </small>
          )}
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
  latest: "Latest release", available: "Available fix",
};

// A fix that exists for this installed copy, shown whatever the verdict or compatibility say.
// How well a source-reported fix matches this copy (app.available_fix).
const AVAILABLE_FIX_RELIABILITY = {
  assumed_version: "Based on an assumed version",
  installed_unknown: "Installed version unknown",
  unreliable: "Unverified match",
  supposed: "Supposed fix (not stated by a source)",
  no_package_fix: "No package update yet",
};

function AvailableFixSection({ result, compatibility }) {
  const fix = result.available_fix;
  if (!fix || !["source", "supposed", "distribution_status"].includes(fix.origin)) return null;
  const packageStatus = fix.origin === "distribution_status";
  const evaluation = (compatibility?.evaluations || []).find((entry) =>
    entry.role === "available" && entry.target === fix.identifier);
  const failing = evaluation?.checks?.find((check) => check.status === "FAIL");
  const verdictNote = {
    NOT_APPLICABLE: "The assessment found this copy not affected (see Assessment below). This is the fix the source reports for the affected versions; applying it also removes the finding from scanners.",
    NO_FIX_AVAILABLE: "The assessment found no fix for this copy's own package route; this is the fix the source reports for the product.",
  }[result.verdict] || "The source reports this fix for the installed version. The assessment did not validate it on its own; see what it still needs below.";
  const headline = packageStatus
    ? "This copy is an OS package: only its distribution's package update fixes it, and none is published yet."
    : fix.origin === "supposed"
      ? "No source states the release that fixes this CVE; this is the release expected to include the fix (see the notes)."
      : verdictNote;
  const reliability = AVAILABLE_FIX_RELIABILITY[fix.reliability];
  const installedText = result.component_version
    ? `installed ${result.component_version}${result.component_version_assumed ? " (assumed, not observed)" : ""}`
    : "installed version unknown";
  return (
    <section className={`available-fix-section${["unreliable", "no_package_fix", "supposed"].includes(fix.reliability) ? " available-fix-unreliable" : ""}`}>
      <div className="result-title-row">
        <h3>{packageStatus ? <><AlertTriangle size={16} /> Package fix status</>
          : <><CircleCheckBig size={16} /> {fix.origin === "supposed" ? "Supposed fix" : "Fix available"}</>}</h3>
        {reliability && <span className={`fix-reliability fix-reliability-${fix.reliability}`}>{reliability}</span>}
        {evaluation && (
          <span className={`compatibility compatibility-${String(evaluation.status).toLowerCase()}`}>
            Host check: {humanize(evaluation.status)}
          </span>
        )}
      </div>
      <div className="available-fix-body">
        <div className="available-fix-target">
          <small>{fix.identifier_kind || "Fix"}{fix.branch ? ` · ${fix.branch}` : ""}</small>
          <strong>{fix.identifier}</strong>
          <span>{installedText}</span>
        </div>
        <div className="available-fix-details">
          <p>{[fix.source, fix.product].filter(Boolean).join(" · ")}
            {fix.releases?.length ? ` · ${fix.releases.join(", ")}` : ""}</p>
          {fix.latest && (
            <p>Newest release on this branch: <strong>{fix.latest}</strong>
              {fix.latest_url && /^https?:\/\//.test(fix.latest_url) && (
                <> · <a href={fix.latest_url} target="_blank" rel="noreferrer">source</a></>)}</p>
          )}
          <p className="available-fix-note">{headline}</p>
          {!!fix.reliability_notes?.length && (
            <ul className="available-fix-reasons">
              {fix.reliability_notes.map((note) => <li key={note}>{note}</li>)}
            </ul>
          )}
          {!!fix.branches?.length && (
            <table className="available-fix-branches">
              <thead><tr>{fix.products?.length > 1 && <th>Product</th>}<th>Release branch</th><th>First fixed version</th><th>Newest on branch</th><th>Source</th></tr></thead>
              <tbody>
                {fix.branches.map((option) => (
                  <tr key={`${option.product}-${option.branch}-${option.identifier}`}
                    className={option.identifier === fix.identifier ? "available-fix-primary" : undefined}>
                    {fix.products?.length > 1 && <td>{option.product}</td>}
                    <td>{option.branch || "Package"}</td>
                    <td><strong>{option.identifier}</strong></td>
                    <td>{option.latest || "—"}</td>
                    <td>{option.url && /^https?:\/\//.test(option.url)
                      ? <a href={option.url} target="_blank" rel="noreferrer">{option.source || "source"}</a>
                      : option.source}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {!!fix.reference_fixes?.length && (
            <>
              <p className="available-fix-note">Upstream release with the fix, for reference only (not installable over the OS package):</p>
              <table className="available-fix-branches">
                <thead><tr><th>Product</th><th>Release branch</th><th>First fixed version</th><th>Newest on branch</th></tr></thead>
                <tbody>
                  {fix.reference_fixes.flatMap((group) => group.options.map((option) => (
                    <tr key={`ref-${group.product}-${option.branch}-${option.identifier}`}>
                      <td>{group.product}</td>
                      <td>{option.branch || "—"}</td>
                      <td><strong>{option.identifier}</strong></td>
                      <td>{option.latest || "—"}</td>
                    </tr>
                  )))}
                </tbody>
              </table>
            </>
          )}
          {!!fix.other_products?.length && (
            <>
              <p className="available-fix-note">This CVE also affects other products; their fixes are listed for reference, not for this component:</p>
              <table className="available-fix-branches">
                <thead><tr><th>Other affected product</th><th>Release branch</th><th>First fixed version</th><th>Newest on branch</th></tr></thead>
                <tbody>
                  {fix.other_products.flatMap((group) => group.options.map((option) => (
                    <tr key={`${group.product}-${option.branch}-${option.identifier}`}>
                      <td>{group.product}</td>
                      <td>{option.branch || "—"}</td>
                      <td><strong>{option.identifier}</strong></td>
                      <td>{option.latest || "—"}</td>
                    </tr>
                  )))}
                </tbody>
              </table>
            </>
          )}
          {failing && (
            <p className="validation-note"><AlertTriangle size={14} /> Compatibility on this host: {failing.detail}</p>
          )}
          <div className="source-fix-footer">
            <span>{(fix.evidence_ids || []).join(", ")}</span>
            {fix.url && /^https?:\/\//.test(fix.url) && (
              <a href={fix.url} target="_blank" rel="noreferrer">View source <ExternalLink size={12} /></a>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}

// Rule types a user can enter by hand; each is checked by the engine itself (no model call).
const MANUAL_RULE_KINDS = [
  { value: "os_support", label: "Supported on an OS", help: "Which OS releases this product (version) is supported on." },
  { value: "requirement", label: "Requires a dependency", help: "This product version needs a runtime or component version." },
  { value: "application_support", label: "Application supports product", help: "An application release lists the product versions it supports." },
  { value: "behaviour_change", label: "Behaviour change", help: "From this release on, something changes or is removed." },
];

function splitOs(name) {
  const text = String(name || "");
  const version = (text.match(/\d+(?:\.\d+)*/) || [""])[0];
  return { os: text.replace(version, "").replace(/\s+/g, " ").trim(), version };
}

function describeProposal(proposal) {
  if (proposal.summary) return proposal.summary;
  if (proposal.kind === "requirement")
    return `${proposal.product} ${proposal.when} requires ${proposal.runtime || proposal.component} ${proposal.spec}.`;
  if (proposal.kind === "application_support")
    return `${proposal.application} ${proposal.when} supports ${proposal.product} ${proposal.versions.join(", ")}.`;
  if (proposal.kind === "os_support")
    return `${proposal.product} ${proposal.when || "(any version)"} is ${proposal.supported ? "supported" : "NOT supported"} on ${proposal.os} ${proposal.os_versions.join(", ")}.`;
  return `${proposal.product}: behaviour change since ${proposal.since}.`;
}

function CompatibilityRuleRequest({ compatibility, result, onChecked }) {
  const [sourceUrl, setSourceUrl] = useState("");
  const [ruleText, setRuleText] = useState("");
  const [draft, setDraft] = useState(null);
  const [ruleBusy, setRuleBusy] = useState(false);
  const [ruleMessage, setRuleMessage] = useState("");
  const [config, setConfig] = useState({ model_drafting: false, model_judge: false });
  const [mode, setMode] = useState("manual");
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
  const product = missingRules?.product || result.product || result.component || "";
  const hostOs = splitOs(result.operating_systems?.[0]);
  const [manual, setManual] = useState(() => ({
    kind: "os_support", os: hostOs.os, os_versions: hostOs.version, when: "", supported: "yes",
    dependency: "", spec: "", application: result.applications?.[0] || "",
    versions: "", since: "", note: "", source: "", this_cve_only: false,
  }));
  const setField = (name) => (event) => setManual((current) => ({ ...current, [name]: event.target.value }));

  useEffect(() => {
    let active = true;
    fetch("/api/compatibility/config").then((response) => response.json())
      .then((data) => { if (active) setConfig(data); }).catch(() => {});
    return () => { active = false; };
  }, []);

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
        body: JSON.stringify({ cve: result.cve, product,
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

  async function enterRule(event) {
    event.preventDefault();
    setRuleBusy(true); setRuleMessage(""); setDraft(null);
    try {
      const { this_cve_only: onlyThisCve, ...fields } = manual;
      const response = await fetch("/api/compatibility/rules/manual", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ...fields, product, cve: onlyThisCve ? result.cve : "" }),
      });
      const data = await readRuleResponse(response, "Rule check");
      setDraft(data);
    } catch (error) { setRuleMessage(error.message); }
    finally { setRuleBusy(false); }
  }

  async function applyNewRule() {
    setRuleBusy(true); setRuleMessage("");
    try {
      const savedResponse = await fetch(`/api/compatibility/rules/${draft.draft_id}/apply`, { method: "POST" });
      await readRuleResponse(savedResponse, "Rule save");
      const handEntered = Boolean(draft.proposal.manual);
      setDraft(null);
      setRuleMessage("Rule saved. Rechecking this CVE against the updated knowledge…");
      const response = await fetch("/api/compatibility/recheck", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ run_id: result.run_id, cve: result.cve, component_id: result.component_id,
          host: result.host || null, use_model: !handEntered }),
      });
      const data = await readRuleResponse(response, "Compatibility recheck");
      onChecked(data.compatibility);
      setRuleMessage("Rule saved and compatibility rechecked. The original run record is unchanged.");
    } catch (error) { setRuleMessage(error.message); }
    finally { setRuleBusy(false); }
  }
  if (!missingRules) return null;
  const kind = MANUAL_RULE_KINDS.find((entry) => entry.value === manual.kind);
  const manualMode = mode === "manual" || !config.model_drafting;
  return (
        <div className="compatibility-eval knowledge-gap">
          <strong>Compatibility rules needed for {product}</strong>
          {config.model_drafting && (
            <div className="server-actions-buttons">
              <button type="button" className={`button button-small ${manualMode ? "button-primary" : "button-secondary"}`}
                onClick={() => setMode("manual")}>Enter rule</button>
              <button type="button" className={`button button-small ${manualMode ? "button-secondary" : "button-primary"}`}
                onClick={() => setMode("source")}>Draft from a source (model)</button>
            </div>
          )}
          {manualMode ? (
            <form onSubmit={enterRule} className="manual-rule">
              <p>Enter the rule; the engine checks it against this server and fix itself (no model call).
                Versions take 8.10, 8.x, 9.27+ or &gt;=8 &lt;9; separate several with commas.</p>
              <label>Rule type <select value={manual.kind} onChange={setField("kind")}>
                {MANUAL_RULE_KINDS.map((entry) => <option key={entry.value} value={entry.value}>{entry.label}</option>)}
              </select></label>
              {kind && <p className="hint">{kind.help}</p>}
              <label>Product <input value={product} readOnly /></label>
              {manual.kind === "os_support" && (<>
                <label>Operating system <input value={manual.os} onChange={setField("os")}
                  placeholder="Red Hat Enterprise Linux, AIX, Windows Server" required /></label>
                <label>OS versions <input value={manual.os_versions} onChange={setField("os_versions")}
                  placeholder="8.10, 9.x" required /></label>
                <label>Product versions (optional) <input value={manual.when} onChange={setField("when")}
                  placeholder="9.27.x (empty: every version)" /></label>
                <label>Supported? <select value={manual.supported} onChange={setField("supported")}>
                  <option value="yes">Supported</option><option value="no">Not supported</option></select></label>
              </>)}
              {manual.kind === "requirement" && (<>
                <label>Product versions <input value={manual.when} onChange={setField("when")} placeholder="10.1.x" required /></label>
                <label>Requires (runtime or component) <input value={manual.dependency} onChange={setField("dependency")}
                  placeholder="Java, OpenSSL" required /></label>
                <label>Required version <input value={manual.spec} onChange={setField("spec")} placeholder="11+" required /></label>
              </>)}
              {manual.kind === "application_support" && (<>
                <label>Application <input value={manual.application} onChange={setField("application")} required /></label>
                <label>Application release <input value={manual.when} onChange={setField("when")} placeholder="10.0" required /></label>
                <label>Supported product versions <input value={manual.versions} onChange={setField("versions")}
                  placeholder="9.0.x, 10.1.x" required /></label>
              </>)}
              {manual.kind === "behaviour_change" && (
                <label>Since release <input value={manual.since} onChange={setField("since")} placeholder="2.4.60" required /></label>
              )}
              <label>{manual.kind === "behaviour_change" ? "What changes" : "Note (optional)"}
                <textarea value={manual.note} onChange={setField("note")} required={manual.kind === "behaviour_change"} /></label>
              <label>Source (optional) <input value={manual.source} onChange={setField("source")}
                placeholder="https://vendor.example/support-matrix or where the rule comes from" /></label>
              <label className="checkbox"><input type="checkbox" checked={manual.this_cve_only}
                onChange={(event) => setManual((current) => ({ ...current, this_cve_only: event.target.checked }))} />
                Only for {result.cve} (otherwise used for every CVE of {product})</label>
              <button className="button button-secondary" disabled={ruleBusy}>{ruleBusy ? "Checking…" : "Check rule"}</button>
            </form>
          ) : (
            <form onSubmit={draftNewRule}>
              <p>Provide an approved publisher HTTPS page or paste a compatibility rule. A small model call will draft one rule for review.</p>
              <label>Source URL <input type="url" value={sourceUrl} onChange={(event) => setSourceUrl(event.target.value)}
                placeholder="https://publisher.example/support" /></label>
              <label>Compatibility rule text <textarea value={ruleText} onChange={(event) => setRuleText(event.target.value)}
                placeholder="Paste the exact vendor statement or the rule you want checked" /></label>
              <button className="button button-secondary" disabled={ruleBusy || (!sourceUrl.trim() && !ruleText.trim())}>
                {ruleBusy ? "Working…" : "Draft rule"}</button>
            </form>
          )}
          {draft && (
            <div>
              <p><strong>Review the rule before saving</strong></p>
              <p>{describeProposal(draft.proposal)}</p>
              {draft.proposal.quote !== describeProposal(draft.proposal) && <blockquote>{draft.proposal.quote}</blockquote>}
              <p>Source: {draft.proposal.source}. {draft.proposal.cve ? `Used for ${draft.proposal.cve} only.` : "Used for every CVE of this product."} This rule is not in the knowledge base yet.</p>
              <details><summary>Full rule fields</summary><pre>{JSON.stringify(draft.proposal, null, 2)}</pre></details>
              <button type="button" className="button button-primary" disabled={ruleBusy} onClick={applyNewRule}>
                Save rule and recheck</button>
            </div>
          )}
          {ruleMessage && <p role="status">{ruleMessage}</p>}
        </div>
  );
}

const RULE_KINDS = {
  requires: "Requirement", public_release_limit: "Public release", major_change: "Major version change",
  end_of_life: "End of life", end_of_life_branches: "End-of-life branches", lifecycle: "Support lifecycle",
  behaviour_change: "Behaviour change", note: "Note", upgrade_together: "Upgrade together",
  os_support: "OS support",
};

// The knowledge-base rules the check used, with whether each one covers the fix version.
function AppliedRules({ rules, productKey, target }) {
  if (!rules?.length) return null;
  const covering = rules.filter((rule) => rule.applies === true).length;
  return (
    <details className="applied-rules">
      <summary>Compatibility rules for {productKey}: {rules.length}
        {covering ? ` (${covering} cover ${target})` : ""}</summary>
      <ul>
        {rules.map((rule, index) => (
          <li key={`${rule.kind}-${index}`} className={rule.applies === false ? "is-other" : ""}>
            <span className="rule-kind">{RULE_KINDS[rule.kind] || humanize(rule.kind)}</span>
            {rule.applies === true && <span className="rule-tag rule-applies">applies to {target}</span>}
            {rule.applies === false && <span className="rule-tag">other versions</span>}
            {rule.verify && <span className="rule-tag rule-verify">confirm</span>}
            <div>{rule.text}{rule.source && /^https?:\/\//.test(rule.source)
              ? <> · <a href={rule.source} target="_blank" rel="noreferrer">Source</a></> : null}</div>
          </li>
        ))}
      </ul>
    </details>
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
            </ul>
            {passed > 0 && (
              <details className="compatibility-passed" open={!flagged.length}>
                <summary>Why this version fits: {passed} check(s) passed</summary>
                <ul className="compatibility-checks">
                  {(evaluation.checks || []).filter((check) => check.status === "PASS").map((check) => (
                    <li key={check.id + check.detail}>
                      <span className="check-pass">PASS</span>
                      <div><strong>{humanize(check.id)}:</strong> {check.detail}</div>
                    </li>
                  ))}
                </ul>
              </details>
            )}
            <AppliedRules rules={evaluation.applied_rules} productKey={evaluation.product_rules} target={evaluation.target} />
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

// Results whose compatibility could not be established, and why.
const COMPATIBILITY_GAP_STATUSES = ["AWAITING_RULES", "NOT_EVALUATED", "FAILED", "UNVERIFIED"];

function compatibilityGap(result) {
  const compatibility = result.compatibility;
  if (!compatibility) return { label: "Not checked", reason: "This result has no compatibility check." };
  if (compatibility.host_found === false) {
    return { label: "Server not in inventory", reason: `No inventory host matched ${result.host || "this item"}, so nothing could be checked.` };
  }
  const request = compatibility.rule_request || {};
  switch (compatibility.status) {
    case "AWAITING_RULES":
      return { label: "No vendor rule", reason: [request.product, request.target_version].filter(Boolean).join(" ")
        + (request.application ? ` on ${request.application}${request.application_version ? ` ${request.application_version}` : ""}` : "")
        + ": no compatibility rule covers this fix yet. Answer the questions or supply a source." };
    case "NOT_EVALUATED":
      return { label: "No fix to check", reason: compatibility.summary || `Verdict ${humanize(result.verdict)}: there is no fix to check.` };
    case "FAILED":
      return { label: "Check failed", reason: compatibility.error || "The compatibility check failed." };
    case "UNVERIFIED":
      return { label: "Unverified", reason: "Checked, but facts it needs (version, ownership or runtime) are unknown." };
    default:
      return null;
  }
}

function CompatibilityGaps({ results }) {
  const groups = new Map();
  for (const result of results || []) {
    const gap = compatibilityGap(result);
    if (!gap) continue;
    const key = [result.product, result.component, result.host || result.compatibility?.host || ""].join("|");
    const group = groups.get(key) || { result, gap, cves: [], questions: 0 };
    group.cves.push(result);
    group.questions += result.compatibility?.questions?.length || 0;
    groups.set(key, group);
  }
  if (!groups.size) return null;
  const entries = [...groups.values()];
  return (
    <details className="compat-gaps" open={entries.length <= 8}>
      <summary>
        <AlertTriangle size={15} /> Compatibility not available for {entries.length} component{entries.length === 1 ? "" : "s"}
        <span>({entries.reduce((sum, entry) => sum + entry.cves.length, 0)} result(s))</span>
      </summary>
      <div className="table-shell">
        <table>
          <thead>
            <tr><th>Component</th><th>Server</th><th>Why</th><th>CVEs</th><th>Open questions</th></tr>
          </thead>
          <tbody>
            {entries.map(({ result, gap, cves, questions }) => (
              <tr key={resultAnchor(result)}>
                <td><strong>{result.product}</strong>{result.component ? ` · ${result.component}` : ""}
                  {result.component_version ? <small> ({result.component_version})</small> : null}</td>
                <td>{result.host || result.compatibility?.host || "Unknown"}</td>
                <td className="compat-gap-reason"><span className="compat-gap-label">{gap.label}</span> {gap.reason}</td>
                <td>{cves.map((entry, index) => (
                  <span key={resultAnchor(entry)}>{index ? ", " : ""}<a href={`#${resultAnchor(entry)}`}>{entry.cve}</a></span>
                ))}</td>
                <td>{questions || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </details>
  );
}

// One card per component of a run (and server): a miniature of the details until opened.
const UNSPECIFIED_COMPONENT = /^(unspecified component|unknown|unidentified)?$/i;
const VERDICT_RANK = ["FIX_AVAILABLE", "NEEDS_INPUT", "ASSESSMENT_LIMITED", "INSUFFICIENT_EVIDENCE", "NOT_APPLICABLE"];

function resultGroups(results) {
  const groups = new Map();
  for (const result of results) {
    const key = [result.run_id, result.product, result.component_id || result.component, result.host || ""].join("|");
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(result);
  }
  return [...groups.values()];
}

// "12.1.0.2.171017 / 12.2.0.1.171017": the Oracle Database patch levels a CPU-named fix gives.
function patchVersions(remedy) {
  return (remedy?.patch_versions || []).map((entry) => entry.version).join(" / ") || null;
}

function fixLabel(result) {
  const remedy = result.recommended_remediation || {};
  return remedy.target_version || patchVersions(remedy) || remedy.patch_id || result.available_fix?.identifier || null;
}

// The verdict a component card leads with (its edge colour and sort order).
function leadVerdict(results) {
  if (results.some((result) => result.fix_available)) return "FIX_AVAILABLE";
  const ranked = results.map((result) => result.verdict)
    .sort((a, b) => (VERDICT_RANK.indexOf(a) + 99) % 99 - (VERDICT_RANK.indexOf(b) + 99) % 99);
  return ranked[0];
}

const RESULT_SORTS = [
  { id: "verdict", label: "Fix first" },
  { id: "product", label: "Product" },
  { id: "server", label: "Server" },
];

function sortGroups(groups, sort) {
  const text = (group, field) => String(group[0][field] || "").toLowerCase();
  const rank = (group) => (VERDICT_RANK.indexOf(leadVerdict(group)) + 99) % 99;
  return [...groups].sort((a, b) => sort === "product" ? text(a, "product").localeCompare(text(b, "product"))
    : sort === "server" ? (text(a, "host") || "~").localeCompare(text(b, "host") || "~") || text(a, "product").localeCompare(text(b, "product"))
      : rank(a) - rank(b) || b.length - a.length);
}

function matchesQuery(result, query) {
  const text = query.trim().toLowerCase();
  return !text || [result.cve, result.product, result.component, result.host, result.component_version,
    fixLabel(result), humanize(result.verdict)].some((value) => String(value || "").toLowerCase().includes(text));
}

function ComponentResultCard({ results: savedResults, jobId, expand }) {
  const [results, setResults] = useState(savedResults);
  useEffect(() => { setResults(savedResults); }, [savedResults]);
  const anchors = results.map(resultAnchor);
  const fromHash = () => Math.max(0, anchors.indexOf(window.location.hash.slice(1)));
  const [open, setOpen] = useState(() => anchors.includes(window.location.hash.slice(1)));
  // "Expand all" / "Collapse all" from the results toolbar.
  useEffect(() => { if (expand) setOpen(expand.open); }, [expand]);
  const [selected, setSelected] = useState(fromHash);
  useEffect(() => {
    const follow = () => {
      if (anchors.includes(window.location.hash.slice(1))) { setOpen(true); setSelected(fromHash()); }
    };
    window.addEventListener("hashchange", follow);
    return () => window.removeEventListener("hashchange", follow);
  });
  const first = results[0];
  const counts = {};
  for (const result of results) counts[result.verdict] = (counts[result.verdict] || 0) + 1;
  const verdicts = Object.keys(counts).sort((a, b) =>
    (VERDICT_RANK.indexOf(a) + 99) % 99 - (VERDICT_RANK.indexOf(b) + 99) % 99);
  const lead = results.some((result) => result.fix_available) ? "FIX_AVAILABLE" : verdicts[0];
  const versions = [...new Set(results.map((result) => result.component_version).filter(Boolean))];
  const fixes = [...new Set(results.map(fixLabel).filter(Boolean))];
  const compat = [...new Set(results.map((result) => result.compatibility?.status)
    .filter((status) => status && status !== "NOT_EVALUATED"))];
  const shownCves = results.slice(0, 4);
  const current = results[Math.min(selected, results.length - 1)];
  return (
    <article className={`component-card verdict-edge-${String(lead).toLowerCase()}${open ? " is-open" : ""}`}>
      {anchors.map((anchor) => <span key={anchor} id={anchor} className="result-anchor" />)}
      <button type="button" className="component-card-summary" aria-expanded={open} onClick={() => setOpen(!open)}>
        <div className="component-card-top">
          <div className="component-card-title">
            <strong>{first.product || "Unidentified product"}</strong>
            <small>{[first.host ? `Server ${first.host}` : "No server named", first.applications?.find(
              (name) => name && name !== "Unspecified Application")].filter(Boolean).join(" · ")}</small>
          </div>
          <div className="component-card-badges">
            {verdicts.map((verdict) => (
              <span key={verdict} className={`verdict verdict-${String(verdict).toLowerCase()}`}>
                {humanize(verdict)}{results.length > 1 ? ` · ${counts[verdict]}` : ""}
              </span>
            ))}
            {compat.map((status) => (
              <span key={status} className={`compatibility compatibility-${String(status).toLowerCase()}`}>{humanize(status)}</span>
            ))}
          </div>
          {open ? <ChevronDown size={18} className="component-card-chevron" /> : <ChevronRight size={18} className="component-card-chevron" />}
        </div>
        <dl className="component-card-facts">
          <div><dt>Installed</dt><dd>{versions.join(", ") || "Unknown"}</dd></div>
          <div><dt>Fix</dt><dd className={fixes.length ? "has-fix" : ""}>{fixes.join(", ") || "None found"}</dd></div>
          <div className="component-card-cves">
            <dt>CVEs ({results.length})</dt>
            <dd>
              {shownCves.map((result) => <span key={result.cve} className="cve-pill">{result.cve}</span>)}
              {results.length > shownCves.length && <span className="cve-more">+{results.length - shownCves.length} more</span>}
            </dd>
          </div>
        </dl>
      </button>
      {open && (
        <div className="component-card-body">
          {results.length > 1 && (
            <div className="cve-tabs" role="tablist" aria-label="CVEs of this component">
              {results.map((result, index) => (
                <button key={resultAnchor(result)} type="button" role="tab" aria-selected={index === selected}
                  className={`cve-tab verdict-edge-${String(result.verdict).toLowerCase()}${index === selected ? " active" : ""}`}
                  onClick={() => setSelected(index)}>
                  <strong>{result.cve}</strong>
                  <small>{humanize(result.verdict)}{fixLabel(result) ? ` · ${fixLabel(result)}` : ""}</small>
                </button>
              ))}
            </div>
          )}
          <RemediationResultCard key={resultAnchor(current)} result={current} jobId={jobId}
            onResult={(next) => setResults((list) => list.map((item) => (item === current ? next : item)))} />
        </div>
      )}
    </article>
  );
}

function RemediationResultCard({ result: savedResult, jobId, onResult }) {
  // Replaced by the re-assessment when the server's script output is pasted into this card.
  const [result, setResultState] = useState(savedResult);
  useEffect(() => { setResultState(savedResult); }, [savedResult]);
  const setResult = (next) => { setResultState(next); onResult?.(next); };
  // A context file uploaded on this card: stored for the server and this CVE re-assessed with it.
  const applyServerContext = async (text) => {
    const response = await fetch("/api/compatibility/context", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ run_id: result.run_id, cve: result.cve, component_id: result.component_id,
        host: result.host || null, text }),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || `Applying the context failed (HTTP ${response.status}).`);
    if (data.result) setResult(data.result);
    return data.context || {};
  };
  const [currentCompatibility, setCurrentCompatibility] = useState(result.compatibility);
  useEffect(() => { setCurrentCompatibility(result.compatibility); }, [result.compatibility]);
  const lookupSources = uniqueLookupSources(result.lookup_sources);
  const context = [
    ...(result.components || []),
    ...(result.applications || []),
    ...(result.operating_systems || []),
  ];
  // Shown inside its component's card (ComponentResultCard), which lists every CVE.
  return (
    <div className="remediation-result-detail">
      <header className="result-card-header">
        <div>
          <div className="result-title-row">
            <h2>{result.cve}</h2>
            <span className={`verdict verdict-${String(result.verdict).toLowerCase()}`}>
              {humanize(result.verdict)}
            </span>
            {result.fix_available && result.verdict !== "FIX_AVAILABLE" && result.available_fix && (
              <span className="verdict verdict-fix_available" title="A fix exists for the installed version">
                Fix available: {result.available_fix.identifier}
                {result.available_fix.reliability === "unreliable" ? " (unverified)" : ""}
              </span>
            )}
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
            {result.host && <span className="server-chip">Server {result.host}</span>}
            {result.component_id && <span>Component ID {result.component_id}</span>}
            {context.filter(Boolean).map((item, index) => <span key={`${item}-${index}`}>{item}</span>)}
          </div>
        </div>
      </header>

      <dl className="result-metadata">
        <div><dt>Affected component</dt><dd>{result.component || "Unknown"}</dd></div>
        <div><dt>Component version</dt><dd>{result.component_version || "Unknown"}
          {result.component_version_assumed ? " (assumed from the CVE's affected versions)" : ""}</dd></div>
        <div><dt>Application</dt><dd>{result.applications?.join(" | ") || "Unknown"}</dd></div>
        <div><dt>Application version</dt><dd>{result.application_version || "Unknown"}</dd></div>
        <div><dt>Application path</dt><dd>{result.application_install_path || "Unknown"}</dd></div>
        <div><dt>Component path</dt><dd>{result.component_path || "Unknown"}</dd></div>
      </dl>

      {result.host && result.context_missing && (
        <section className="server-context-callout">
          <h3>Context for {result.host} has not been collected</h3>
          <p>This CVE was assessed once, on {result.host}, without its installed versions. {SCRIPT_HELP} Then run
            remediation for this component again, or upload the output (or an inventory YAML) here: this CVE is re-assessed with it.</p>
          <ServerContextActions server={result.host} jobId={jobId} onApply={applyServerContext} />
        </section>
      )}

      {result.host && result.context_source === "central baseline" && (
        <section className="server-context-callout">
          <h3>{result.host}: assessed with the central baseline</h3>
          <p>No context has been collected for {result.host}, so its versions come from the central baseline
            (the organisation's observed middleware build), not from the server itself. {SCRIPT_HELP} Upload the
            output (or an inventory YAML) here and this CVE is re-assessed with the server's own versions.</p>
          <ServerContextActions server={result.host} jobId={jobId} onApply={applyServerContext} />
        </section>
      )}

      {result.other_hosts?.length > 0 && (
        <details className="server-context-others">
          <summary>Also found on {result.other_hosts.length} other server{result.other_hosts.length === 1 ? "" : "s"}
            {" "}(not assessed separately; collect a server's context to check it)</summary>
          <ul className="server-list">
            {result.other_hosts.map((server) => (
              <li key={server}>
                <div><strong>{server}</strong></div>
                <ServerContextActions server={server} jobId={jobId} />
              </li>
            ))}
          </ul>
        </details>
      )}

      <AvailableFixSection result={result} compatibility={currentCompatibility} />

      {/* A lead for another product or release line (IBM TXSeries for OpenJ9) is not this copy's
          fix: it stays in "Fixes reported by each source" below, not highlighted here. */}
      {!result.recommended_remediation && !result.available_fix && result.primary_source_fix
        && result.primary_source_fix.match_scope !== "source_only" && (
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

          <CardServerContext item={result} compatibility={currentCompatibility} onChecked={setCurrentCompatibility}
            onResult={setResult} />

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
    </div>
  );
}

// Search across every column plus one filter per column, set from the column's header.
function useTableFilter(columns, rows, extra = null) {
  const [query, setQuery] = useState("");
  const [filters, setFilters] = useState([]);
  const entries = useMemo(
    () => filterRows(rows, columns, { query, filters, extra }),
    [rows, columns, query, filters, extra],
  );
  return { query, setQuery, filters, setFilters, entries };
}

function filterSummary(filter) {
  if (filter.mode === "in") {
    const names = filter.values.map((value) => value || "(empty)");
    return names.length > 2 ? `${names.slice(0, 2).join(", ")} +${names.length - 2}` : names.join(", ");
  }
  if (filter.mode === "empty") return "is empty";
  if (filter.mode === "not_empty") return "has a value";
  return `contains "${filter.value}"`;
}

// A column header with a filter button: tick the column's values, or type text for a column
// with too many distinct values.
function ColumnHeader({ column, rows, state }) {
  const { filters, setFilters } = state;
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState("");
  const [position, setPosition] = useState(null);
  const button = useRef(null);
  const panel = useRef(null);
  const current = filters.find((filter) => filter.column === column);
  const values = useMemo(() => (open ? distinctValues(rows, column, COLUMN_VALUE_LIMIT) : null), [open, rows, column]);
  const hasEmpty = useMemo(() => open && rows.some((row) => !String(row[column] ?? "").trim()), [open, rows, column]);

  useEffect(() => {
    if (!open) return undefined;
    const close = (event) => {
      if (event.type === "keydown" ? event.key === "Escape"
        : !panel.current?.contains(event.target) && !button.current?.contains(event.target)) setOpen(false);
    };
    const shut = () => setOpen(false);
    document.addEventListener("mousedown", close);
    document.addEventListener("keydown", close);
    window.addEventListener("resize", shut);
    return () => {
      document.removeEventListener("mousedown", close);
      document.removeEventListener("keydown", close);
      window.removeEventListener("resize", shut);
    };
  }, [open]);

  function toggleOpen(event) {
    event.stopPropagation();
    if (!open) {
      const box = button.current.getBoundingClientRect();
      setPosition({ top: box.bottom + 6, left: Math.max(8, Math.min(box.left, window.innerWidth - 288)) });
      setSearch("");
    }
    setOpen(!open);
  }

  function setFilter(next) {
    setFilters((list) => [...list.filter((filter) => filter.column !== column),
      ...(next ? [{ column, ...next }] : [])]);
  }

  const picked = current?.mode === "in" ? current.values : [];
  function toggleValue(value) {
    const next = picked.includes(value) ? picked.filter((item) => item !== value) : [...picked, value];
    setFilter(next.length ? { mode: "in", values: next } : null);
  }
  const options = [...(hasEmpty ? [""] : []), ...(values || [])]
    .filter((value) => !search || (value || "(empty)").toLowerCase().includes(search.toLowerCase()));

  return (
    <div className="column-header">
      <span>{column}</span>
      <button ref={button} type="button" className={`column-filter-button${current ? " active" : ""}`}
        aria-label={`Filter ${column}`} aria-expanded={open} title={current ? `${column}: ${filterSummary(current)}` : `Filter ${column}`}
        onClick={toggleOpen}>
        <ListFilter size={13} />
      </button>
      {open && position && (
        <div ref={panel} className="column-filter-panel" style={position} onClick={(event) => event.stopPropagation()}>
          <strong>{column}</strong>
          {values ? (
            <>
              <input type="search" placeholder="Find a value…" value={search} autoFocus
                onChange={(event) => setSearch(event.target.value)} />
              <div className="column-filter-actions">
                <button type="button" onClick={() => setFilter(options.length ? { mode: "in", values: [...new Set([...picked, ...options])] } : null)}>
                  Select {search ? "shown" : "all"}
                </button>
                <button type="button" onClick={() => setFilter(null)}>Clear</button>
              </div>
              <ul className="column-filter-values">
                {options.map((value) => (
                  <li key={value || "(empty)"}>
                    <label>
                      <input type="checkbox" checked={picked.includes(value)} onChange={() => toggleValue(value)} />
                      <span className={value ? "" : "empty"}>{value || "(empty)"}</span>
                    </label>
                  </li>
                ))}
                {!options.length && <li className="column-filter-none">No matching values</li>}
              </ul>
            </>
          ) : (
            <>
              <input type="search" placeholder="Contains…" autoFocus
                value={current?.mode === "contains" ? current.value : ""}
                onChange={(event) => setFilter(event.target.value ? { mode: "contains", value: event.target.value } : null)} />
              <div className="column-filter-actions">
                <button type="button" onClick={() => setFilter({ mode: "not_empty" })}>Has a value</button>
                <button type="button" onClick={() => setFilter({ mode: "empty" })}>Is empty</button>
                <button type="button" onClick={() => setFilter(null)}>Clear</button>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}

function FilterBar({ state, total, children, extraActive = false, onClearExtra }) {
  const { query, setQuery, filters, setFilters, entries } = state;
  const active = Boolean(query.trim()) || filters.length > 0 || extraActive;

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
        <span className="filter-hint"><ListFilter size={13} /> Filter a column from its header</span>
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
          {filters.map((filter) => (
            <span className="filter-chip" key={filter.column}>
              <strong>{filter.column}:</strong> {filterSummary(filter)}
              <button type="button" aria-label={`Remove ${filter.column} filter`}
                onClick={() => setFilters((list) => list.filter((item) => item.column !== filter.column))}>
                <X size={13} />
              </button>
            </span>
          ))}
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
      <FilterBar state={filter} total={rows.length}
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
              {columns.map((column) => <th key={column}><ColumnHeader column={column} rows={rows} state={filter} /></th>)}
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
      <FilterBar state={filter} total={rows.length} />
      <div className="table-shell">
        <table>
          <thead>
            <tr>
              <th className="row-number">#</th>
              {columns.map((column) => (
                <th key={column}><ColumnHeader column={column} rows={rows} state={filter} /></th>
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

// Download the read-only collection script for one server, and upload what it printed.
// onApply(text): on a result card, the file is applied to that card instead (stored as the
// server's context and the CVE re-assessed with it); it returns the stored-context summary.
function ServerContextActions({ server, jobId, onUploaded, onApply }) {
  const input = useRef(null);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);
  const [failure, setFailure] = useState("");

  async function upload(file) {
    if (!file) return;
    setBusy(true);
    setFailure("");
    setResult(null);
    try {
      if (onApply) {
        setResult({ ...(await onApply(await file.text())), reassessed: true });
        return;
      }
      const body = new FormData();
      body.append("file", file);
      body.append("server", server);
      body.append("job_id", jobId || "");
      const response = await fetch("/api/context-upload", { method: "POST", body });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Upload failed.");
      setResult(data);
      onUploaded?.(data);
    } catch (error) {
      setFailure(error.message);
    } finally {
      setBusy(false);
      if (input.current) input.current.value = "";
    }
  }

  return (
    <div className="server-actions">
      <div className="server-actions-buttons">
        <a className="button button-secondary button-small"
          href={`/api/context-script?server=${encodeURIComponent(server)}&job_id=${encodeURIComponent(jobId || "")}`}>
          <Download size={14} /> Download script
        </a>
        <button type="button" className="button button-primary button-small" disabled={busy}
          onClick={() => input.current?.click()}>
          {busy ? <LoaderCircle className="spin" size={14} /> : <UploadCloud size={14} />}
          {busy ? "Converting…" : "Upload output"}
        </button>
        <input ref={input} type="file" accept=".txt,text/plain" hidden onChange={(event) => upload(event.target.files[0])} />
      </div>
      {result && (
        <p className="server-upload-ok">
          <Check size={13} /> Stored {result.hostname}{result.os ? ` (${result.os})` : ""}: {result.components} components.
          {" "}{result.database?.message}
          {result.warnings?.map((warning) => <span key={warning}> {warning}</span>)}
          {" "}{result.reassessed ? "This CVE was re-assessed with it (card updated)."
            : "Used by the next remediation run; to update a result already shown, use \"Update server context\" on its card."}
        </p>
      )}
      {failure && <p className="server-upload-error"><AlertTriangle size={13} /> {failure}</p>}
    </div>
  );
}

const SCRIPT_HELP = "Download the collection script for this server's operating system (a shell script, or PowerShell "
  + "for Windows) and run it on the server as your normal user (no root or administrator rights needed), as its first "
  + "comment shows; then upload the aegis_context.txt it writes. It only reads (fixed, allowlisted commands), runs at the "
  + "lowest priority, masks passwords and tokens before printing, and writes nothing on the server except that file.";

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
              {fix && <span>{fix.cve}{fix.host ? ` on ${fix.host}` : ""} → {fix.target || "fix recorded"}</span>}
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
  // Sidebar page: the CVE workspace (all workflow views) or the context gatherer.
  const [page, setPage] = useState("workspace");
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
  // Delivery agent: the runs (and, for previous fixes, the results) a server delivery is built from.
  const [deliveryScope, setDeliveryScope] = useState(null);
  const [middlewareFrom, setMiddlewareFrom] = useState(null);
  const [resultQuery, setResultQuery] = useState("");
  const [resultSort, setResultSort] = useState("verdict");
  const [expandAll, setExpandAll] = useState(null);
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
    setDeliveryScope(null);
    setResultQuery("");
    setExpandAll(null);
    setLoadingResults(false);
    setLoadingPreviousFixes(false);
    setActiveTab("deduplicated");
    setStart(1);
    setCount(10);
    setError("");
  }

  // Build the server delivery from the results on screen (this file's runs, or the previous fixes shown).
  function openDelivery(source = view) {
    const previous = source === "previous_fixes";
    const shown = previous ? previousFixResults : remediationResults;
    if (!shown?.run_ids?.length) return;
    setDeliveryScope({
      runIds: shown.run_ids,
      items: previous ? shown.results.map((result) => ({
        run_id: result.run_id, cve: result.cve, component_id: result.component_id, host: result.host })) : null,
      label: previous ? "the previous fixes shown"
        : `${shown.run_ids.length} remediation run${shown.run_ids.length === 1 ? "" : "s"} of this file`,
      from: previous ? "previous_fixes" : "results",
    });
    setView("delivery");
  }

  // Middleware delivery: the whole uploaded file by middleware -> product -> CVE.
  function openMiddleware() {
    if (!dataset?.job_id || !grouped) return;
    if (view !== "middleware_delivery") setMiddlewareFrom(view);
    setView("middleware_delivery");
  }

  // A link from the middleware page to the result card a fix came from: this file's results
  // when the card is there, else the previous fixes saved for that grouped row.
  async function openResultCard(fix, rowIndex) {
    const anchor = resultAnchor(fix.card);
    const has = (shown) => shown?.results?.some((result) => resultAnchor(result) === anchor);
    setVerdictFilter(null);
    setResultQuery("");
    if (has(remediationResults)) setView("results");
    else if (has(previousFixResults)) setView("previous_fixes");
    else await showPreviousFixes([rowIndex]);
    // After the results render: the card opens from the hash and is scrolled to.
    setTimeout(() => {
      if (window.location.hash === `#${anchor}`) window.dispatchEvent(new HashChangeEvent("hashchange"));
      else window.location.hash = anchor;
      document.getElementById(anchor)?.scrollIntoView({ behavior: "smooth", block: "start" });
    }, 120);
  }

  // Steps in the top bar: a step is clickable once its page has something to show.
  const STEPS = ["Upload", "Enrich", "Select components", "Results", "Delivery"];
  const currentStep = !dataset ? 0 : view === "workspace" ? 1 : view === "grouped" ? 2
    : view === "delivery" || view === "middleware_delivery" ? 4 : 3;
  function stepTarget(index) {
    if (index === 1 && dataset) return () => setView("workspace");
    if (index === 2 && grouped) return () => setView("grouped");
    if (index === 3 && remediationResults) return () => setView("results");
    if (index === 4 && (remediationResults || deliveryScope)) {
      // This file's latest runs when there are any; otherwise the delivery last opened.
      return () => (remediationResults ? openDelivery("results") : setView("delivery"));
    }
    if (index === 4 && grouped) return openMiddleware;
    return null;
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
        {page === "workspace" && <ol className="step-indicator" aria-label="Workflow steps">
          {STEPS.map((label, index) => {
            const go = index === currentStep ? null : stepTarget(index);
            const done = index < currentStep || (index > currentStep && go);
            return (
              <li key={label} className={index === currentStep ? "is-current" : done ? "is-done" : ""}
                aria-current={index === currentStep ? "step" : undefined}>
                <button type="button" disabled={!go} onClick={go || undefined}
                  title={go ? `Go to ${label.toLowerCase()}` : undefined}>
                  <span>{done ? <Check size={12} /> : index + 1}</span>{label}
                </button>
              </li>
            );
          })}
        </ol>}
        {dataset && page === "workspace" && (
          <button className="button button-ghost" onClick={reset}>
            <RefreshCw size={16} /> New file
          </button>
        )}
      </header>

      <div className="app-body">
      <nav className="side-nav" aria-label="Pages">
        <button type="button" className={page === "workspace" ? "is-active" : ""} onClick={() => setPage("workspace")}
          aria-current={page === "workspace" ? "page" : undefined}>
          <Workflow size={18} /><span>CVE workspace</span>
        </button>
        <button type="button" className={page === "context_gatherer" ? "is-active" : ""}
          onClick={() => setPage("context_gatherer")} aria-current={page === "context_gatherer" ? "page" : undefined}>
          <Server size={18} /><span>Context gatherer</span>
        </button>
        <button type="button" className={page === "compat_rules" ? "is-active" : ""}
          onClick={() => setPage("compat_rules")} aria-current={page === "compat_rules" ? "page" : undefined}>
          <ShieldCheck size={18} /><span>Compatibility rules</span>
        </button>
      </nav>
      <main>
        {/* Kept mounted for the whole session (hidden on other pages), so its servers, uploads,
            generated scripts and filters stay as they were when the user comes back. */}
        <div hidden={page !== "context_gatherer"}>
          <ContextGathererView results={remediationResults} jobId={dataset?.job_id}
            sourceName={grouped?.source_filename || dataset?.filename}
            enrichedKey={grouped ? `${grouped.filename || ""}:${grouped.rows?.length || 0}` : ""}
            onOpenWorkspace={() => setPage("workspace")} />
        </div>
        {page === "compat_rules" && (
          <CompatRulesView jobId={dataset?.job_id}
            sourceName={grouped?.source_filename || dataset?.filename}
            enrichedKey={grouped ? `${grouped.filename || ""}:${grouped.rows?.length || 0}` : ""}
            onOpenWorkspace={() => setPage("workspace")} />
        )}
        {page === "context_gatherer" || page === "compat_rules" ? null : !dataset ? (
          <UploadPanel
            uploading={uploading}
            setUploading={setUploading}
            setError={setError}
            onUploaded={(result) => {
              setDataset(result);
              setCount(Math.min(10, result.unique_count));
            }}
          />
        ) : view === "delivery" && deliveryScope ? (
          <DeliveryView runIds={deliveryScope.runIds} items={deliveryScope.items} scopeLabel={deliveryScope.label}
            onMiddleware={grouped && dataset?.job_id ? openMiddleware : null}
            onBack={() => setView(deliveryScope.from === "previous_fixes" && previousFixRuns.length ? "previous_fixes"
              : remediationResults ? "results" : "grouped")} />
        ) : view === "middleware_delivery" && dataset?.job_id && grouped ? (
          <MiddlewareDeliveryView jobId={dataset.job_id} sourceName={grouped.source_filename || dataset.filename}
            onOpenCard={openResultCard}
            onServerDelivery={remediationResults ? () => openDelivery("results") : deliveryScope ? () => setView("delivery") : null}
            onBack={() => setView(middlewareFrom && middlewareFrom !== "middleware_delivery" ? middlewareFrom : "grouped")} />
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
              <div className="results-heading-side">
                <button type="button" className="button button-primary" disabled={!displayResults.results.length}
                  onClick={() => openDelivery()}>
                  <GitBranch size={16} /> Build server delivery
                </button>
                <button type="button" className="button button-secondary" disabled={!grouped}
                  onClick={openMiddleware}>
                  <Layers3 size={16} /> Middleware delivery
                </button>
                <details className="run-identity">
                  <summary>{displayResults.run_ids.length} remediation run{displayResults.run_ids.length === 1 ? "" : "s"}</summary>
                  {displayResults.run_ids.map((runId) => <code key={runId}>{runId}</code>)}
                </details>
              </div>
            </div>

            <section className="results-summary" aria-label="Filter results by verdict">
              <div className="summary-icon"><CircleCheckBig size={24} /></div>
              {[
                { id: null, label: "Assessments", count: displayResults.total },
                ...MAIN_VERDICTS.map((verdict) => ({
                  id: verdict.id, label: verdict.label,
                  // "Fix available" counts every result with a fix for its installed copy,
                  // whatever its verdict (a not-affected copy can still have the fix).
                  count: verdict.id === "FIX_AVAILABLE"
                    ? displayResults.results.filter((result) =>
                      result.verdict === "FIX_AVAILABLE" || result.fix_available).length
                    : displayResults.verdict_counts[verdict.id] || 0,
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

            <CompatibilityGaps results={displayResults.results} />

            {view === "results" && pipelineRun && <WorkflowView run={pipelineRun} />}

            {(() => {
              const filtered = displayResults.results.filter((result) => (!verdictFilter
                || (verdictFilter === "OTHER"
                  ? !MAIN_VERDICTS.some((verdict) => verdict.id === result.verdict)
                  : verdictFilter === "FIX_AVAILABLE"
                    ? result.verdict === "FIX_AVAILABLE" || result.fix_available
                    : result.verdict === verdictFilter)) && matchesQuery(result, resultQuery));
              const groups = sortGroups(resultGroups(filtered), resultSort);
              return (
                <div className="results-list">
                  <div className="results-toolbar">
                    <label className="search-field">
                      <Search size={16} aria-hidden="true" />
                      <input type="search" placeholder="Search CVE, product, server or fix…" value={resultQuery}
                        aria-label="Search results" onChange={(event) => setResultQuery(event.target.value)} />
                      {resultQuery && (
                        <button type="button" aria-label="Clear search" onClick={() => setResultQuery("")}><X size={14} /></button>
                      )}
                    </label>
                    <div className="segmented" role="tablist" aria-label="Sort components">
                      {RESULT_SORTS.map((option) => (
                        <button key={option.id} role="tab" aria-selected={resultSort === option.id}
                          className={resultSort === option.id ? "active" : ""} onClick={() => setResultSort(option.id)}>
                          {option.label}
                        </button>
                      ))}
                    </div>
                    <div className="results-toolbar-actions">
                      <button type="button" className="button button-ghost button-small"
                        onClick={() => setExpandAll({ open: true, at: Date.now() })}>Expand all</button>
                      <button type="button" className="button button-ghost button-small"
                        onClick={() => setExpandAll({ open: false, at: Date.now() })}>Collapse all</button>
                    </div>
                    <span className="filter-count">
                      <strong>{groups.length}</strong> component{groups.length === 1 ? "" : "s"} · {filtered.length} CVE result{filtered.length === 1 ? "" : "s"}
                    </span>
                  </div>
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
                  {displayResults.results.length > 0 && !groups.length && (
                    <div className="empty-previous-fixes">No result matches “{resultQuery}”.</div>
                  )}
                  {groups.map((group) => (
                    <ComponentResultCard
                      key={resultAnchor(group[0])}
                      results={group}
                      jobId={dataset?.job_id}
                      expand={expandAll}
                    />
                  ))}
                </div>
              );
            })()}
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
                {remediationResults && (
                  <button className="button button-secondary" onClick={() => openDelivery("results")}>
                    <GitBranch size={16} /> Server delivery
                  </button>
                )}
                <button className="button button-secondary" onClick={openMiddleware}>
                  <Layers3 size={16} /> Middleware delivery
                </button>
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

            {/* Server context is asked for inside each result card (the server that CVE was
                assessed on, and the other servers it was found on), not for every server here. */}

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
    </div>
  );
}
