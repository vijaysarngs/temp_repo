export function mergeRemediationRuns(runs, incoming) {
  const index = runs.findIndex((run) => run.run_id === incoming.run_id);
  if (index < 0) return [...runs, incoming];
  return runs.map((run, position) => position === index ? incoming : run);
}

export function combineRemediationRuns(runs) {
  if (!runs.length) return null;
  const results = runs.flatMap((run) => run.results || []);
  const verdict_counts = {};
  for (const result of results) {
    const verdict = result.verdict || "UNKNOWN";
    verdict_counts[verdict] = (verdict_counts[verdict] || 0) + 1;
  }
  return {
    run_ids: runs.map((run) => run.run_id),
    total: results.length,
    verdict_counts,
    uses_test_context: runs.some((run) => run.uses_test_context),
    results,
  };
}

// The DOM id of a result card (results and previous-fixes pages); other pages link to `#<id>`.
export function resultAnchor(result) {
  return "result-" + [result.run_id, result.cve, result.component_id, result.host]
    .map((part) => String(part || "")).join("-").replace(/[^A-Za-z0-9_-]+/g, "_");
}
