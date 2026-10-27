import assert from "node:assert/strict";
import test from "node:test";
import { combineRemediationRuns, mergeRemediationRuns } from "./remediationResults.js";

test("a later run keeps earlier assessments and repeated reads replace the same run", () => {
  const first = { run_id: "run-1", uses_test_context: true, results: [
    { run_id: "run-1", cve: "CVE-2025-0001", verdict: "FIX_AVAILABLE" },
  ] };
  const second = { run_id: "run-2", results: [
    { run_id: "run-2", cve: "CVE-2025-0002", verdict: "ASSESSMENT_LIMITED" },
  ] };
  const runs = mergeRemediationRuns(mergeRemediationRuns([], first), second);
  assert.deepEqual(combineRemediationRuns(runs).run_ids, ["run-1", "run-2"]);
  assert.equal(combineRemediationRuns(runs).total, 2);
  assert.equal(combineRemediationRuns(runs).verdict_counts.FIX_AVAILABLE, 1);
  assert.equal(combineRemediationRuns(runs).uses_test_context, true);
  const reloaded = mergeRemediationRuns(runs, { ...second, results: [
    { run_id: "run-2", cve: "CVE-2025-0002", verdict: "NEEDS_INPUT" },
  ] });
  assert.equal(combineRemediationRuns(reloaded).total, 2);
  assert.equal(combineRemediationRuns(reloaded).verdict_counts.NEEDS_INPUT, 1);
});
