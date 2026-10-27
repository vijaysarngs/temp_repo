import assert from "node:assert/strict";
import test from "node:test";
import { distinctValues, filterRows, matchesFilter, matchesSearch } from "./tableFilters.js";

const columns = ["CVE", "Product", "Severity"];
const rows = [
  { CVE: "CVE-2024-0001", Product: "OpenSSL", Severity: "High" },
  { CVE: "CVE-2024-0002", Product: "Apache Tomcat", Severity: "Low" },
  { CVE: "CVE-2024-0003", Product: "OpenSSH", Severity: "" },
];

test("search matches every word across any column and keeps the original index", () => {
  assert.deepEqual(filterRows(rows, columns, { query: "open high" }).map((e) => e.index), [0]);
  assert.deepEqual(filterRows(rows, columns, { query: "  " }).map((e) => e.index), [0, 1, 2]);
  assert.equal(matchesSearch(rows[1], columns, "TOMCAT 0002"), true);
});

test("column filters support contains, equals, empty and not empty", () => {
  assert.equal(matchesFilter(rows[0], { column: "Product", value: "ssl", mode: "contains" }), true);
  assert.equal(matchesFilter(rows[0], { column: "Product", value: "openssl", mode: "equals" }), true);
  assert.equal(matchesFilter(rows[2], { column: "Severity", mode: "empty" }), true);
  const entries = filterRows(rows, columns, { filters: [
    { column: "Product", value: "open", mode: "contains" },
    { column: "Severity", mode: "not_empty" },
  ] });
  assert.deepEqual(entries.map((e) => e.index), [0]);
});

test("incomplete filters are ignored and the extra test applies last", () => {
  const entries = filterRows(rows, columns, {
    filters: [{ column: "Product", value: "", mode: "contains" }],
    extra: (_row, index) => index !== 1,
  });
  assert.deepEqual(entries.map((e) => e.index), [0, 2]);
});

test("short value lists are offered as choices, long ones are not", () => {
  assert.deepEqual(distinctValues(rows, "Severity"), ["High", "Low"]);
  assert.equal(distinctValues(rows, "CVE", 2), null);
});
