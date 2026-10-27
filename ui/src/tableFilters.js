// Table filtering shared by the upload, enrichment and grouped-component tables.
// Rows keep their original index so selection and row numbers stay correct.

export const DISTINCT_LIMIT = 30;

function text(value) {
  return String(value ?? "").trim();
}

// A column with a short list of values gets a value picker instead of free text.
export function distinctValues(rows, column, limit = DISTINCT_LIMIT) {
  const values = new Set();
  for (const row of rows) {
    const value = text(row[column]);
    if (!value) continue;
    values.add(value);
    if (values.size > limit) return null;
  }
  return [...values].sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
}

// filter: { column, value, mode: "contains" | "equals" | "empty" | "not_empty" }
export function matchesFilter(row, filter) {
  const cell = text(row[filter.column]);
  const wanted = text(filter.value).toLowerCase();
  switch (filter.mode) {
    case "equals": return cell.toLowerCase() === wanted;
    case "empty": return !cell;
    case "not_empty": return Boolean(cell);
    default: return !wanted || cell.toLowerCase().includes(wanted);
  }
}

// Every word of the search must appear somewhere in the row (any column).
export function matchesSearch(row, columns, query) {
  const words = text(query).toLowerCase().split(/\s+/).filter(Boolean);
  if (!words.length) return true;
  const haystack = columns.map((column) => text(row[column]).toLowerCase()).join("\u0001");
  return words.every((word) => haystack.includes(word));
}

// Returns [{ row, index }] for rows that pass the search, every column filter and the extra test.
export function filterRows(rows, columns, { query = "", filters = [], extra = null } = {}) {
  const active = filters.filter((filter) => filter.column &&
    (filter.mode === "empty" || filter.mode === "not_empty" || text(filter.value)));
  const entries = [];
  rows.forEach((row, index) => {
    if (!matchesSearch(row, columns, query)) return;
    if (!active.every((filter) => matchesFilter(row, filter))) return;
    if (extra && !extra(row, index)) return;
    entries.push({ row, index });
  });
  return entries;
}
