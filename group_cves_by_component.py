"""Group enriched CVE rows by their classified product and component."""

import csv
from pathlib import Path

from cve_component_enrichment import COMPONENT_COLUMNS, component_identifier


LIST_COLUMNS = {
    "Application", "Description", "CVE IDs", "Operating System",
    "Technical Details", "Evidence", "Affected Symbol", "Source Path",
    "Component Kind", "Classification Status", "Classification Reason",
    "Source Rows",
}


def _values(value):
    return [item.strip() for item in str(value or "").split(" | ") if item.strip()]


def group_by_product_and_component(rows):
    """Combine CVEs only when both their product and component match."""
    groups = {}
    for row in rows:
        product = str(row.get("Product", "")).strip()
        component = str(row.get("Component", "")).strip()
        key = (product, component)
        group = groups.setdefault(key, {
            column: [] if column in LIST_COLUMNS else str(row.get(column, "")).strip()
            for column in COMPONENT_COLUMNS
        })
        group["Component ID"] = component_identifier(product, component)
        for column in LIST_COLUMNS:
            group[column].extend(_values(row.get(column, "")))

    output = []
    for group in groups.values():
        output.append({
            column: " | ".join(dict.fromkeys(value)) if isinstance(value, list) else value
            for column, value in group.items()
        })
    return sorted(output, key=lambda row: (
        row["Product"].casefold(), row["Component"].casefold()
    ))


def write_grouped_csv(path, rows):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=COMPONENT_COLUMNS)
        writer.writeheader()
        writer.writerows(group_by_product_and_component(rows))
    return path
