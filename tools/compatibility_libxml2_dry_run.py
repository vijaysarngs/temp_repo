"""Offline, read-only compatibility walkthrough for the saved libxml2 AIX case."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT / "aegis-cve-evidence"
sys.path.insert(0, str(PROJECT))

from compatibility.agent import (_component_for_context, assess_compatibility, evaluate_fix,  # noqa: E402
                                 load_knowledge)
from compatibility.context_provider import YamlContextProvider  # noqa: E402
from context_gathered.host_inventory import load_inventory  # noqa: E402

RUN_ID = "ui-20261026-054103-7ca13a07"
AGGREGATE = PROJECT / "remediation" / "runs" / f"grouped_remediation_{RUN_ID}.json"
INVENTORY = PROJECT / "context_gathered" / "inventory" / "aix" / "aix_hosts.yaml"


def main() -> None:
    aggregate = json.loads(AGGREGATE.read_text(encoding="utf-8"))
    item = next(row for row in aggregate["results"] if row["cve"] == "CVE-2025-27113")
    context = item["context"]
    provider = YamlContextProvider(INVENTORY)
    provider._hosts = load_inventory(INVENTORY)  # offline: skip the optional Oracle overlay
    host = provider.host_for(context)
    component = _component_for_context(context, host)[0]
    knowledge = load_knowledge()
    print(f"host_for(context) -> {host['hostname']}; component={component['inventory_component']}; "
          f"owner={component['package_lineage']}")
    current = assess_compatibility(item["remediation_result"], context,
                                   provider=provider, evidence=item["mcp_evidence"])
    print(f"assess_compatibility(saved assessment) -> {current['status']}; "
          f"evaluations={len(current['evaluations'])}; platform_support="
          f"{[entry['status'] for entry in current['platform_support']]}")
    options = [
        ("CVE record upstream boundary", {"route": "component_upgrade", "target_version": "2.12.10"}),
        ("IBM AIX Toolbox RPM candidate", {"route": "os_package_update",
                                           "target_version": "libxml2-2.14.6-1.aix7.1.ppc",
                                           "evidence_kind": "package_candidate"}),
        ("IBM AIX base fileset SP", {"route": "os_package_update", "target_version": "SP10"}),
    ]
    for label, fix in options:
        result = evaluate_fix(fix, component, host, context, knowledge=knowledge,
                              evidence=item["mcp_evidence"]["evidence"], cve=item["cve"])
        print(f"evaluate_fix({label}, {fix['target_version']}) -> {result['status']}")
        for check in result["checks"]:
            if check["status"] != "PASS":
                print(f"  {check['id']}: {check['status']} — {check['detail']}")
        print(f"  required_actions={result['required_actions']}")
        print(f"  verification_commands={result['verification_commands']}")


if __name__ == "__main__":
    main()
