"""Command line: python -m cve_feed_enrichment <input.csv> [options]"""
import argparse
import sys
from pathlib import Path

from .enrich import enrich, load_env_value, print_progress, read_cves, write_outputs
from .http_client import Cache
from .sources import ALL_SOURCES, Sources

PACKAGE_DIR = Path(__file__).resolve().parent


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="python -m cve_feed_enrichment",
        description="Enrich a CSV of CVE IDs from public CVE sources (CVE.org, NVD, OSV, "
                    "Red Hat, EPSS, CISA KEV). No model calls.")
    parser.add_argument("input_csv", type=Path, help="CSV containing CVE IDs")
    parser.add_argument("--cve-column", help="Column holding the CVE IDs (default: any header "
                                             "containing 'cve', else every cell)")
    parser.add_argument("--out-dir", type=Path, default=PACKAGE_DIR / "output")
    parser.add_argument("--out-name", help="Output file name without extension "
                                           "(default: <input>_feed_enriched)")
    parser.add_argument("--sources", default=",".join(ALL_SOURCES),
                        help=f"Comma-separated subset of: {', '.join(ALL_SOURCES)}")
    parser.add_argument("--limit", type=int, help="Only the first N CVEs (for a quick try)")
    parser.add_argument("--workers", type=int, default=4, help="CVEs looked up in parallel")
    parser.add_argument("--cache-dir", type=Path, default=PACKAGE_DIR / "cache")
    parser.add_argument("--cache-days", type=float, default=2,
                        help="Reuse saved responses younger than this (EPSS/KEV: 1 day)")
    parser.add_argument("--refresh", action="store_true", help="Ignore the cache and fetch again")
    parser.add_argument("--env-file", type=Path, default=PACKAGE_DIR.parent / ".env",
                        help="Where to read NVD_API_KEY if it is not in the environment")
    args = parser.parse_args(argv)

    enabled = [name.strip() for name in args.sources.split(",") if name.strip()]
    unknown = sorted(set(enabled) - set(ALL_SOURCES))
    if unknown:
        parser.error(f"unknown source(s): {', '.join(unknown)}")
    if not args.input_csv.is_file():
        parser.error(f"input CSV not found: {args.input_csv}")

    cves = read_cves(args.input_csv, args.cve_column)
    if args.limit:
        cves = dict(list(cves.items())[:args.limit])
    if not cves:
        print("No CVE IDs found in the input.", file=sys.stderr)
        return 1

    api_key = load_env_value("NVD_API_KEY", args.env_file)
    if "nvd" in enabled and not api_key:
        minutes = len(cves) * 6.5 / 60
        print(f"Note: no NVD_API_KEY, so NVD is limited to 5 requests / 30 s "
              f"(about {minutes:.0f} min for {len(cves)} uncached CVEs).", file=sys.stderr)

    sources = Sources(Cache(args.cache_dir, args.cache_days, args.refresh), api_key, enabled)
    print(f"Looking up {len(cves)} CVE(s) in: {', '.join(enabled)}", file=sys.stderr)
    rows, details = enrich(cves, sources, args.workers, print_progress)
    stem = args.out_name or f"{args.input_csv.stem}_feed_enriched"
    csv_path, json_path = write_outputs(rows, details, args.out_dir, stem)

    with_component = sum(1 for row in rows if row["Components"])
    with_product = sum(1 for row in rows if row["Products"] or row["CPE Products"])
    with_description = sum(1 for row in rows if row["Description"])
    failed = sum(1 for row in rows if row["Source Errors"])
    print(f"\nDone: {len(rows)} CVEs | description: {with_description} | product: {with_product} "
          f"| component named by a source: {with_component} | with source errors: {failed}")
    print(f"CSV:  {csv_path}\nJSON: {json_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
