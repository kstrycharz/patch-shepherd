#!/usr/bin/env python3
"""
Patch Shepherd - Remediation Campaign Builder

Reads Tenable CSV exports from Data/ and clusters individual vulnerability
findings into practical, prioritized remediation campaigns. Compares the
current pull against the prior archived snapshot in Data/snapshots/ to
surface trend, recurrence, and remediation progress.

Outputs (written to Data/):
  remediation_campaigns.json        - machine-readable campaign list
  remediation_campaigns.csv         - flat CSV for spreadsheets/ticketing
  remediation_report.md             - full campaign report (analyst)
  remediation_worklist.md           - per-campaign worklist with owners (analyst)
  remediation_leadership_update.md  - what changed/fixed/blocked (manager)
  remediation_executive_summary.md  - trend, top risks, plain-English (executive)

Usage (run from the repository root):
  python3 .agents/skills/patch-shepherd/scripts/build_campaigns.py
"""

from __future__ import annotations

import argparse
import csv
import glob
import json
import os
from collections import defaultdict
from dataclasses import dataclass, asdict, field
from pathlib import Path
from statistics import mean
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

ROOT = Path(__file__).resolve().parents[4]
DATA_DIR = ROOT / "Data"

SEVERITY_RANK = {
    "informational": 0, "info": 0,
    "low": 1,
    "medium": 2, "moderate": 2,
    "high": 3,
    "critical": 4,
}

CRITICAL_ACR_THRESHOLD = 8.0

# Cap on per-finding worklist rows embedded in the JSON export per campaign.
# `finding_count` on the campaign always reflects the true total; this only
# bounds how many individual rows are inlined for campaigns with very large
# blast radius (full detail remains in the source CSVs).
WORKLIST_CAP = 50

# The JSON export embeds full per-finding worklist detail, which only makes
# sense for the campaigns an analyst would actually open. The CSV export
# always contains every campaign as a flat summary row (no embedded detail)
# so nothing is lost -- it's the right format for bulk filtering/ticketing
# import anyway.
JSON_CAMPAIGN_CAP = 500

# Keyword -> suggested owning team. Checked in order against the finding
# name + solution text since this Tenable account's export scope does not
# expose plugin_family. First match wins.
TEAM_ROUTING: List[Tuple[str, str]] = [
    (("kubernetes", "k8s", "docker", "container", "helm"), "Platform/Container Team"),
    (("vmware", "esxi", "hypervisor", "vcenter"), "Virtualization Team"),
    (("scada", "ics", " plc", "siemens", "schneider", "modicon", "simatic", "sinamics", "siplus"), "OT/ICS Security Team"),
    (("windows", "active directory", "kerberos", "microsoft", ".net", "iis"), "Windows/AD Team"),
    (("sql", "postgres", "mysql", "oracle database", "mongodb", "mariadb", "database"), "Database Team"),
    (("cisco", "juniper", "firewall", "router", "switch", " vpn", "network device"), "Network Team"),
    (("openssl", "tls", "ssl ", "certificate", "cipher"), "Crypto/PKI Team"),
    (("linux", "ubuntu", "centos", "redhat", "rhel", "debian", "freebsd", "suse", "kernel"), "Linux/Unix Team"),
    (("chrome", "firefox", "adobe", "browser", "office ", "acrobat"), "Endpoint/Desktop Team"),
    (("apache", "nginx", "tomcat", "web server", "http"), "Web/App Team"),
]


def _clean(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _parse_float(value: Any, default: float = 0.0) -> float:
    text = _clean(value)
    if not text:
        return default
    try:
        return float(text)
    except ValueError:
        return default


def _severity_rank(value: str) -> int:
    return SEVERITY_RANK.get(value.lower(), 0) if value else 0


def _rank_to_label(rank: int) -> str:
    labels = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
    return labels.get(rank, "Info")


def suggest_owner(text: str) -> str:
    lowered = text.lower()
    for keywords, team in TEAM_ROUTING:
        if any(kw in lowered for kw in keywords):
            return team
    return "General IT / Infrastructure Team"


@dataclass
class FindingRecord:
    asset_id: str
    hostname: str
    acr_score: float
    exposure_score: float
    plugin_id: str
    plugin_name: str
    severity: str
    vpr_score: float
    solution: str
    cves: str

@dataclass
class Campaign:
    campaign_id: str
    title: str
    solution: str
    severity: str
    max_vpr: float
    avg_vpr: float
    max_acr: float
    avg_acr: float
    affected_assets: int
    business_critical_assets: int
    finding_count: int
    priority_score: float
    suggested_owner: str
    rationale: str
    new_assets_since_last_snapshot: int
    resolved_findings_since_last_snapshot: int
    asset_ids: List[str] = field(default_factory=list)
    hostnames: List[str] = field(default_factory=list)
    plugins: List[str] = field(default_factory=list)
    worklist: List[Dict[str, Any]] = field(default_factory=list)


def load_rows(csv_path: Path) -> List[Dict[str, str]]:
    if not csv_path.exists():
        return []
    with csv_path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def normalize_records(rows: Iterable[Dict[str, str]]) -> List[FindingRecord]:
    records: List[FindingRecord] = []
    for row in rows:
        asset_id = _clean(row.get("asset_id"))
        plugin_id = _clean(row.get("plugin_id") or row.get("finding_id"))
        solution = _clean(row.get("solution"))
        plugin_name = _clean(row.get("plugin_name") or row.get("finding_name"))

        if not any([asset_id, plugin_id, solution, plugin_name]):
            continue

        records.append(
            FindingRecord(
                asset_id=asset_id,
                hostname=_clean(row.get("hostname")),
                acr_score=_parse_float(row.get("acr_score") or row.get("acr")),
                exposure_score=_parse_float(row.get("exposure_score") or row.get("aes")),
                plugin_id=plugin_id,
                plugin_name=plugin_name,
                severity=_clean(row.get("severity")),
                vpr_score=_parse_float(row.get("vpr_score")),
                solution=solution,
                cves=_clean(row.get("cves")),
            )
        )
    return records


def extract_product_family(plugin_name: str) -> str:
    """Pull the leading OS/product family off a Tenable advisory title.

    Nessus advisory titles are conventionally "<Family> : <Advisory>" (or
    "<Family>: <package list>" for SUSE). Splitting on that gives a stable
    grouping token even when the solution text itself is boilerplate.
    """
    name = (plugin_name or "").strip()
    for sep in (" : ", ": "):
        if sep in name:
            return name.split(sep, 1)[0].strip()
    return name


def campaign_key(record: FindingRecord) -> Tuple[str, str]:
    """Root-cause grouping key: (solution text, product family).

    Many findings share generic, boilerplate solution text (e.g. "Update the
    affected packages.") across completely unrelated OS/package advisories.
    Grouping on solution text alone would silently merge those unrelated
    fixes into one campaign, which undermines the "one campaign = one real
    fix" premise. Pairing the solution with the advisory's product family
    keeps genuinely shared fixes together while keeping unrelated ones apart.
    When there is no solution text at all, the finding name itself (already
    family-qualified) is a good enough key on its own.
    """
    if record.solution:
        family = extract_product_family(record.plugin_name)
        if family and family.lower() != record.solution.lower():
            return (record.solution, family)
        return (record.solution, "")
    return (record.plugin_name or "Unspecified remediation", "")


def find_prior_snapshot(data_dir: Path) -> Optional[Path]:
    """Return the snapshot immediately before the current pull, if one exists.

    The pull script archives the *current* data into Data/snapshots/ on every
    run, so the newest snapshot is the current data and the second-newest is
    the previous run -- the correct baseline for trend comparison.
    """
    snapshots_dir = data_dir / "snapshots"
    if not snapshots_dir.is_dir():
        return None
    files = sorted(glob.glob(str(snapshots_dir / "*_unified_exposure.csv")))
    if len(files) < 2:
        return None
    return Path(files[-2])


def build_prior_campaign_assets(prior_snapshot: Optional[Path]) -> Dict[Tuple[str, str], Set[str]]:
    """Return campaign_key -> set of asset_ids as of the prior snapshot."""
    if not prior_snapshot:
        return {}
    rows = load_rows(prior_snapshot)
    records = normalize_records(rows)
    campaign_assets: Dict[Tuple[str, str], Set[str]] = defaultdict(set)
    for r in records:
        if r.asset_id:
            campaign_assets[campaign_key(r)].add(r.asset_id)
    return campaign_assets


def build_campaigns(
    records: Sequence[FindingRecord],
    prior_campaign_assets: Dict[Tuple[str, str], Set[str]],
) -> List[Campaign]:
    if not records:
        return []

    buckets: Dict[Tuple[str, str], List[FindingRecord]] = defaultdict(list)
    for record in records:
        buckets[campaign_key(record)].append(record)

    campaigns: List[Campaign] = []
    for index, ((solution, family), items) in enumerate(buckets.items(), start=1):
        severities = [_severity_rank(item.severity) for item in items]
        max_severity = max(severities) if severities else 0
        max_vpr = max((item.vpr_score for item in items), default=0.0)
        avg_vpr = mean(item.vpr_score for item in items) if items else 0.0
        max_acr = max((item.acr_score for item in items), default=0.0)
        avg_acr = mean(item.acr_score for item in items) if items else 0.0
        asset_ids = sorted({item.asset_id for item in items if item.asset_id})
        hostnames = sorted({item.hostname for item in items if item.hostname})
        plugins = sorted({item.plugin_name for item in items if item.plugin_name})
        unique_asset_count = len(asset_ids)
        business_critical_assets = len({
            item.asset_id for item in items
            if item.asset_id and item.acr_score >= CRITICAL_ACR_THRESHOLD
        })

        priority_score = sum(item.vpr_score * max(item.acr_score, 1.0) for item in items)
        if max_severity >= 4:
            priority_score *= 1.25
        elif max_severity >= 3:
            priority_score *= 1.1

        # Trend vs. prior snapshot
        current_asset_set = set(asset_ids)
        prior_asset_set = prior_campaign_assets.get((solution, family), set())
        new_assets = len(current_asset_set - prior_asset_set) if prior_campaign_assets else 0
        # A finding "resolved" for this campaign = an asset that was in this
        # campaign last run but has no matching finding for it this run.
        resolved_count = len(prior_asset_set - current_asset_set) if prior_campaign_assets else 0

        representative_name = items[0].plugin_name or solution
        if solution and family:
            title = f"{solution} ({family})"
        elif solution:
            title = solution
        else:
            title = f"{representative_name} remediation"
        owner = suggest_owner(f"{title} {representative_name}")

        trend_clause = ""
        if prior_campaign_assets:
            if new_assets > 0 and resolved_count > 0:
                trend_clause = f" Exposure is shifting: +{new_assets} newly affected assets, -{resolved_count} resolved since the last scan."
            elif new_assets > 0:
                trend_clause = f" Exposure is growing: +{new_assets} newly affected assets since the last scan."
            elif resolved_count > 0:
                trend_clause = f" Progress made: -{resolved_count} assets resolved since the last scan."

        rationale = (
            f"{_rank_to_label(max_severity)} severity affecting {unique_asset_count} asset(s) "
            f"({business_critical_assets} business-critical), max VPR {round(max_vpr, 1)}, "
            f"{len(items)} finding(s) share this single fix.{trend_clause}"
        )

        campaign = Campaign(
            campaign_id=f"CAMP-{index:04d}",
            title=title,
            solution=solution,
            severity=_rank_to_label(max_severity),
            max_vpr=round(max_vpr, 1),
            avg_vpr=round(avg_vpr, 2),
            max_acr=round(max_acr, 1),
            avg_acr=round(avg_acr, 2),
            affected_assets=unique_asset_count,
            business_critical_assets=business_critical_assets,
            finding_count=len(items),
            priority_score=round(priority_score, 2),
            suggested_owner=owner,
            rationale=rationale,
            new_assets_since_last_snapshot=new_assets,
            resolved_findings_since_last_snapshot=resolved_count,
            asset_ids=asset_ids,
            hostnames=hostnames,
            plugins=plugins,
            worklist=[
                {
                    "asset_id": item.asset_id,
                    "hostname": item.hostname,
                    "plugin_id": item.plugin_id,
                    "plugin_name": item.plugin_name,
                    "severity": item.severity,
                    "vpr_score": item.vpr_score,
                    "acr_score": item.acr_score,
                    "cves": item.cves,
                }
                # solution is already on the campaign; per-finding rows only need
                # what varies by finding. Capped so one campaign with thousands of
                # near-identical findings (same fix, many assets) can't blow up the
                # JSON export -- the full raw detail always lives in the source CSVs.
                for item in sorted(items, key=lambda x: (x.vpr_score, x.acr_score), reverse=True)[:WORKLIST_CAP]
            ],
        )
        campaigns.append(campaign)

    campaigns.sort(key=lambda item: (item.priority_score, item.max_vpr, item.affected_assets), reverse=True)
    return campaigns


# ---------------------------------------------------------------- Outputs --

def write_json(campaigns: Sequence[Campaign], output_path: Path) -> None:
    payload = [asdict(campaign) for campaign in campaigns[:JSON_CAMPAIGN_CAP]]
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)


def write_csv(campaigns: Sequence[Campaign], output_path: Path) -> None:
    fieldnames = [
        "campaign_id", "title", "solution", "severity",
        "max_vpr", "avg_vpr", "max_acr", "avg_acr",
        "affected_assets", "business_critical_assets", "finding_count",
        "priority_score", "suggested_owner",
        "new_assets_since_last_snapshot", "resolved_findings_since_last_snapshot",
        "asset_ids", "hostnames", "plugins",
    ]
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for campaign in campaigns:
            writer.writerow({
                "campaign_id": campaign.campaign_id,
                "title": campaign.title,
                "solution": campaign.solution,
                "severity": campaign.severity,
                "max_vpr": campaign.max_vpr,
                "avg_vpr": campaign.avg_vpr,
                "max_acr": campaign.max_acr,
                "avg_acr": campaign.avg_acr,
                "affected_assets": campaign.affected_assets,
                "business_critical_assets": campaign.business_critical_assets,
                "finding_count": campaign.finding_count,
                "priority_score": campaign.priority_score,
                "suggested_owner": campaign.suggested_owner,
                "new_assets_since_last_snapshot": campaign.new_assets_since_last_snapshot,
                "resolved_findings_since_last_snapshot": campaign.resolved_findings_since_last_snapshot,
                "asset_ids": ";".join(campaign.asset_ids[:50]),
                "hostnames": ";".join(campaign.hostnames[:50]),
                "plugins": ";".join(campaign.plugins[:20]),
            })


def write_report(campaigns: Sequence[Campaign], output_path: Path, record_count: int, has_trend: bool) -> None:
    lines: List[str] = ["# Remediation Campaign Report", ""]
    lines.append(f"Total usable findings: {record_count}")
    lines.append(f"Total campaigns: {len(campaigns)}")
    lines.append(f"Trend comparison available: {'Yes' if has_trend else 'No (baseline run)'}")
    lines.append("")

    if not campaigns:
        lines.append("No usable findings were available to build campaigns.")
        lines.append("The builder completed successfully, but the input CSVs did not contain populated finding rows.")
        lines.append("")
        lines.append("Once the data exports contain real rows, rerun this script to generate worklists and executive summaries.")
        output_path.write_text("\n".join(lines), encoding="utf-8")
        return

    lines.append("## Top Campaigns")
    lines.append("")
    for campaign in campaigns[:10]:
        lines.append(f"### {campaign.campaign_id} - {campaign.title}")
        lines.append(f"- Priority score: {campaign.priority_score}")
        lines.append(f"- Severity: {campaign.severity}")
        lines.append(f"- Affected assets: {campaign.affected_assets} ({campaign.business_critical_assets} business-critical)")
        lines.append(f"- Findings resolved by this one fix: {campaign.finding_count}")
        lines.append(f"- Suggested fix: {campaign.solution or campaign.title}")
        lines.append(f"- Suggested owner: {campaign.suggested_owner}")
        lines.append(f"- Why this matters: {campaign.rationale}")
        if campaign.hostnames:
            lines.append(f"- Example hosts: {', '.join(campaign.hostnames[:5])}")
        lines.append("")

    lines.append("## Leadership Summary")
    lines.append("")
    lines.append(f"- Highest priority campaign: {campaigns[0].title}")
    lines.append(f"- Most affected assets in one campaign: {max(c.affected_assets for c in campaigns)}")
    lines.append(f"- Highest severity observed: {max((c.severity for c in campaigns), key=lambda s: _severity_rank(s))}")
    lines.append("")
    lines.append("## What To Fix Next")
    lines.append("")
    lines.append("Focus on the top campaign first, then route the next two campaigns to the owners best positioned to remove the most risk quickly.")

    output_path.write_text("\n".join(lines), encoding="utf-8")


def write_worklist(campaigns: Sequence[Campaign], output_path: Path) -> None:
    lines: List[str] = ["# Remediation Worklist (Analyst View)", ""]
    if not campaigns:
        lines.append("No campaign rows were generated from the current exports.")
        output_path.write_text("\n".join(lines), encoding="utf-8")
        return

    for campaign in campaigns[:25]:
        lines.append(f"## {campaign.campaign_id}: {campaign.title}")
        lines.append(f"- Owner: {campaign.suggested_owner}")
        lines.append(f"- Severity: {campaign.severity} | Priority score: {campaign.priority_score}")
        lines.append(f"- Assets: {campaign.affected_assets} ({campaign.business_critical_assets} business-critical) | Findings: {campaign.finding_count}")
        lines.append(f"- Fix: {campaign.solution or campaign.title}")
        lines.append(f"- Rationale: {campaign.rationale}")
        if campaign.hostnames:
            lines.append(f"- Hosts (sample): {', '.join(campaign.hostnames[:10])}")
        lines.append("")

    output_path.write_text("\n".join(lines), encoding="utf-8")


def write_manager_update(campaigns: Sequence[Campaign], output_path: Path, record_count: int, has_trend: bool) -> None:
    lines = ["# Manager Update", ""]
    lines.append(f"Usable findings processed: {record_count}")
    lines.append(f"Campaigns created: {len(campaigns)}")
    lines.append("")

    if not campaigns:
        lines.append("No manager update could be generated from the current CSVs because the exported records are empty or incomplete.")
        output_path.write_text("\n".join(lines), encoding="utf-8")
        return

    if not has_trend:
        lines.append("This is the first recorded pull. Trend comparison (what's fixed, what's new, what's spreading) will be available starting with the next data refresh.")
        lines.append("")

    growing = sorted([c for c in campaigns if c.new_assets_since_last_snapshot > 0], key=lambda c: c.new_assets_since_last_snapshot, reverse=True)
    fixed = sorted([c for c in campaigns if c.resolved_findings_since_last_snapshot > 0], key=lambda c: c.resolved_findings_since_last_snapshot, reverse=True)
    blocked = [c for c in campaigns[:15] if c.new_assets_since_last_snapshot == 0 and c.resolved_findings_since_last_snapshot == 0]

    top = campaigns[0]
    lines.append("## Top Risk Reduction Opportunity")
    lines.append(f"- {top.title} ({top.campaign_id})")
    lines.append(f"- Severity: {top.severity} | Priority score: {top.priority_score} | Owner: {top.suggested_owner}")
    lines.append(f"- {top.rationale}")
    lines.append("")

    lines.append("## What Was Fixed")
    lines.append("")
    if fixed:
        for c in fixed[:10]:
            lines.append(f"- {c.campaign_id} {c.title}: -{c.resolved_findings_since_last_snapshot} assets resolved")
    else:
        lines.append("- No resolved assets detected since the last scan.")
    lines.append("")

    lines.append("## Which Campaigns Are Spreading")
    lines.append("")
    if growing:
        for c in growing[:10]:
            lines.append(f"- {c.campaign_id} {c.title}: +{c.new_assets_since_last_snapshot} newly affected assets")
    else:
        lines.append("- No campaigns are actively growing since the last scan.")
    lines.append("")

    lines.append("## Still Open / Unchanged (Top Priority)")
    lines.append("")
    if blocked:
        for c in blocked[:10]:
            lines.append(f"- {c.campaign_id} {c.title}: {c.affected_assets} assets, priority {c.priority_score}, owner {c.suggested_owner}")
    else:
        lines.append("- N/A")

    output_path.write_text("\n".join(lines), encoding="utf-8")


def write_executive_summary(campaigns: Sequence[Campaign], output_path: Path, record_count: int, has_trend: bool) -> None:
    lines = ["# Executive Summary", ""]

    if not campaigns:
        lines.append("No executive summary could be generated because the current data pull returned no usable findings.")
        output_path.write_text("\n".join(lines), encoding="utf-8")
        return

    total_assets = len({a for c in campaigns for a in c.asset_ids})
    total_critical_campaigns = sum(1 for c in campaigns if c.severity == "Critical")
    total_growth = sum(c.new_assets_since_last_snapshot for c in campaigns)
    total_resolved = sum(c.resolved_findings_since_last_snapshot for c in campaigns)
    top5 = campaigns[:5]

    lines.append("## Plain-English Summary")
    lines.append("")
    trend_sentence = ""
    if has_trend:
        if total_growth > total_resolved:
            trend_sentence = f" Exposure is trending up: {total_growth} newly affected assets versus {total_resolved} resolved since the last scan."
        elif total_resolved > total_growth:
            trend_sentence = f" Exposure is trending down: {total_resolved} assets resolved versus {total_growth} newly affected since the last scan."
        else:
            trend_sentence = " Exposure is holding steady since the last scan."
    else:
        trend_sentence = " This is the baseline scan; trend will be available after the next refresh."

    lines.append(
        f"{record_count} raw findings were consolidated into {len(campaigns)} remediation campaigns covering "
        f"{total_assets} assets. {total_critical_campaigns} campaign(s) are Critical severity and need immediate "
        f"attention.{trend_sentence}"
    )
    lines.append("")

    lines.append("## Total Exposure Trend")
    lines.append("")
    if has_trend:
        lines.append(f"- New asset exposure since last scan: +{total_growth}")
        lines.append(f"- Assets resolved since last scan: -{total_resolved}")
        lines.append(f"- Net change: {total_growth - total_resolved:+d}")
    else:
        lines.append("- Baseline snapshot established. Trend will populate after the next data refresh.")
    lines.append("")

    lines.append("## Critical Campaigns")
    lines.append("")
    critical = [c for c in campaigns if c.severity == "Critical"]
    if critical:
        for c in critical[:10]:
            lines.append(f"- {c.campaign_id} {c.title}: {c.affected_assets} assets ({c.business_critical_assets} business-critical), owner {c.suggested_owner}")
    else:
        lines.append("- None currently open.")
    lines.append("")

    lines.append("## Top 5 Risks By Business Impact")
    lines.append("")
    for i, c in enumerate(top5, start=1):
        lines.append(f"{i}. **{c.title}** ({c.campaign_id}) — {c.rationale}")
    lines.append("")

    lines.append("## Remediation Progress")
    lines.append("")
    if has_trend:
        lines.append(f"- {total_resolved} findings resolved since the last scan across {sum(1 for c in campaigns if c.resolved_findings_since_last_snapshot > 0)} campaign(s).")
    else:
        lines.append("- Not yet measurable; establish a second data pull to compute progress.")

    output_path.write_text("\n".join(lines), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build remediation campaigns from Tenable CSV exports.")
    parser.add_argument("--data-dir", default=str(DATA_DIR), help="Directory containing Tenable CSV exports.")
    parser.add_argument("--output-dir", default=str(DATA_DIR), help="Directory for generated campaign files.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    data_dir = Path(args.data_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    unified_rows = load_rows(data_dir / "tenable_unified_exposure.csv")
    findings_rows = load_rows(data_dir / "tenable_vulnerability_findings.csv")

    records = normalize_records(unified_rows)
    if not records:
        records = normalize_records(findings_rows)

    prior_snapshot = find_prior_snapshot(data_dir)
    prior_campaign_assets = build_prior_campaign_assets(prior_snapshot)
    has_trend = bool(prior_campaign_assets)

    campaigns = build_campaigns(records, prior_campaign_assets)

    write_json(campaigns, output_dir / "remediation_campaigns.json")
    write_csv(campaigns, output_dir / "remediation_campaigns.csv")
    write_report(campaigns, output_dir / "remediation_report.md", len(records), has_trend)
    write_worklist(campaigns, output_dir / "remediation_worklist.md")
    write_manager_update(campaigns, output_dir / "remediation_leadership_update.md", len(records), has_trend)
    write_executive_summary(campaigns, output_dir / "remediation_executive_summary.md", len(records), has_trend)

    print(f"Built {len(campaigns)} campaigns from {len(records)} usable findings.")
    print(f"Trend comparison: {'enabled (prior snapshot found)' if has_trend else 'disabled (baseline run)'}")
    if len(campaigns) > JSON_CAMPAIGN_CAP:
        print(f"JSON export includes full worklist detail for the top {JSON_CAMPAIGN_CAP} campaigns; the CSV export includes all {len(campaigns)}.")
    print(f"Outputs written to: {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
