---
name: patch-shepherd
description: End-to-end Tenable remediation skill. Pulls live asset and vulnerability data from the Tenable One inventory export API, clusters findings into practical remediation campaigns grouped by root-cause fix, ranks campaigns by risk-reduction impact, detects exposure trend since the last pull, and generates analyst worklists, manager updates, and executive summaries.
---

# 🐑 Patch Shepherd

**Invocation:** `/patch-shepherd`

Patch Shepherd is a single skill that runs the whole pipeline end to end: pull live Tenable data, cluster findings into root-cause campaigns, score and route them, and produce audience-specific reports. It replaces manually reviewing thousands of individual vulnerability alerts one by one.

---

## 🛠️ Running Patch Shepherd

Run both steps from the **repository root** (both scripts resolve `.env` and `Data/` relative to the current directory):

```bash
python3 .agents/skills/patch-shepherd/scripts/pull_tenable_exposure_data.py  # 1. refresh live data + archive snapshot
python3 .agents/skills/patch-shepherd/scripts/build_campaigns.py            # 2. cluster into campaigns + build all reports
```

(On Windows without a `python3` alias, use `py -3` in place of `python3`.)

Step 1 requires `TENABLE_ACCESS_KEY` and `TENABLE_SECRET_KEY` in a `.env` file in the repository root — see the main [README.md](README.md) for the exact `.env` format and setup steps. Step 2 reads the CSVs step 1 produces; run step 1 first (or on a schedule) and step 2 after.

---

## 📥 Step 1 Output: Tenable Data

`pull_tenable_exposure_data.py` downloads live asset inventory (with ACR & Exposure Scores) and active vulnerability findings (with VPR scores & solutions) from the Tenable One inventory export API, writing:

| File | Description |
| :--- | :--- |
| `Data/tenable_unified_exposure.csv` | *(preferred)* Joined asset + vulnerability rows with ACR, VPR, and solutions |
| `Data/tenable_vulnerability_findings.csv` | Standalone vulnerability findings (fallback) |
| `Data/tenable_assets.csv` | Asset inventory with ACR/exposure scores |
| `Data/snapshots/*_unified_exposure.csv` | Timestamped historical pulls, archived automatically, used for trend comparison |

### Unified CSV Column Schema
`asset_id, hostname, ipv4, acr_score, exposure_score, operating_system, plugin_id, plugin_name, plugin_family, severity, vpr_score, solution, first_found, cves`

Note: this Tenable account's public export scope does not return `ipv4`, `operating_system`, `plugin_family`, or `first_found` — those columns are present in the schema but intentionally left blank rather than guessed. `solution` is populated for a minority of findings; the rest fall back to grouping by `plugin_name`, which is still fix-specific.

---

## 🧠 Step 2: Campaign Grouping Strategy

`build_campaigns.py` consumes the CSVs from step 1 and transforms thousands of individual vulnerability alerts into a small number of **actionable remediation campaigns**.

### Level 1: Root-Cause Solution Grouping
Findings that share the same `solution` text (the vendor-prescribed fix) are merged into one campaign — e.g. every asset needing the same OpenSSL upgrade becomes one campaign.

### Level 2: Product-Family Guard
Boilerplate solution text (e.g. "Update the affected packages.", "Refer to the vendor advisory.") is common across completely unrelated advisories. The builder pairs the solution text with the product family parsed from the finding name (the text before " : " or ": " in the Nessus advisory title, e.g. "Oracle Linux 8", "SUSE SLED15") so unrelated fixes are never silently merged. Findings with no solution text at all fall back to the finding name directly, which is already fix-specific.

### Level 3: Severity Escalation
Each campaign inherits the **highest severity** and **highest VPR** of any finding within it.

---

## 📊 Campaign Priority Score (CPS)

```
CPS = Σ (VPR_score × max(ACR_score, 1)) for each finding in the campaign
    × 1.25 if any finding is Critical, × 1.10 if any finding is High
```

- **VPR** (0.1–10.0): exploit likelihood weighted by real-world threat intelligence.
- **ACR** (1–10): business criticality of the affected asset (assets with ACR ≥ 8 count as "business-critical" in the report).

Higher CPS = more risk reduced per remediation action. Campaigns are sorted by CPS descending.

---

## 📈 Trend Detection

Step 1 archives a timestamped copy of the unified export into `Data/snapshots/` on every run. Step 2 compares the current pull against the second-most-recent snapshot (the prior run) to compute, per campaign:

- `new_assets_since_last_snapshot` — assets newly affected (exposure growing)
- `resolved_findings_since_last_snapshot` — assets no longer affected (remediation working)

The very first pull has no prior snapshot to compare against, so trend fields report zero and the outputs say so explicitly rather than fabricating a comparison.

---

## 📤 Outputs (written to `Data/`)

- `remediation_campaigns.json` — top 500 campaigns by priority score, each with full per-finding worklist detail (capped at 50 rows/campaign so one high-volume campaign can't blow up the export).
- `remediation_campaigns.csv` — every campaign as a flat summary row (no embedded worklist), for bulk filtering/ticketing import.
- `remediation_report.md` — full analyst report: top campaigns, rationale, owners.
- `remediation_worklist.md` — analyst view: per-campaign worklist with suggested owning team.
- `remediation_leadership_update.md` — manager view: what was fixed, what's spreading, what's still open.
- `remediation_executive_summary.md` — executive view: exposure trend, critical campaigns, top 5 risks by business impact, plain-English summary.

---

## 🤖 Instructions for AI Agents

When invoked as `/patch-shepherd` to group or prioritize remediation work from Tenable data:

1. If `Data/` is missing or stale, run `pull_tenable_exposure_data.py` first (requires `TENABLE_ACCESS_KEY`/`TENABLE_SECRET_KEY` in `.env` at the repository root).
2. Run `build_campaigns.py` against the `Data/` directory.
3. Read the output files to answer questions about campaigns — prefer the audience-specific file (worklist/leadership/executive) that matches who is asking.
4. When presenting results, always lead with the **top 3 campaigns by priority score** and explain the single remediation action that resolves each, plus its suggested owning team.
5. If trend fields are all zero, say so plainly ("baseline run — trend available after the next pull") rather than implying no risk is changing.

---

## Notes

- Both scripts run in live mode against the real Tenable API using credentials in `.env` — no synthetic/demo data.
- If the exported CSV rows are empty or incomplete, the builder still completes and writes an explanatory report instead of failing.
- This Tenable account's export scope does not expose asset `ipv4`/`operating_system` or finding `first_found`/`plugin_family` via the public export API; those columns are intentionally left blank in the CSVs rather than guessed.
