# Patch Shepherd

This workspace contains **Patch Shepherd**, a single end-to-end Claude Code skill that pulls live Tenable exposure data and turns it into a small number of prioritized remediation campaigns, then keeps analysts, managers, and executives aligned with worklists, status updates, and trend visibility. See `SWARM_COMPETITION_PLAN.md` for the full product plan and [`SKILL.md`](SKILL.md) for the skill definition.

## Prerequisites

- Python 3.8 or later (both scripts are stdlib-only — no third-party packages to install).
- A Tenable One account with permission to use the inventory export API (`/api/v1/t1/inventory/export/*`).
- A Tenable API access key and secret key, available from **My Account → API Keys** in Tenable Vulnerability Management.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/kstrycharz/patch-shepherd.git
   cd patch-shepherd
   ```
2. Copy [`.env.example`](.env.example) to `.env` in the repository root (the same directory as this README) and fill in your Tenable API keys:
   ```bash
   cp .env.example .env
   ```
   ```
   TENABLE_ACCESS_KEY=your_access_key_here
   TENABLE_SECRET_KEY=your_secret_key_here
   ```
   Both scripts load this file automatically from the current working directory, so always run them from the repository root. `.env` is listed in `.gitignore` and is never committed — only `.env.example` (with placeholder values) is tracked.
3. **Claude Code users:** the skill is defined in [`SKILL.md`](SKILL.md) at the repository root, so Claude Code can load it directly from this repo URL. Once installed, invoke it as `/patch-shepherd`.

## Available workflows

Patch Shepherd is one skill, run in two steps, both from the **repository root**:

- Pull exposure data: `python3 .agents/skills/patch-shepherd/scripts/pull_tenable_exposure_data.py`
- Build remediation campaigns: `python3 .agents/skills/patch-shepherd/scripts/build_campaigns.py`

(On Windows without a `python3` alias, substitute `py -3` for `python3` in the commands above.)

Run the pull script first (or on a schedule), then the campaign builder. Each pull archives a timestamped copy of the unified export into `Data/snapshots/`; the campaign builder automatically compares the current pull against the prior snapshot to compute trend, growth, and remediation progress. The very first run establishes a baseline — trend fields populate starting with the second pull.

## Campaign outputs

Running the campaign builder writes these files to `Data/`, mapped to the three audiences from the plan:

| File | Audience | Contents |
| :--- | :--- | :--- |
| `remediation_campaigns.json` | machine-readable | Top 500 campaigns by priority, each with full per-finding worklist detail (capped at 50 rows/campaign) |
| `remediation_campaigns.csv` | machine-readable | Flat summary row for **every** campaign, for spreadsheets/ticketing import |
| `remediation_report.md` | Analyst | Top campaigns, priority scores, rationale, suggested owners |
| `remediation_worklist.md` | Analyst | Per-campaign worklist: fix, affected hosts, owning team |
| `remediation_leadership_update.md` | Manager | What was fixed, what's spreading, what's still open |
| `remediation_executive_summary.md` | Executive | Exposure trend, critical campaigns, top 5 risks, plain-English summary |

## How campaigns are built

- **Root-cause grouping**: findings are clustered by shared solution text. Tenable's public export API only returns populated `solution` text for a minority of findings (this account's export scope doesn't expose `plugin_family`/first-seen timestamps), so findings without solution text fall back to grouping by finding name, which is still fix-specific (e.g. a CVE ID or a per-OS advisory title).
- **Anti-conflation guard**: many findings share generic boilerplate solution text (e.g. "Update the affected packages.") across completely unrelated OS/package advisories. The builder pairs solution text with the advisory's product family (parsed from the finding name) so unrelated fixes never get silently merged into one campaign.
- **Priority score**: `sum(VPR × max(ACR, 1))` across a campaign's findings, boosted for Critical/High severity — transparent and defendable in a demo, per the plan's scoring model.
- **Suggested owner**: a keyword-based router maps each campaign to a likely owning team (Linux/Unix, Windows/AD, Database, Network, Container/Platform, OT/ICS, etc.) since the export doesn't expose Tenable's own plugin family/category.
- **Trend**: comparing the current campaign membership (by campaign key + asset) against the prior archived snapshot in `Data/snapshots/` surfaces newly affected assets, resolved assets, and net exposure change per campaign.

## Notes

- Both scripts run in live mode against the real Tenable API using credentials in `.env` — no synthetic/demo data.
- If the exported CSV rows are empty or incomplete, the builder still completes and writes an explanatory report instead of failing.
- This Tenable account's export scope does not expose asset `ipv4`/`operating_system` or finding `first_found`/`plugin_family` via the public export API; those columns are intentionally left blank in the CSVs rather than guessed.
