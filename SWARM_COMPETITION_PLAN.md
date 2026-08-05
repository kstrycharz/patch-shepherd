# SWARM Competition Plan

## Pitch

Build an agent/skill that turns raw Tenable findings into a small number of remediation campaigns, then keeps the organization aligned with daily worklists and leadership-ready updates.

The core value is simple: reduce noise, identify what actually matters, show what is getting worse, and prove what has already been fixed.

## Winning Thesis

The best SWARM submissions will do three things well:

1. Automate a painful security workflow end to end.
2. Produce outputs that an analyst, manager, and executive can all use.
3. Stay explainable enough that teams trust the recommendations.

This project fits that pattern because vulnerability data is already abundant, but decision-making is still manual. Most teams do not need more alerts. They need fewer, better priorities.

## Product Name Idea

Campaign Commander

Alternates:

- Exposure Campaigner
- Fix Flow
- Remediation Radar

## What The Agent Does

Input:

- Tenable findings
- Asset context
- Exposure scores and VPR
- Fix/solution text
- Historical snapshots for trend analysis

Outputs:

- Remediation campaigns grouped by root cause
- Ranked worklists by risk reduction
- Assets likely to become future problems
- Simple leadership updates
- Fixed items and remaining exposure
- Areas where exposure is building over time

## Core Differentiator

The agent should not just sort findings by severity.

It should answer the operational question: "What single remediation action removes the most risk across the most important assets?"

That means clustering issues by shared fix, then ranking those clusters by:

- Asset criticality
- Exploitability
- Breadth of affected assets
- Trend over time
- Recurrence after prior remediation

## Campaign Logic

Group findings into campaigns using a layered approach:

1. Root-cause grouping by shared solution or fix pattern.
2. Asset clustering so one campaign can be routed to the right team.
3. Priority scoring so leadership sees the largest risk reduction first.
4. Exception handling for high-risk singletons that should break out of the cluster.

Examples:

- Patch a shared library version across multiple hosts
- Close an exposed service on a family of assets
- Remediate a configuration weakness repeated across a platform
- Fix a vulnerable package version across application fleets

## Scoring Model

Use a transparent score so the output is defendable in a demo.

Suggested campaign score components:

- VPR and severity
- Asset criticality or exposure score
- Number of affected assets
- Number of business-critical assets affected
- Trend delta since the last snapshot
- Age of the issue

Simple leadership language matters more than a complicated formula. The model should explain why a campaign is high priority in one sentence.

## User Experience

Analyst view:

- Top campaigns
- Campaign members
- Recommended fix
- Affected assets
- Risk score and rationale
- Suggested owner/team

Manager view:

- What changed this week
- What was fixed
- What is still open
- Which campaigns are blocked
- Which campaigns are spreading across the environment

Executive view:

- Total exposure trend
- Critical campaigns
- Remediation progress
- Top 5 risks by business impact
- Plain-English summary

## Data Story

The data narrative should be easy to explain in the demo:

- Before: thousands of findings, no clear action path.
- During: the agent groups them into a manageable number of campaigns.
- After: teams get worklists, status updates, and trend visibility.

## Demo Flow

1. Load or refresh Tenable exposure data.
2. Generate campaigns from findings.
3. Show the top 3 campaigns and why they matter.
4. Open one campaign and show the affected assets and the fix.
5. Generate a worklist for remediation owners.
6. Generate a leadership update that summarizes risk, progress, and growth.
7. Show a before/after view that highlights what was fixed and what is getting worse.

## What Will Make The Judges Care

Judges are likely to reward a submission that is:

- Useful immediately
- Clearly explainable
- Open and reusable
- Focused on a real security workflow
- Demoable in a few minutes

To stand out, the agent should feel like a control plane for remediation, not a report generator.

## Minimum Viable Demo

Build only the parts needed to prove value:

- Campaign clustering
- Priority ranking
- Worklist generation
- Leadership summary
- Trend detection

If time is short, skip fancy dashboards and spend effort on clarity, output quality, and narrative.

## Suggested Deliverables

- `Data/remediation_campaigns.json`
- `Data/remediation_campaigns.csv`
- `Data/remediation_report.md`
- Optional: a lightweight CLI or prompt-driven interface

## Implementation Plan

Phase 1: Campaign Intelligence

- Cluster findings by solution and shared fix.
- Add priority ranking and explainability.
- Identify top campaigns and top affected assets.

Phase 2: Operational Output

- Produce analyst worklists.
- Produce leadership summaries.
- Highlight fixed vs still open items.

Phase 3: Trend Awareness

- Compare current vs prior snapshots.
- Flag exposure growth, recurrence, and remediation progress.
- Identify assets that are likely to become recurring problem areas.

Phase 4: Demo Polish

- Make outputs concise.
- Keep the language non-technical where possible.
- Ensure the demo can be shown quickly and repeatably.

## Demo Script

Open with the pain:

"Security teams do not need more findings. They need to know what to fix first, who should fix it, and whether risk is moving in the right direction."

Then show the transformation:

- Raw findings in
- Campaigns out
- Worklists produced
- Leadership summary generated
- Trends and fixed items surfaced

Close with the outcome:

"This agent turns exposure management into remediation management."

## Risk To Avoid

- A tool that only re-sorts findings by severity.
- A summary that is too generic to act on.
- Too much UI and not enough decision value.
- Output that is not explainable to a manager or executive.

## Final Positioning

The pitch should be centered on this idea:

"We built an agent that converts noisy vulnerability data into prioritized remediation campaigns, operational worklists, and leadership updates so teams can fix the right things faster and see where exposure is building."
