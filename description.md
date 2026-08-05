# Patch Shepherd — How It Works

## The Problem

Tenable scans return hundreds of thousands of individual vulnerability findings. No security team can triage that many one by one, and severity alone doesn't tell you what to fix first. The result: teams drown in alerts instead of reducing risk.

## What This Does

Patch Shepherd turns raw Tenable data into a short, prioritized list of remediation actions — automatically, on a schedule, with no manual sorting.

**In our first live run: 545,414 individual findings became 36,821 grouped remediation campaigns**, each one representing a single fix a team can act on.

## How It Works — 3 Steps

**1. Pull.** The system connects to Tenable directly and pulls every active asset and finding — nothing sampled or filtered.

**2. Cluster & Prioritize.** Instead of listing findings one by one, it groups them by *shared root cause* — the same patch, the same package update, the same fix — so one action can resolve dozens or hundreds of findings at once. Each resulting campaign gets a transparent priority score based on how exploitable the issue is, how critical the affected systems are, and how many assets it touches. Every campaign also gets a suggested owning team (e.g. Linux, Windows/AD, Database, Network) so it can be routed immediately.

**3. Report to Everyone.** The same underlying data is presented differently depending on who's looking:

| Audience | What they see |
| :--- | :--- |
| **Analyst** | The exact worklist — which hosts, which fix, which team owns it |
| **Manager** | What got fixed, what's new, what's spreading, what's still blocked |
| **Executive** | Overall exposure trend, the critical few campaigns that matter, and a plain-English summary |

## Trend Over Time

Every pull is archived. Starting with the second pull, the system automatically compares runs to show whether exposure is growing or shrinking — proof of progress, not just a snapshot.

## Why It Matters

This doesn't just re-sort a list by severity — it answers the operational question every security leader actually asks: **"What's the single action that removes the most risk, and who owns it?"**
