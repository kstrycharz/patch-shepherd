# Tenable API Endpoint Catalog & Request Reference

Based on Tenable Developer Portal (`https://developer.tenable.com/reference/navigate`).

## Base URL
`https://cloud.tenable.com`

---

## 1. Bulk Vulnerabilities Export API (`/vulns/export`)

### Endpoint Overview
Extracts detailed vulnerability findings across all assets.

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/vulns/export` | Request new vulnerability export job |
| `GET` | `/vulns/export/{export_uuid}/status` | Get export job status & chunk list |
| `GET` | `/vulns/export/{export_uuid}/download/{chunk_id}` | Download export chunk (JSON) |

### Available Filters (`POST /vulns/export`)
```json
{
  "num_assets": 5000,
  "filters": {
    "severity": ["medium", "high", "critical"],
    "state": ["open", "remediated"],
    "vpr_score": { "gte": 7.0 },
    "first_found": 1750000000,
    "last_found": 1780000000,
    "tags": {
      "Environment": ["Production"]
    }
  }
}
```

---

## 2. Bulk Assets Export API (`/assets/export`)

### Endpoint Overview
Extracts asset metadata, Asset Criticality Rating (ACR), Exposure Scores, IP addresses, hostnames, and installed software.

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/assets/export` | Request new asset export job |
| `GET` | `/assets/export/{export_uuid}/status` | Get asset export job status |
| `GET` | `/assets/export/{export_uuid}/download/{chunk_id}` | Download asset export chunk |

### Payload Example (`POST /assets/export`)
```json
{
  "chunk_size": 1000,
  "filters": {
    "has_plugin_results": true,
    "created_at": 1750000000,
    "updated_at": 1780000000,
    "sources": ["NESSUS"]
  }
}
```

---

## 3. Workbenches API (Synchronous Dashboard Data)

Ideal for quick metrics, dashboard aggregations, or querying specific asset details without creating export jobs.

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/workbenches/vulnerabilities` | Retrieve vulnerability findings summary |
| `GET` | `/workbenches/assets` | Retrieve asset inventory summary |
| `GET` | `/workbenches/assets/{asset_id}/vulnerabilities` | Vulnerabilities specific to an asset |
| `GET` | `/workbenches/vulnerabilities/{plugin_id}/info` | Plugin information & remediation |

---

## 4. Plugins & VPR API

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/plugins/plugin/{plugin_id}` | Plugin description, CVEs, solution |
| `GET` | `/plugins/attributes/vpr` | VPR score distribution metadata |

---

## 5. Tenable Exposure Management / Attack Paths API

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/exposure/score` | Compute overall enterprise Exposure Score |
| `GET` | `/api/v1/attack-paths` | Query high-probability attack path graphs |

---

## 6. Tenable One Inventory Export API (`/api/v1/t1/inventory/export/*`)

Used by `pull_tenable_exposure_data.py`. Some API keys (this project's included) are scoped for
Tenable One inventory access but return `403 Insufficient scope` on the classic `/vulns/export`
chunk-download endpoint above — use this endpoint instead when that happens.

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/v1/t1/inventory/export/assets?properties=...&use_readable_name=false&file_format=JSON` | Request new asset export job |
| `POST` | `/api/v1/t1/inventory/export/findings?properties=...&use_readable_name=false&file_format=JSON` | Request new findings export job (body: `{"filters": [...]}`) |
| `GET` | `/api/v1/t1/inventory/export/{export_id}/status` | Poll job status; `chunks_available` lists downloadable chunk IDs |
| `GET` | `/api/v1/t1/inventory/export/{export_id}/download/{chunk_id}` | Download one chunk (JSON array of records) |

**Important**: `properties` is an allow-list — an unsupported column returns `400 Bad Request` naming
the exact column that failed, so probe one property at a time when in doubt. Leave
`use_readable_name=false`; `true` renames keys to human-formatted strings (e.g. `"Asset ID"`) that
don't match a stable schema. Verified-valid columns for this project's key:

- Assets: `asset_name, asset_id, asset_class, aes, acr, fqdns, sources, tag_ids`
- Findings: `asset_id, finding_id, finding_name, finding_severity, finding_vpr_score, finding_solution, finding_cves, state`

Columns like `plugin_family`, `vpr_score`, `solution`, `ipv4s`, `operating_systems`, and
`first_observed_at` are rejected ("not supported" or "not available for public export") for this
account's export scope — don't assume they're available without probing first.
