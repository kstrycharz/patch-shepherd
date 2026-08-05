#!/usr/bin/env python3
"""
Tenable Live Exposure Telemetry CSV Extractor
Built using the 'tenable-api-builder' skill guidance.

Strictly runs in LIVE MODE using Tenable API keys loaded from the local .env file.
Saves all CSV export files into the './Data' directory.

Downloads live asset inventory (with ACR & Exposure Scores) and active
vulnerability findings (with VPR scores & solutions) from the Tenable One
inventory export API.

Exports clean CSV files in Data/:
- Data/tenable_assets.csv
- Data/tenable_vulnerability_findings.csv
- Data/tenable_unified_exposure.csv

A timestamped copy of the unified export is also archived under
Data/snapshots/ so the Patch Shepherd skill can compare runs over time
and detect trend, recurrence, and remediation progress.

Usage (run from the repository root, so .env and Data/ resolve correctly):
  1. Add your keys to a .env file in the repository root:
     TENABLE_ACCESS_KEY=your_access_key_here
     TENABLE_SECRET_KEY=your_secret_key_here
  2. Run the script:
     py -3 .agents/skills/patch-shepherd/scripts/pull_tenable_exposure_data.py

Notes on the export API:
  The `/api/v1/t1/inventory/export/*` endpoints only return the columns
  explicitly requested via `properties`, and only a fixed subset of column
  names are accepted for "public export" (anything else returns HTTP 400).
  `use_readable_name` must be left False -- the readable-name variant
  renames keys to human-formatted strings (e.g. "Asset ID") that do not
  match the plain snake_case names this script parses.

  Verified valid asset properties: asset_name, asset_id, asset_class, aes,
  acr, fqdns, sources, tag_ids. (ipv4s/operating_systems are rejected by
  the public export endpoint for this account and are intentionally
  omitted below.)

  Verified valid finding properties: asset_id, finding_id, finding_name,
  finding_severity, finding_vpr_score, finding_solution, finding_cves,
  state. (plugin_family/plugin_id/first_observed_at/port are rejected by
  the public export endpoint for this account and are intentionally
  omitted below.)
"""

import os
import sys
import csv
import json
import shutil
import time
import argparse
import logging
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("TenableLiveExtractor")

# Columns accepted by this account's /inventory/export/assets endpoint.
ASSET_EXPORT_PROPERTIES = [
    "asset_name",
    "asset_id",
    "asset_class",
    "aes",
    "acr",
    "fqdns",
    "sources",
    "tag_ids",
]

# Columns accepted by this account's /inventory/export/findings endpoint.
FINDING_EXPORT_PROPERTIES = [
    "asset_id",
    "finding_id",
    "finding_name",
    "finding_severity",
    "finding_vpr_score",
    "finding_solution",
    "finding_cves",
    "state",
]


def load_dotenv(filepath: str = ".env") -> bool:
    """Helper to parse local .env file into os.environ if present."""
    if not os.path.exists(filepath):
        return False

    loaded_any = False
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, val = line.split("=", 1)
                key = key.strip()
                # Strip quotes and any surrounding whitespace from the value
                val = val.strip().strip("'\"")
                if key:
                    os.environ[key] = val
                    loaded_any = True
                    # Mask value in log for security
                    masked = val[:4] + "..." + val[-4:] if len(val) > 12 else "****"
                    logger.info(f"  Loaded {key} = {masked}")
    return loaded_any


class TenableLiveExtractor:
    def __init__(self, base_url: str = "https://cloud.tenable.com"):
        # Load environment variables from .env file
        env_loaded = load_dotenv(".env")
        if env_loaded:
            logger.info("Successfully loaded API credentials from .env file.")

        self.access_key = os.getenv("TENABLE_ACCESS_KEY")
        self.secret_key = os.getenv("TENABLE_SECRET_KEY")
        self.base_url = base_url.rstrip("/")

        if not (self.access_key and self.secret_key):
            logger.error("ERROR: Missing Tenable API credentials!")
            logger.error("Please ensure TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY are defined in your .env file.")
            sys.exit(1)

        # Validate credentials with a lightweight API call before running exports
        self._validate_credentials()

    def _headers(self) -> Dict[str, str]:
        # NOTE: Tenable requires NO spaces in the X-ApiKeys value.
        # Correct:  accessKey=abc123;secretKey=def456
        # Wrong:    accessKey=abc123; secretKey=def456;
        return {
            "X-ApiKeys": f"accessKey={self.access_key};secretKey={self.secret_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "TenableSwarmExposureScript/1.0"
        }

    def _build_endpoint(self, endpoint: str, query_params: Optional[Dict[str, Any]] = None) -> str:
        if not query_params:
            return endpoint

        encoded_items = []
        for key, value in query_params.items():
            if value is None:
                continue
            if isinstance(value, bool):
                encoded_items.append((key, "true" if value else "false"))
            elif isinstance(value, (list, tuple)):
                encoded_items.append((key, ",".join(str(item) for item in value)))
            else:
                encoded_items.append((key, str(value)))

        if not encoded_items:
            return endpoint

        return f"{endpoint}?{urllib.parse.urlencode(encoded_items, doseq=True)}"

    def _http_request(self, method: str, endpoint: str, payload: Optional[Dict[str, Any]] = None, retries: int = 5) -> Any:
        url = f"{self.base_url}{endpoint}"
        data = json.dumps(payload).encode("utf-8") if payload else None

        for attempt in range(1, retries + 1):
            req = urllib.request.Request(url, data=data, headers=self._headers(), method=method.upper())
            try:
                with urllib.request.urlopen(req) as resp:
                    body = resp.read()
                    if not body:
                        return {}

                    text = body.decode("utf-8", errors="replace")
                    content_type = resp.headers.get("Content-Type", "")

                    if "json" in content_type.lower() or text.lstrip().startswith(("{", "[")):
                        try:
                            return json.loads(text)
                        except json.JSONDecodeError:
                            pass

                    return text
            except urllib.error.HTTPError as e:
                error_body = e.read().decode("utf-8")
                if e.code == 429 and attempt < retries:
                    wait_s = 10 * attempt
                    logger.warning(f"Rate limited on {endpoint} (attempt {attempt}/{retries}). Waiting {wait_s}s...")
                    time.sleep(wait_s)
                    continue
                logger.error(f"Tenable API HTTP {e.code} Error on {endpoint}: {error_body}")
                raise RuntimeError(f"Tenable API Error {e.code}: {error_body}")
            except urllib.error.URLError as e:
                logger.error(f"URL Connection Error on {endpoint}: {e.reason}")
                raise RuntimeError(f"Tenable API Connection Error: {e.reason}")

        raise RuntimeError(f"Exhausted retries calling {endpoint}")

    def _validate_credentials(self):
        """Quick auth check using a lightweight endpoint before running exports."""
        logger.info("Validating Tenable API credentials...")
        url = f"{self.base_url}/session"
        req = urllib.request.Request(url, headers=self._headers(), method="GET")
        try:
            with urllib.request.urlopen(req) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                username = body.get("username", body.get("name", "unknown"))
                permissions = body.get("permissions", "unknown")
                logger.info(f"Authenticated as: {username} (permissions: {permissions})")

                # Permissions check: 64 = Administrator, 16 = Basic (minimum for exports)
                try:
                    perm_int = int(permissions)
                    if perm_int < 16:
                        logger.warning(f"WARNING: User permissions ({perm_int}) may be too low for exports.")
                        logger.warning("  Exports require at least Basic [16] or Administrator [64] role.")
                except (ValueError, TypeError):
                    pass

        except urllib.error.HTTPError as e:
            error_body = e.read().decode("utf-8")
            if e.code == 401:
                logger.error("AUTHENTICATION FAILED (HTTP 401).")
                logger.error("  Your API keys are invalid or expired.")
                logger.error("  Generate new keys at: Tenable.io > Settings > My Account > API Keys")
                sys.exit(1)
            elif e.code == 403:
                logger.error("AUTHORIZATION FAILED (HTTP 403 - Insufficient Scope).")
                logger.error("  Your API keys authenticated but lack permissions for this action.")
                logger.error("  Common fixes:")
                logger.error("    1. Ensure the API key user has Administrator [64] or Basic [16] role")
                logger.error("    2. Check Access Groups: user needs 'Can View' on 'All Assets'")
                logger.error("    3. Regenerate keys from an admin account")
                logger.error(f"  Response: {error_body}")
                sys.exit(1)
            else:
                logger.error(f"Auth validation HTTP {e.code}: {error_body}")
                sys.exit(1)
        except urllib.error.URLError as e:
            logger.error(f"Cannot reach Tenable API at {self.base_url}: {e.reason}")
            sys.exit(1)

    # --- 1. Fetch All Live Assets ---

    def fetch_all_assets(self) -> List[Dict[str, Any]]:
        """Fetch asset telemetry using Tenable's bulk asset export API."""
        return self._fetch_assets_via_export()

    def _fetch_assets_via_export(self) -> List[Dict[str, Any]]:
        logger.info("Initiating Live Tenable Asset Export (/inventory/export/assets)...")
        query_params = {
            "properties": ASSET_EXPORT_PROPERTIES,
            "use_readable_name": False,
            "file_format": "JSON",
        }
        export_res = self._http_request("POST", self._build_endpoint("/api/v1/t1/inventory/export/assets", query_params))
        export_id = export_res.get("export_id")
        if not export_id:
            raise RuntimeError(f"Failed to obtain export_id from Tenable response: {export_res}")

        logger.info(f"Asset export job created: {export_id}")

        while True:
            status_res = self._http_request("GET", f"/api/v1/t1/inventory/export/{export_id}/status")
            status = status_res.get("status")
            logger.info(f"Asset Export Status: {status}")

            if status == "FINISHED":
                chunks = status_res.get("chunks_available", [])
                logger.info(f"Asset export finished. Downloading {len(chunks)} chunk(s)...")
                all_assets = []
                for chunk_id in chunks:
                    logger.info(f"Downloading Asset Chunk #{chunk_id}...")
                    chunk = self._http_request("GET", f"/api/v1/t1/inventory/export/{export_id}/download/{chunk_id}")
                    all_assets.extend(chunk)
                return all_assets
            elif status in ("ERROR", "CANCELLED"):
                raise RuntimeError(f"Asset export job failed with status: {status}")

            time.sleep(3)

    # --- 2. Fetch All Live Vulnerability Findings ---

    def fetch_all_vulnerabilities(self, min_vpr: Optional[float] = None) -> List[Dict[str, Any]]:
        """Fetch vulnerability telemetry using Tenable's bulk vulnerability export API."""
        return self._fetch_vulns_via_export(min_vpr)

    def _fetch_vulns_via_export(self, min_vpr: Optional[float] = None) -> List[Dict[str, Any]]:
        logger.info("Initiating Live Tenable Vulnerability Export (/inventory/export/findings)...")
        query_params = {
            "properties": FINDING_EXPORT_PROPERTIES,
            "use_readable_name": False,
            "file_format": "JSON",
        }

        filters = [
            {
                "property": "state",
                "operator": "=",
                "value": ["ACTIVE"],
            }
        ]
        if min_vpr is not None:
            filters.append({
                "property": "finding_vpr_score",
                "operator": ">=",
                "value": [str(min_vpr)],
            })

        payload = {"filters": filters}

        export_res = self._http_request("POST", self._build_endpoint("/api/v1/t1/inventory/export/findings", query_params), payload)
        export_id = export_res.get("export_id")
        if not export_id:
            raise RuntimeError(f"Failed to obtain export_id from Tenable response: {export_res}")

        logger.info(f"Vulnerability export job created: {export_id}")

        while True:
            status_res = self._http_request("GET", f"/api/v1/t1/inventory/export/{export_id}/status")
            status = status_res.get("status")
            logger.info(f"Vulnerability Export Status: {status}")

            if status == "FINISHED":
                chunks = status_res.get("chunks_available", [])
                logger.info(f"Vulnerability export finished. Downloading {len(chunks)} chunk(s)...")
                all_findings = []
                for chunk_id in chunks:
                    logger.info(f"Downloading Vulnerability Chunk #{chunk_id}...")
                    chunk = self._http_request("GET", f"/api/v1/t1/inventory/export/{export_id}/download/{chunk_id}")
                    all_findings.extend(chunk)
                return all_findings
            elif status in ("ERROR", "CANCELLED"):
                raise RuntimeError(f"Vulnerability export job failed with status: {status}")

            time.sleep(3)

# --- CSV Export Helpers ---

def _joined(value: Any) -> str:
    if isinstance(value, list):
        return ", ".join(str(v) for v in value if v not in (None, ""))
    return str(value) if value not in (None, "") else ""


def export_assets_to_csv(assets: List[Dict[str, Any]], filepath: str):
    fieldnames = ["asset_id", "hostname", "ipv4", "operating_system", "acr_score", "exposure_score", "tags"]
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for a in assets:
            hostname = a.get("asset_name") or _joined(a.get("fqdns"))
            writer.writerow({
                "asset_id": a.get("asset_id", ""),
                "hostname": hostname,
                "ipv4": "",  # not available via public export for this account
                "operating_system": "",  # not available via public export for this account
                "acr_score": a.get("acr") if a.get("acr") is not None else 0,
                "exposure_score": a.get("aes") if a.get("aes") is not None else 0,
                "tags": json.dumps(a.get("tag_ids") or [])
            })
    logger.info(f"Saved {len(assets)} live asset records to CSV: {filepath}")

def export_vulnerabilities_to_csv(findings: List[Dict[str, Any]], filepath: str):
    fieldnames = ["asset_id", "hostname", "ipv4", "plugin_id", "plugin_name", "plugin_family", "severity", "vpr_score", "state", "solution", "first_found", "cves"]
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for v in findings:
            writer.writerow({
                "asset_id": v.get("asset_id", ""),
                "hostname": "",  # joined in from the asset export in the unified CSV
                "ipv4": "",
                "plugin_id": v.get("finding_id", ""),
                "plugin_name": v.get("finding_name", ""),
                "plugin_family": "",  # not available via public export for this account
                "severity": (v.get("finding_severity") or "").title(),
                "vpr_score": v.get("finding_vpr_score") if v.get("finding_vpr_score") is not None else 0.0,
                "state": v.get("state", ""),
                "solution": v.get("finding_solution") or "",
                "first_found": "",  # not available via public export; tracked via local snapshots instead
                "cves": _joined(v.get("finding_cves")),
            })
    logger.info(f"Saved {len(findings)} live vulnerability finding records to CSV: {filepath}")

def export_unified_csv(assets: List[Dict[str, Any]], findings: List[Dict[str, Any]], filepath: str):
    asset_map = {a.get("asset_id"): a for a in assets if a.get("asset_id")}
    fieldnames = ["asset_id", "hostname", "ipv4", "acr_score", "exposure_score", "operating_system", "plugin_id", "plugin_name", "plugin_family", "severity", "vpr_score", "solution", "first_found", "cves"]

    written_count = 0
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for v in findings:
            aid = v.get("asset_id", "")
            asset = asset_map.get(aid, {})

            hostname = asset.get("asset_name") or _joined(asset.get("fqdns")) or aid

            writer.writerow({
                "asset_id": aid,
                "hostname": hostname,
                "ipv4": "",
                "acr_score": asset.get("acr") if asset.get("acr") is not None else 0,
                "exposure_score": asset.get("aes") if asset.get("aes") is not None else 0,
                "operating_system": "",
                "plugin_id": v.get("finding_id", ""),
                "plugin_name": v.get("finding_name", ""),
                "plugin_family": "",
                "severity": (v.get("finding_severity") or "").title(),
                "vpr_score": v.get("finding_vpr_score") if v.get("finding_vpr_score") is not None else 0.0,
                "solution": v.get("finding_solution") or "",
                "first_found": "",
                "cves": _joined(v.get("finding_cves")),
            })
            written_count += 1

    logger.info(f"Saved {written_count} unified joined live exposure rows to CSV: {filepath}")


def archive_snapshot(output_dir: str, unified_csv: str) -> str:
    """Copy the unified export into Data/snapshots/<timestamp>.csv for trend analysis."""
    snapshots_dir = os.path.join(output_dir, "snapshots")
    os.makedirs(snapshots_dir, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest = os.path.join(snapshots_dir, f"{stamp}_unified_exposure.csv")
    shutil.copyfile(unified_csv, dest)
    logger.info(f"Archived snapshot for trend analysis: {dest}")
    return dest


def main():
    parser = argparse.ArgumentParser(description="Extract live Tenable Asset and Exposure Vulnerability Telemetry to CSV")
    parser.add_argument("--output-dir", default="Data", help="Directory to save CSV data files (default: Data)")
    parser.add_argument("--min-vpr", type=float, default=None, help="Optional minimum VPR score filter")
    args = parser.parse_args()

    # Ensure output Data directory exists
    os.makedirs(args.output_dir, exist_ok=True)

    extractor = TenableLiveExtractor()

    logger.info("Extracting Live Asset Telemetry...")
    assets = extractor.fetch_all_assets()
    logger.info(f"Retrieved {len(assets)} live assets.")

    logger.info("Extracting Live Vulnerability Findings (state=ACTIVE)...")
    findings = extractor.fetch_all_vulnerabilities(min_vpr=args.min_vpr)
    logger.info(f"Retrieved {len(findings)} live vulnerability findings.")

    assets_csv = os.path.join(args.output_dir, "tenable_assets.csv")
    vulns_csv = os.path.join(args.output_dir, "tenable_vulnerability_findings.csv")
    unified_csv = os.path.join(args.output_dir, "tenable_unified_exposure.csv")

    export_assets_to_csv(assets, assets_csv)
    export_vulnerabilities_to_csv(findings, vulns_csv)
    export_unified_csv(assets, findings, unified_csv)

    snapshot_path = archive_snapshot(args.output_dir, unified_csv)

    print("\n========================================================")
    print("      TENABLE LIVE EXPOSURE CSV EXTRACTION COMPLETE     ")
    print("========================================================")
    print(f" Output Directory:                  {args.output_dir}")
    print(f" Total Live Assets Downloaded:          {len(assets)}")
    print(f" Total Live Vulnerabilities Downloaded: {len(findings)}")
    print(f" CSV Files Created:")
    print(f"   - {assets_csv}")
    print(f"   - {vulns_csv}")
    print(f"   - {unified_csv}")
    print(f" Snapshot archived:                 {snapshot_path}")
    print("========================================================")

if __name__ == "__main__":
    main()
