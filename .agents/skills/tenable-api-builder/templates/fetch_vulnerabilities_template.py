#!/usr/bin/env python3
"""
Template: Async Bulk Vulnerabilities Exporter
Pulls active vulnerability findings from Tenable API using requests / urllib.
"""

import os
import json
import time
import requests

TENABLE_ACCESS_KEY = os.getenv("TENABLE_ACCESS_KEY", "YOUR_ACCESS_KEY")
TENABLE_SECRET_KEY = os.getenv("TENABLE_SECRET_KEY", "YOUR_SECRET_KEY")
BASE_URL = "https://cloud.tenable.com"

HEADERS = {
    "X-ApiKeys": f"accessKey={TENABLE_ACCESS_KEY}; secretKey={TENABLE_SECRET_KEY};",
    "Content-Type": "application/json",
    "Accept": "application/json"
}

def export_vulnerabilities(severities=["high", "critical"], min_vpr=7.0):
    url = f"{BASE_URL}/vulns/export"
    payload = {
        "num_assets": 5000,
        "filters": {
            "severity": severities,
            "state": ["open"],
            "vpr_score": {"gte": min_vpr}
        }
    }
    
    response = requests.post(url, json=payload, headers=HEADERS)
    response.raise_for_status()
    export_uuid = response.json()["export_uuid"]
    print(f"[*] Started Vuln Export Job: {export_uuid}")
    
    # Poll status
    status_url = f"{BASE_URL}/vulns/export/{export_uuid}/status"
    while True:
        res = requests.get(status_url, headers=HEADERS).json()
        status = res.get("status")
        print(f"[*] Status: {status}")
        
        if status == "FINISHED":
            chunks = res.get("chunks_available", [])
            all_vulns = []
            for chunk_id in chunks:
                chunk_url = f"{BASE_URL}/vulns/export/{export_uuid}/download/{chunk_id}"
                chunk_data = requests.get(chunk_url, headers=HEADERS).json()
                all_vulns.extend(chunk_data)
            return all_vulns
        elif status in ("ERROR", "CANCELLED"):
            raise RuntimeError(f"Export failed: {status}")
        
        time.sleep(3)

if __name__ == "__main__":
    vulns = export_vulnerabilities()
    print(f"[+] Downloaded {len(vulns)} vulnerability records.")
    with open("exported_vulnerabilities.json", "w") as f:
        json.dump(vulns, f, indent=2)
