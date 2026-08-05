#!/usr/bin/env python3
"""
Template: Async Bulk Asset Telemetry Exporter
Pulls asset metadata, ACR scores, Exposure scores, and tags from Tenable API.
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

def export_assets(chunk_size=1000):
    url = f"{BASE_URL}/assets/export"
    payload = {"chunk_size": chunk_size}
    
    response = requests.post(url, json=payload, headers=HEADERS)
    response.raise_for_status()
    export_uuid = response.json()["export_uuid"]
    print(f"[*] Started Asset Export Job: {export_uuid}")
    
    status_url = f"{BASE_URL}/assets/export/{export_uuid}/status"
    while True:
        res = requests.get(status_url, headers=HEADERS).json()
        status = res.get("status")
        print(f"[*] Asset Export Status: {status}")
        
        if status == "FINISHED":
            chunks = res.get("chunks_available", [])
            all_assets = []
            for chunk_id in chunks:
                chunk_url = f"{BASE_URL}/assets/export/{export_uuid}/download/{chunk_id}"
                chunk_data = requests.get(chunk_url, headers=HEADERS).json()
                all_assets.extend(chunk_data)
            return all_assets
        elif status in ("ERROR", "CANCELLED"):
            raise RuntimeError(f"Asset export failed: {status}")
        
        time.sleep(3)

if __name__ == "__main__":
    assets = export_assets()
    print(f"[+] Downloaded {len(assets)} asset records.")
    with open("exported_assets.json", "w") as f:
        json.dump(assets, f, indent=2)
