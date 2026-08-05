#!/usr/bin/env python3
"""
Tenable Script Generator Utility
Generates customized Python scripts for fetching Tenable API data based on desired parameters.
Usage:
  py -3 skills/tenable-api-builder/scripts/generate_tenable_script.py --type vulns --min-vpr 8.0 --output fetch_high_vpr.py
"""

import sys
import json
import argparse

VULN_SCRIPT_TEMPLATE = '''#!/usr/bin/env python3
import os
import json
import time
import requests

ACCESS_KEY = os.getenv("TENABLE_ACCESS_KEY", "{access_key}")
SECRET_KEY = os.getenv("TENABLE_SECRET_KEY", "{secret_key}")
BASE_URL = "https://cloud.tenable.com"

HEADERS = {{
    "X-ApiKeys": f"accessKey={{ACCESS_KEY}}; secretKey={{SECRET_KEY}};",
    "Content-Type": "application/json",
    "Accept": "application/json"
}}

def main():
    print("[*] Initiating Vulnerability Export...")
    url = f"{{BASE_URL}}/vulns/export"
    payload = {{
        "num_assets": 5000,
        "filters": {{
            "severity": {severities},
            "state": ["open"],
            "vpr_score": {{"gte": {min_vpr}}}
        }}
    }}
    
    resp = requests.post(url, json=payload, headers=HEADERS)
    resp.raise_for_status()
    export_uuid = resp.json()["export_uuid"]
    print(f"[+] Job Created: {{export_uuid}}")
    
    status_url = f"{{BASE_URL}}/vulns/export/{{export_uuid}}/status"
    while True:
        status_resp = requests.get(status_url, headers=HEADERS).json()
        status = status_resp.get("status")
        print(f"[*] Status: {{status}}")
        if status == "FINISHED":
            chunks = status_resp.get("chunks_available", [])
            records = []
            for chunk_id in chunks:
                chunk_url = f"{{BASE_URL}}/vulns/export/{{export_uuid}}/download/{{chunk_id}}"
                records.extend(requests.get(chunk_url, headers=HEADERS).json())
            print(f"[+] Downloaded {{len(records)}} vulnerabilities.")
            with open("{output_json}", "w") as f:
                json.dump(records, f, indent=2)
            break
        elif status in ("ERROR", "CANCELLED"):
            print(f"[!] Export failed with status: {{status}}")
            break
        time.sleep(3)

if __name__ == "__main__":
    main()
'''

ASSET_SCRIPT_TEMPLATE = '''#!/usr/bin/env python3
import os
import json
import time
import requests

ACCESS_KEY = os.getenv("TENABLE_ACCESS_KEY", "{access_key}")
SECRET_KEY = os.getenv("TENABLE_SECRET_KEY", "{secret_key}")
BASE_URL = "https://cloud.tenable.com"

HEADERS = {{
    "X-ApiKeys": f"accessKey={{ACCESS_KEY}}; secretKey={{SECRET_KEY}};",
    "Content-Type": "application/json",
    "Accept": "application/json"
}}

def main():
    print("[*] Initiating Asset Export...")
    url = f"{{BASE_URL}}/assets/export"
    payload = {{"chunk_size": 1000}}
    
    resp = requests.post(url, json=payload, headers=HEADERS)
    resp.raise_for_status()
    export_uuid = resp.json()["export_uuid"]
    print(f"[+] Asset Export Job Created: {{export_uuid}}")
    
    status_url = f"{{BASE_URL}}/assets/export/{{export_uuid}}/status"
    while True:
        status_resp = requests.get(status_url, headers=HEADERS).json()
        status = status_resp.get("status")
        print(f"[*] Status: {{status}}")
        if status == "FINISHED":
            chunks = status_resp.get("chunks_available", [])
            records = []
            for chunk_id in chunks:
                chunk_url = f"{{BASE_URL}}/assets/export/{{export_uuid}}/download/{{chunk_id}}"
                records.extend(requests.get(chunk_url, headers=HEADERS).json())
            print(f"[+] Downloaded {{len(records)}} assets.")
            with open("{output_json}", "w") as f:
                json.dump(records, f, indent=2)
            break
        elif status in ("ERROR", "CANCELLED"):
            print(f"[!] Export failed: {{status}}")
            break
        time.sleep(3)

if __name__ == "__main__":
    main()
'''

def main():
    parser = argparse.ArgumentParser(description="Generate custom Tenable API extraction script.")
    parser.add_argument("--type", choices=["vulns", "assets"], default="vulns", help="Data type to extract")
    parser.add_argument("--min-vpr", type=float, default=7.0, help="Minimum VPR score filter")
    parser.add_argument("--severities", nargs="+", default=["high", "critical"], help="Severities list")
    parser.add_argument("--output", default="custom_tenable_fetcher.py", help="Output python script filename")
    parser.add_argument("--output-json", default="tenable_data.json", help="JSON data output filename")
    args = parser.parse_args()

    if args.type == "vulns":
        code = VULN_SCRIPT_TEMPLATE.format(
            access_key="YOUR_ACCESS_KEY",
            secret_key="YOUR_SECRET_KEY",
            severities=json.dumps(args.severities),
            min_vpr=args.min_vpr,
            output_json=args.output_json
        )
    else:
        code = ASSET_SCRIPT_TEMPLATE.format(
            access_key="YOUR_ACCESS_KEY",
            secret_key="YOUR_SECRET_KEY",
            output_json=args.output_json
        )

    with open(args.output, "w", encoding="utf-8") as f:
        f.write(code)

    print(f"[+] Generated Tenable extraction script: {args.output}")

if __name__ == "__main__":
    main()
