#!/usr/bin/env python3
"""
Template: pyTenable SDK Integration
Demonstrates using the official pyTenable library for extracting assets and vulnerabilities.
Requires: pip install pyTenable
"""

import os
import json

try:
    from tenable.io import TenableIO
except ImportError:
    print("[!] pyTenable library not installed. Install via: pip install pyTenable")
    TenableIO = None

def fetch_with_sdk():
    if not TenableIO:
        return
        
    access_key = os.getenv("TENABLE_ACCESS_KEY")
    secret_key = os.getenv("TENABLE_SECRET_KEY")
    
    tio = TenableIO(access_key, secret_key)
    
    # Export Vulnerabilities with pyTenable iterator
    print("[*] Exporting vulnerabilities via pyTenable SDK...")
    vulns_iterator = tio.exports.vulns(
        severity=["high", "critical"],
        state=["open"]
    )
    
    vuln_list = list(vulns_iterator)
    print(f"[+] Downloaded {len(vuln_list)} vulnerabilities using pyTenable.")
    
    # Export Assets via pyTenable iterator
    print("[*] Exporting assets via pyTenable SDK...")
    assets_iterator = tio.exports.assets()
    asset_list = list(assets_iterator)
    print(f"[+] Downloaded {len(asset_list)} assets using pyTenable.")

if __name__ == "__main__":
    fetch_with_sdk()
