#!/usr/bin/env python3
"""
cve_bot.py

A simple bot to detect the current OS and find related CVEs using the NVD API.

REQUIREMENTS:
  - Python 3.6+
  - requests library (`pip install requests`)

HOW TO USE:
1.  (Optional but Recommended) Get a free NVD API key from:
    https://nvd.nist.gov/developers/request-an-api-key
2.  Add your API key to the `NVD_API_KEY` variable below.
3.  Add or update OS-to-CPE mappings in the `CPE_MAP` dictionary.
4.  Run the script from your terminal: `python cve_bot.py`
"""

import platform
import subprocess
import sys
import requests

# --- CONFIGURATION ---

# (Optional) Add your NVD API key here for a higher request rate.
NVD_API_KEY = ""

# Maps a simple OS identifier to its official CPE name.
# You will need to add mappings for the OSes you want to support.
CPE_MAP = {
    "ubuntu_24.04": "cpe:2.3:o:canonical:ubuntu:24.04:*:*:*:lts:*:*:*",
    "ubuntu_22.04": "cpe:2.3:o:canonical:ubuntu:22.04:*:*:*:lts:*:*:*",
    "macos_14": "cpe:2.3:o:apple:macos:14.0:*:*:*:*:*:*:*",
    # Example for Debian 12 "Bookworm"
    #"debian_12": "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:*", 
}

# --- SCRIPT LOGIC ---

def get_os_identifier():
    """Detects the current OS and returns a simplified identifier string."""
    system = platform.system()

    if system == "Linux":
        try:
            # Use /etc/os-release for reliable detection on modern Linux
            with open("/etc/os-release") as f:
                d = dict(line.strip().split("=") for line in f if "=" in line)
                os_id = d.get("ID", "").strip('"')
                version_id = d.get("VERSION_ID", "").strip('"')
                return f"{os_id}_{version_id}"
        except (IOError, ValueError):
            print("Could not parse /etc/os-release. This Linux distribution may not be supported.")
            return None

    elif system == "Darwin": # macOS
        version = platform.mac_ver()[0]
        major_version = version.split('.')[0]
        return f"macos_{major_version}"
        
    elif system == "Windows":
        # Add logic for Windows if needed. Parsing Windows versions can be complex.
        print("Windows detection is not implemented in this version.")
        return None

    return None

def fetch_cves_for_cpe(cpe_string):
    """Queries the NVD API for CVEs matching a given CPE string."""
    print(f"\n🔍 Searching for CVEs with CPE: {cpe_string}")
    
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    params = {"cpeName": cpe_string}

    try:
        response = requests.get(base_url, headers=headers, params=params, timeout=30)
        response.raise_for_status()  # Raises an exception for bad status codes (4xx or 5xx)
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"❌ Error fetching data from NVD API: {e}")
        return None

def display_cves(data):
    """Parses and prints CVE data in a readable format."""
    vulnerabilities = data.get("vulnerabilities", [])
    total_results = data.get("totalResults", 0)

    if not vulnerabilities:
        print("✅ No vulnerabilities found matching the specified CPE.")
        return

    print(f"\nFound {total_results} vulnerabilities. Displaying details:\n")
    print("-" * 60)

    for item in vulnerabilities:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "N/A")
        description = "No description available."
        
        # Get English description
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value")
                break
        
        # Get CVSS V3.1 score if available, otherwise V2
        severity = "N/A"
        metrics = cve.get("metrics", {})
        if "cvssMetricV31" in metrics:
            severity = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV2" in metrics:
            severity = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
            
        print(f"ID: {cve_id}")
        print(f"Severity Score: {severity}")
        print(f"Description: {description}\n")
        print("-" * 60)


def find_cpe_online(os_identifier):
    """
    Searches the NVD API for a CPE string based on a keyword.
    """
    print(f"ℹ️ OS '{os_identifier}' not in local map. Searching NVD API...")
    
    # Convert "debian_12" to "debian 12" for a better search
    keyword = os_identifier.replace("_", " ")
    
    base_url = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    params = {"keywordSearch": keyword}

    try:
        response = requests.get(base_url, headers=headers, params=params, timeout=30)
        response.raise_for_status()
        data = response.json()
        products = data.get("products", [])

        # Heuristic: Find the first result that is a base Operating System
        for product in products:
            cpe = product.get("cpe", {})
            cpe_name = cpe.get("cpeName")
            
            # Check if the CPE is for an OS (cpe:2.3:o:...)
            if cpe_name and cpe_name.startswith("cpe:2.3:o:"):
                print(f"✅ Discovered CPE: {cpe_name}")
                return cpe_name  # Return the first valid OS match

        print("❌ No suitable CPE found online for this keyword.")
        return None
        
    except requests.exceptions.RequestException as e:
        print(f"❌ Error searching for CPE online: {e}")
        return None

def main():
    """Main function to orchestrate the CVE check."""
    print("--- CVE Check Bot Initializing ---")
    
    os_identifier = get_os_identifier()

    if not os_identifier:
        print("Could not determine the operating system. Exiting.")
        sys.exit(1)
        
    print(f"✅ Detected OS: {os_identifier}")

    # First, try to find the CPE in our local map
    cpe = CPE_MAP.get(os_identifier)

    # If not found locally, search for it online
    if not cpe:
        cpe = find_cpe_online(os_identifier)

    # If it's still not found after searching, then exit
    if not cpe:
        print(f"❌ Could not find a CPE for '{os_identifier}' locally or online. Exiting.")
        sys.exit(1)

    cve_data = fetch_cves_for_cpe(cpe)
    if cve_data:
        display_cves(cve_data)

if __name__ == "__main__":
    main()