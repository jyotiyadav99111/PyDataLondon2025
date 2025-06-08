"""
tools/fetch.py

Tool implementations for data fetching in Agentic Maliciousness Query Agent.
Contains:
- fetch_whois(target: str) -> dict
- geoip_lookup(target: str) -> dict
- fetch_threat_feed(target: str) -> dict (supports domains and IPs)
Includes a simple test harness when run as __main__.
"""

import whois
import requests
import json
import re
import os
import geoip2.database

# Load GeoIP2 database reader (ensure you have the GeoLite2-City.mmdb file at ./data/)
GEOIP_DB_PATH = "./data/GeoLite2-City.mmdb"
try:
    geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH)
except Exception:
    geoip_reader = None  # Fallback to public API if DB not available

# Regex to detect IPv4 addresses
octet = r'(?:25[0-5]|2[0-4]\d|[01]?\d?\d)'
IPV4_PATTERN = re.compile(rf'^{octet}\.{octet}\.{octet}\.{octet}$')


def fetch_whois(target: str) -> dict:
    """
    Fetch WHOIS data for a domain using the python-whois module.
    Returns a dict with:
      - raw: full WHOIS text (as string)
      - creation_date: datetime of registration (or None)
    """
    try:
        w = whois.whois(target)
        # whois.whois returns creation_date as datetime or list
        cd = w.creation_date
        if isinstance(cd, list):
            creation = cd[0]
        else:
            creation = cd
        return {
            "raw": w.text or "",
            "creation_date": creation
        }
    except Exception as e:
        return {"error": str(e)}


def geoip_lookup(target: str) -> dict:
    """
    Perform a GeoIP lookup for an IP address.
    Tries local GeoLite2 DB first, then falls back to public API if unavailable.
    Returns country, city, latitude, longitude, etc.
    """
    # Try local database
    if geoip_reader:
        try:
            resp = geoip_reader.city(target)
            return {
                "country": resp.country.name,
                "region": resp.subdivisions.most_specific.name,
                "city": resp.city.name,
                "latitude": resp.location.latitude,
                "longitude": resp.location.longitude,
                "source": "GeoLite2"
            }
        except Exception:
            pass

    # Fallback to public API (ip-api.com)
    try:
        r = requests.get(f"http://ip-api.com/json/{target}")
        data = r.json()
        if data.get("status") == "success":
            return {
                "country": data.get("country"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "latitude": data.get("lat"),
                "longitude": data.get("lon"),
                "source": "ip-api"
            }
        else:
            return {"error": data.get("message", "Lookup failed")}
    except Exception as e:
        return {"error": str(e)}


def fetch_threat_feed(target: str) -> dict:
    """
    Query VirusTotal for domain or IP reputation.
    Uses appropriate endpoint based on target pattern.
    Replace API_KEY with your credentials.
    """
    API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
    headers = {"x-apikey": API_KEY}
    target = target.strip().strip('\'"')

    # Determine endpoint: IP vs. domain
    if IPV4_PATTERN.match(target):
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
    else:
        url = f"https://www.virustotal.com/api/v3/domains/{target}"
    try:
        r = requests.get(url, headers=headers)
        if r.status_code == 200:
            data = r.json()
            attrs = data.get("data", {}).get("attributes", {})
            # Use analysis stats if available, else fallback reputation score
            if "last_analysis_stats" in attrs:
                reputation = attrs.get("last_analysis_stats")
            else:
                reputation = {"reputation": attrs.get("reputation")}
                print(reputation)
            return {"threat_feed": reputation}
        else:
            print({"error": f"Status {r.status_code}: {r.text}"})
            return {"error": f"Status {r.status_code}: {r.text}"}
    except Exception as e:
        print('-------')
        print(e)
        return {"error": str(e)}


if __name__ == "__main__":
    # Simple test harness
    test_targets = ["example.com", "8.8.8.8"]
    results = {}

    for t in test_targets:
        print(f"\nTesting target: {t}")
        whois_data = fetch_whois(t)
        print("WHOIS:", json.dumps(whois_data, default=str, indent=2))

        if IPV4_PATTERN.match(t):
            geo = geoip_lookup(t)
            print("GeoIP:", json.dumps(geo, indent=2))

        feed = fetch_threat_feed(t)
        print("Threat Feed:", json.dumps(feed, indent=2))

        results[t] = {
            "whois": whois_data,
            "geoip": geo if IPV4_PATTERN.match(t) else None,
            "feed": feed
        }

    print("\nTest Results Summary:")
    print(json.dumps(results, default=str, indent=2))
