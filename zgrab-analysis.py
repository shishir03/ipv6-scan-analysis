# Things to analyze:
# - ASN / geolocation distribution of the hitlist
# - ASN / geolocation distribution of the ICMP & TCP hosts we found
# - Responsive hosts % on each protocol
# - Host device distribution of the HTTP hosts we found with ZGrab

import json
import csv
import pyasn
from geoip2.database import Reader as GeoIPReader
import os

ZGRAB_DIR = "zgrab2"
OUTPUT_CSV = "zgrab_unified.csv"

ASN_DB_PATH = "pfx2as_rounded.txt"
GEOIP_DB_PATH = "GeoLite2-Country.mmdb"

# Load ASN DB
asn_db = pyasn.pyasn(ASN_DB_PATH)

# Load GeoIP DB
geoip_db = GeoIPReader(GEOIP_DB_PATH)

def classify_device(server_header, banner, cert_cn):
    field = " ".join([
        server_header or "",
        banner or "",
        cert_cn or "",
    ]).lower()

    # Common servers
    if "cisco" in field:
        return "Cisco"
    if "nginx" in field or "openresty" in field:
        return "Nginx"
    if "apache" in field:
        return "Apache"
    if "cloudflare" in field:
        return "Cloudflare edge"
    if "iis" in field or "microsoft-httpapi" in field:
        return "Microsoft/IIS"
    if "proxygen" in field:
        return "Proxygen"

    return "Unknown"

def parse_http(record):
    """Extract useful fields from ZGrab2 http/https module."""
    ip = record["ip"]
    data = record.get("data", {})

    http = data.get("http", {}).get("result", {})
    server = None
    banner = None
    cert_cn = None

    # HTTP banner
    headers = http.get("response", {}).get("headers", {})
    server = None if headers.get("server") is None else headers.get("server")[0]

    # HTTPS certificate?
    tls = data.get("tls", {}).get("result", {})
    if tls:
        certs = tls.get("handshake_log", {}).get("server_certificates", {})
        parsed = certs.get("certificate", {}).get("parsed", {})
        cert_cn = None
        if "subject" in parsed:
            subj = parsed["subject"]
            cert_cn = " ".join(subj.get("common_name", []) or [])

    return ip, server, banner, cert_cn


def parse_ssh(record):
    ip = record["ip"]
    ssh = record.get("data", {}).get("ssh", {})
    banner = ssh.get("banner")
    host_key = ssh.get("host_key")
    return ip, None, banner or host_key, None


def parse_smtp(record):
    ip = record["ip"]
    smtp = record.get("data", {}).get("smtp", {})
    banner = smtp.get("ehlo", {}).get("server", None)
    return ip, None, banner, None


def get_asn_prefix(ip):
    try:
        res = asn_db.lookup(ip)
        return res
    except Exception:
        return None, None

def get_country(ip):
    try:
        r = geoip_db.country(ip)
        return r.country.iso_code
    except Exception as e:
        print(e)
        return None

PARSERS = {
    "http": parse_http,
    "https": parse_http,
    "ssh": parse_ssh,
    "smtp": parse_smtp,
}

rows = []

for protocol in PARSERS.keys():
    base = f"{protocol}_tcp.json"

    parser = PARSERS[protocol]

    path = os.path.join(ZGRAB_DIR, base)
    print(f"[*] Processing {path} ({protocol})")

    with open(path, "r") as f:
        for line in f:
            try:
                record = json.loads(line)
            except:
                continue

            # Parse ZGrab data
            ip, server, banner, cert_cn = parser(record)

            # Enrichment
            asn, prefix = get_asn_prefix(ip)
            country = get_country(ip)
            device = classify_device(server, banner, cert_cn)

            # Append unified row
            rows.append({
                "ip": ip,
                "asn": asn,
                "prefix": prefix,
                "country": country,
                "protocol": protocol,
                "server_header": server,
                "device_type": device
            })

fieldnames = [
    "ip",
    "asn",
    "prefix",
    "country",
    "protocol",
    "server_header",
    "device_type"
]

with open(OUTPUT_CSV, "w", newline="") as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)

print(f"[+] Wrote {len(rows)} rows → {OUTPUT_CSV}")
