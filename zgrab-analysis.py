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

def classify_device(server_header, banner):
    if server_header is None and banner is None:
        return "Unknown"

    field = " ".join([
        server_header or "",
        banner or "",
    ]).lower()

    # HTTP servers
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
    
    # SSH servers
    if "openssh" in field:
        return "OpenSSH"
    if "dropbear" in field:
        return "Dropbear"
    if "comware" in field:
        return "Comware"
    
    # IMAP servers / POP3 servers
    if "dovecot" in field:
        return "Dovecot"
    
    # Telnet servers
    if "kkeeneticos" in field:
        return "KKeeneticOS"
    
    # FTP servers
    if "proftpd" in field:
        return "ProFTPD"
    if "220-idea ftp server" in field:
        return "220-Idea FTP Server"
    if "pure-ftpd" in field:
        return "Pure-FTPd"

    return "Other"

def parse_record(record, protocol):
    if(protocol == "https"):
        protocol = "http"

    ip = record["ip"]
    prot = record.get("data", {}).get(protocol, {})
    result = prot.get("result", {})

    server = None
    banner = result.get("banner")
    status = prot.get("status")
    success = status == "success"

    if protocol == "http":
        headers = result.get("response", {}).get("headers", {})
        server = None if headers.get("server") is None else headers.get("server")[0]

    elif protocol == "ssh":
        server = result.get("server_id", {}).get("software")
        banner = result.get("key_exchange", {}).get("server_host_key", {}).get("raw")

    return ip, server, banner, success

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

PROTOCOLS = ["http", "https", "ssh", "smtp"]

rows = []

for protocol in PROTOCOLS:
    base = f"{protocol}_tcp.json"

    path = os.path.join(ZGRAB_DIR, base)
    print(f"[*] Processing {path} ({protocol})")

    with open(path, "r") as f:
        for line in f:
            try:
                record = json.loads(line)
            except:
                continue

            # Parse ZGrab data
            ip, server, banner, success = parse_record(record, protocol)

            # Enrichment
            asn, prefix = get_asn_prefix(ip)
            country = get_country(ip)
            device = classify_device(server, banner)

            # Append unified row
            rows.append({
                "ip": ip,
                "asn": asn,
                "prefix": prefix,
                "country": country,
                "protocol": protocol,
                "server_header": server,
                "device_type": device,
                "success": success
            })

fieldnames = [
    "ip",
    "asn",
    "prefix",
    "country",
    "protocol",
    "server_header",
    "device_type",
    "success"
]

with open(OUTPUT_CSV, "w", newline="") as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)

print(f"[+] Wrote {len(rows)} rows → {OUTPUT_CSV}")
